import os
import json
from dotenv import load_dotenv
from typing import Annotated, Optional
from typing_extensions import TypedDict

# --- LIBRERÍAS DE GOOGLE (NATIVO) ---
# Usamos el SDK oficial para llamadas críticas donde LangChain falla al parsear
from google import genai
from google.genai import types # Para tipos de configuración

# --- LIBRERÍAS DE LANGCHAIN ---
# Framework principal para orquestar el flujo y manejar el historial
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage, AIMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.checkpoint.memory import MemorySaver # Para añadir memoria al grafo

# --- MÓDULOS PROPIOS ---
# Separación de responsabilidades: Prompts en un lado, Herramientas en otro
from prompts import ORCHESTRATOR_SYSTEM_PROMPT, ANALYST_SYSTEM_PROMPT, CONSULTANT_RAG_PROMPT, REPORTER_SYSTEM_PROMPT
from tools import check_hash_vt, check_url_virustotal, extract_hash_from_text, extract_url_from_text, generate_pdf_report

# --- IMPORTS PARA RAG ---
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings


# ==========================================
# 1. CONFIGURACIÓN E INICIALIZACIÓN
# ==========================================

# Carga de variables desde .env para seguridad
load_dotenv('.env')
google_key = os.getenv('GOOGLE_API_KEY')

if not google_key:
    print("❌ Error crítico: Faltan variables de entorno (GOOGLE_API_KEY).")
    exit()

# Configuración del modelo de LLM a emplear con gemini-3-flash-preview por defecto
MODEL_NAME = os.getenv('GEMINI_MODEL', 'gemini-3-flash-preview')

# Configuración del Cliente LangChain (Principal) / Wrapper de LangChain para el modelo de Google. 
# Usamos 'gemini-3-flash-preview' por ser el modelo más eficiente y capaz actualmente.
# Temperature 0.3 reduce alucinaciones.
# Lo usaremos principalmente para el Orquestador, que maneja texto puro y no datos técnicos sensibles. 
# Además Langchain maneja automáticamente el historial de meoria y el ruteo del Grafo.
# Para análisis técnicos y generación de reportes, usaremos el cliente nativo para evitar problemas de parseo y filtros de seguridad.

llm = ChatGoogleGenerativeAI(
    model=MODEL_NAME,
    google_api_key=google_key,
    temperature=0.3, 
)

# Instanciamos el modelo de Embeddings (Local) UNA SOLA VEZ al arrancar.
# Esto reduce drásticamente la latencia en las consultas RAG.
# (Usamos HuggingFaceEmbeddings para evitar problemas de cuota con Google en la capa gratuita)
print("💾 Cargando modelo de embeddings (HuggingFace Local)...")
embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")    

# Definición del Estado del Grafo (La "Memoria" del Bot)
class State(TypedDict):
    # 1. Historial de chat --> Lista de mensajes con add_messages. Acumula los mensajes nuevos al final de la lista.
    messages: Annotated[list, add_messages] 
    
    # 2. Contexto de Amenaza --> String opcional que almacena el tipo del amenazas detectada en el último análisis
    # Aquí guardaremos "Phishing", "Ransomware", etc.
    # Empleado en el flujo dinámico para que el orquestador pueda dirigir al consultor con contexto específico sin que el usuario tenga que repetirlo.
    active_threat: Optional[str]
    
    # 3. Pregunta Refinada --> string opcional que el orquestador escribe cuando decide derivar al consultor
    # Contiene la pregunta reescrita y enriquecida con contexto (ej: "Explícame en detalle qué es el Phishing y cómo protegerme")
    refined_query: Optional[str]

    # 4. String opcional que actúa como variable temporal de señalización para el router.
    # El Orquestador escribe aquí la decisión de a qué nodo dirigir el flujo (ej: "TO_ANALYST", "TO_CONSULTANT", etc.) y el router la lee para tomar la decisión.
    next_step: Optional[str]


# ==========================================
# 2. FUNCIONES AUXILIARES (UTILITIES)
# ==========================================

def clean_response_text(ai_message):

    """
    SANITIZADOR DE RESPUESTAS:
    Corrige un bug conocido de compatibilidad entre el SDK de Gemini y el wrapper de LangChain.
    En ciertas versiones, cuando Gemini devuelve una respuesta multimodal o con bloques de pensamiento, LangChain la deserializa como una lista de objetos en lugar de un string.
    La función detecta si content es una lista, extrae solo los bloques de tipo texto y los concatena, garantizando que el parsing posterior del formato DESTINO :: CONTENIDO funcione correctamente.
    """

    content = ai_message.content
    if isinstance(content, list):
        # Filtramos solo los bloques que contienen texto
        text_parts = [block.get('text', '') for block in content if isinstance(block, dict) and 'text' in block]
        ai_message.content = "".join(text_parts)
    return ai_message

# ==========================================
# 3. NODOS DEL GRAFO (AGENTES)
# ==========================================

def orchestrator_node(state: State):
    """
    NODO ORQUESTADOR (El Cerebro):
    - Recibe el input del usuario y/o lee el estado (active_threat).
    - Decide a qué especialista enviar la tarea (Analista, Consultor o Chat).
    - Usa LangChain para invocar al modelo.
    - Si es flujo dinámico, Reescribe la pregunta del usuario para el Consultor (Ingeniería de Prompts).
    """

    print("--- 🧠 EJECUTANDO ORQUESTADOR ---")

    # 1. Recuperar contexto de la memoria
    # Si no hay amenaza activa, usamos "Ninguna" por defecto
    active_threat = state.get("active_threat") or "Ninguna"

    # 2. Inyectar contexto en el Prompt del Orquestador (Prompt Engineering)
    # Usamos .format() para rellenar la variable {active_threat}
    filled_prompt = ORCHESTRATOR_SYSTEM_PROMPT.format(active_threat=active_threat)
    
    # Construimos la lista de mensajes para el LLM
    # Mantenemos el historial para que entienda referencias como "Explícame ESO"
    messages = [SystemMessage(content=filled_prompt)] + state['messages']
    
    # 3. Invocamos a la IA
    response = llm.invoke(messages)
    ai_message_object = clean_response_text(response) # Funcion de limpieza
    content_text = ai_message_object.content # Extraemos el texto limpio para el parsing posterior
    
    
    # 4. Parsing de la respueta (formato: DESTINO :: CONTENIDO)
    if "::" in content_text:
        parts = content_text.split("::", 1)
        decision = parts[0].strip()
        refined_content = parts[1].strip()
    else:
        # Si el formato no es correcto, asumimos que es una respuesta de Chat general
        decision = "TO_CHAT"
        refined_content = content_text.strip()
    
    print(f"   🚦 Decisión: {decision}")

    # 5. Retorno de estado
    # Si la decision es TO_CONSULTANT, guardamos la 'refined_content' en 'refined_query'
    # para que el Consultor sepa qué buscar
    
    return {
        "messages": [AIMessage(content=refined_content)], 
        "next_step": decision,
        "refined_query": refined_content if decision == "TO_CONSULTANT" else None
    }


def analyst_node(state: State):

    """
    NODO ANALISTA (El Especialista Técnico):
    - Combina Inteligencia Técnica (VirusTotal) + Inteligencia Semántica (Análisis de Texto).
    - Objetivo: Detectar ataques complejos donde la URL puede parecer limpia pero el contexto es malicioso.
    - Implementa lógica HÍBRIDA (IA + Determinista).
    - Usa el SDK Nativo de Google para saltar limitaciones de LangChain.
    - Incluye mecanismo de 'Graceful Degradation' (Reporte Manual) si falla la IA.
    """

    print("--- 🕵️‍♂️ EJECUTANDO NODO ANALISTA ---")

    # 1. Búsqueda del último mensaje real del usuario (ignorando mensajes de sistema)
    messages = state['messages']
    user_text = ""
    for msg in reversed(messages):
        if msg.type == "human":
            user_text = msg.content
            break
    
    # 2. Uso de Herramientas: Extracción de Hash o URL
    target_hash = extract_hash_from_text(user_text)
    target_url = extract_url_from_text(user_text)

    vt_data = {}
    analysis_type = "Ingeniería Social y estafas Online" # Valor por defecto si no se detecta ni hash ni URL

    # Lógica de clasificación para el flujo dinámico
    detected_topic = "Ciberseguridad General"

    # Prioridad: Si hay Hash (malware) > URL (phishing) > Solo texto
    if target_hash:
        print(f"🔍 Hash detectado: {target_hash}")
        analysis_type = "Archivo (Malware)"
        print("🌍 Consultando VirusTotal...")
        vt_data = check_hash_vt(target_hash)

        # --- LÓGICA DE DETECCIÓN ESPECÍFICA ---
        # 1. Intentamos sacar el nombre exacto (ej: trojan.emotet)
        threat_label = vt_data.get('popular_threat_classification', {}).get('suggested_threat_label')
        
        # 2. Intentamos sacar tags interesantes (ej: rat, ransomware)
        tags = vt_data.get('tags', [])
        
        # Lógica de nombramiento
        if threat_label:
            detected_topic = f"Malware de tipo {threat_label}"
        elif "ransomware" in tags:
            detected_topic = "Ransomware (Secuestro de datos)"
        elif "rat" in tags:
            detected_topic = "Malware RAT (Acceso Remoto)"
        elif "trojan" in tags:
            detected_topic = "Troyano"
        elif "phishing" in tags:
            detected_topic = "Phishing"
        else:
            detected_topic = "Malware y archivos infectados" # Fallback genérico
            
        print(f"🎯 Tema identificado: {detected_topic}")
        
    elif target_url:
        print(f"🔍 URL detectada: {target_url}")
        analysis_type = "URL (Sitio Web)"
        detected_topic = "Phishing y Sitios Web maliciosos"
        print("🌍 Consultando VirusTotal")
        vt_data = check_url_virustotal(target_url)  
    
    # Manejo de errores de la API externa (VirusTotal)
    if "error" in vt_data:
        error_msg = vt_data['error']
        
        # Si es un error de API real (autenticación, timeout...) -> salimos
        if "Falta la clave" in error_msg or "conectar" in error_msg:
            return {"messages": [SystemMessage(content=f"⚠️ Error VirusTotal: {error_msg}")]}
        
        # Si es un 404 (URL/Hash desconocido) -> continuamos con análisis semántico
        # Dejamos vt_data con el mensaje de error para que la IA lo interprete
        print(f"⚠️ VT sin datos previos: {error_msg}. Continuando con análisis semántico...")

    # 3. Preparación del Prompt para el Analista (Promt Engineering)
    full_analysis_prompt = f"""
        {ANALYST_SYSTEM_PROMPT}

        --- INPUTS DEL CASO ---
        USER_CONTEXT: "{user_text}"

        REPORT_VT (Tipo: {analysis_type}):
        {json.dumps(vt_data, indent=2)}
        """

    # Aparece al final del mensaje para guiar al usuario
    call_to_action = (
        f"\n\n🎓 ¿Quieres aprender más sobre {detected_topic}?\n"
        f"Simplemente dime 'Explícame qué es esto' o '¿Cómo funciona?' y te daré más información.\n"
        f"También puedes pedir un informe detallado diciendo 'Genera un informe de esto'."
    )

    # 4. Generaración de Respuesta con Cliente Nativo (Bypass de Seguridad)
    try:
        print(f"🤖 Correlacionando datos ({analysis_type} + Texto) con Gemini (Nativo)...")
        
        client = genai.Client(api_key=google_key)
        
        native_response = client.models.generate_content(
            model=MODEL_NAME,
            contents=full_analysis_prompt,
            config=types.GenerateContentConfig(
                safety_settings=[
                    # Desactivar filtro de contenido peligroso
                    types.SafetySetting(
                        category="HARM_CATEGORY_DANGEROUS_CONTENT",
                        threshold="BLOCK_NONE"
                    )
                ]
            )
        )

        # Validamos que hay texto antes de devolverlo    
        if native_response.text:
            return {
                # Añadimos el Call to Action al mensaje final
                "messages": [AIMessage(content=native_response.text + call_to_action)],
                # Guardamos el topic en la memoria del grafo para el orquestador
                "active_threat": detected_topic
            }
        else:
            raise ValueError("Respuesta vacía por filtros duros.")

    except Exception as e:
        # 5. FALLBACK MANUAL (GRACEFUL DEGRADATION)
        # Si la IA falla, generamos un reporte "feo" pero útil basado en los datos.
        print(f"⚠️ FALLO IA ({e}). ACTIVANDO REPORTE MANUAL.")
        
        malicious = vt_data.get('malicious', 0)
        total = vt_data.get('total_engines', 0) if 'total_engines' in vt_data else (malicious + vt_data.get('undetected', 0))
        
        # Identificador (URL o Nombres de archivo)
        target_id = vt_data.get('url', vt_data.get('names', ['Desconocido']))
        if isinstance(target_id, list): target_id = target_id[0] # Si es lista de nombres, coge el primero

        # Veredicto simple
        if malicious > 0:
            verdict = "⛔ **PELIGROSO / MALICIOSO**"
            advice = "Detectado por motores de seguridad. NO ACCEDER."
        else:
            verdict = "✅ **APARENTEMENTE SEGURO**"
            advice = "Ningún motor detectó amenazas recientes."

        manual_report = (
            f"🤖 *Nota: IA no disponible (Fallback activo). Análisis forense manual:*\n\n"
            f"🛡️ **Informe de Seguridad ({analysis_type})**\n"
            f"-------------------------\n"
            f"🎯 **Objetivo:** `{target_id}`\n"
            f"⚖️ **Veredicto:** {verdict}\n"
            f"📊 **Detección:** {malicious}/{total} motores\n"
            f"💡 **Consejo:** {advice}"
        )
        return {"messages": [SystemMessage(content=manual_report + call_to_action)], "active_threat": detected_topic}


def consultant_node(state: State):

    """
    NODO CONSULTOR (RAG):
    Usa el cliente nativo y desactiva filtros para poder explicar
    conceptos de ciberseguridad sin censura.
    """

    print("--- 📚 EJECUTANDO NODO CONSULTOR (RAG) ---")
    
    # 1. Recuperar pregunta
    # Si refined_query tiene contenido, se usa directamente. Esta pregunta fue reescrita por el orquestador para incluir el contexto de la amenaza activa.
    # Si no hay refined_query, se busca el último mensaje humano en el historial iterando en reversa.
    
    if state.get("refined_query"):
        user_question = state["refined_query"]
        print(f"   ❓ Pregunta detectada por contexto: {user_question}")
    else:    
        messages = state['messages']
        user_question = ""
        for msg in reversed(messages):
            if msg.type == "human":
                user_question = msg.content
                break
            
    print(f"   ❓ Pregunta detectada: {user_question}")

    # 2. Conectar a Base de Datos vectorial (Chroma)
    DB_PATH = "chroma_db"
    
    if not os.path.exists(DB_PATH):
        return {"messages": [SystemMessage(content="⚠️ Error: No encuentro la memoria. Ejecuta 'python ingest.py' primero.")]}

    # Embeddings HuggingFaceEmbeddings inicializados globalmente
    
    try:
        # Conexión a la BBDD vectorial. Carga el índice vectorial desde disco en memoria, construido por ingest.py
        vector_store = Chroma(persist_directory=DB_PATH, embedding_function=embeddings)
        
        # 3. Retrieval
        # Convierte la pregunta en un vector y busca los K fragmentos más cerca matemáticamente (más relevantes).
        results = vector_store.similarity_search(user_question, k=15)
        # A. Extraemos el contexto para la IA (concatenamos los fragmentos recuperados en un solo string, separados por saltos de línea)
        context_text = "\n\n".join([doc.page_content for doc in results])
        # B. Extraemos las fuentes (metadatos) para el debugging
        # Usamos un set() para evitar duplicados si varios trozos vienen del mismo documento
        unique_sources = set()

        for doc in results:
            # doc.metedata es un diccionario: {'source': 'data/Tema1.pdf', 'page':10}
            full_path = doc.metadata.get('source', 'Desconocido')
            filename = os.path.basename(full_path) # Limpiamos la ruta
            page = doc.metadata.get('page', '?')

            # Guardamos formato "Archivo (Pág X)"
            unique_sources.add(f"{filename} (Pág {page})")
        
        # Imprimimos las fuentes en consola 
        print(f"   📚 Fuentes usadas: {', '.join(unique_sources)}")

        if not context_text:
            return {"messages": [SystemMessage(content="Lo siento, no encuentro información sobre eso en tus apuntes.")]}

        print("   📖 Contexto recuperado.")

        # 4. Prompt 
        # Context Injection: Inyectamos contexto y pregunta en el prompt del consultor
        # RAG Prompt Stuffing. Toda la "memoria" del consultor está en el contexto de esa llamada.
        rag_prompt = CONSULTANT_RAG_PROMPT.format(
            context_text=context_text, # Fragmentos recuperados
            user_question=user_question # Pregunta del usuario (o pregunta refinada por el orquestador)
        )

        # 5. GENERACIÓN CON CLIENTE NATIVO (BYPASS DE SEGURIDAD)
        print("🤖 Generando respuesta con Gemini (Nativo)...")
        
        client = genai.Client(api_key=google_key)
        
        native_response = client.models.generate_content(
            model=MODEL_NAME,
            contents=rag_prompt,
            config=types.GenerateContentConfig(
                safety_settings=[
                         # Desactivar filtro de contenido peligroso
                        types.SafetySetting(
                            category="HARM_CATEGORY_DANGEROUS_CONTENT",
                            threshold="BLOCK_NONE"
                        )
                    ]
            )
        )
        
        if native_response.text:
            return {"messages": [AIMessage(content=native_response.text)]}
        else:
            raise ValueError("Respuesta vacía por filtros duros.")

    except Exception as e:
        print(f"❌ Error RAG: {e}")
        return {"messages": [SystemMessage(content="Lo siento, hubo un error al consultar los apuntes.")]}


def reporter_node(state: State):

    """
    NODO REPORTERO:
    Usa el SDK de Google directamente para forzar salida JSON y evitar errores de LangChain.
    """

    print("--- 📝 EJECUTANDO NODO REPORTERO ---")
    
    active_threat = state.get("active_threat", "Amenaza General")
    
    # 1. Recuperamos historial (limpiando llaves para que no rompan el .format)
    recent_messages = state['messages'][-6:]
    history_summary = "\n".join([f"{m.type}: {m.content}" for m in recent_messages])
    history_summary = history_summary.replace("{", "(").replace("}", ")") # Sanitización para el .format
    
    # 2. Rellenamos el prompt
    formatted_prompt = REPORTER_SYSTEM_PROMPT.format(
        active_threat=active_threat,
        history_summary=history_summary
    )
    
    try:
        # 3. Invocamos a Gemini (CLIENTE NATIVO)
        # Esto es mucho más estable que llm.invoke para generar JSONs
        client = genai.Client(api_key=google_key)
        
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=formatted_prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json" # Fuerza respuesta JSON válida
            )
        )
        
        # Como hemos forzado JSON, la respuesta viene limpia
        if not response.text:
            raise ValueError("Gemini devolvió una respuesta vacía.")

        print("   🤖 JSON generado por IA...")
        report_data = json.loads(response.text)
        
        # 4. Generamos el PDF físico
        # Limpiamos el nombre del archivo para que no tenga caracteres raros
        safe_threat_name = "".join([c if c.isalnum() else "_" for c in active_threat])
        filename = f"Reporte_{safe_threat_name}.pdf"
        
        pdf_path = generate_pdf_report(report_data, filename)
        
        print(f"   ✅ PDF generado exitosamente: {pdf_path}")
        
        # 5. Retornamos señal especial para Telegram
        # Esta cadena es detectada por process_with_graph en SecMate.py, que la intercepta antes de intentar enviarla como texto y la procesa como un envío de documento
        return {
            "messages": [AIMessage(content=f"FILE_GENERATED::{pdf_path}")]
        }

    except Exception as e:
        print(f"❌ Error generando reporte: {e}")
        return {
            "messages": [AIMessage(content="Lo siento, hubo un error técnico al generar el archivo PDF.")]
        }
    

# ==========================================
# 4. CONSTRUCCIÓN DEL GRAFO (Workflow)
# ==========================================

def router(state: State):

    """
    ROUTER (Semáforo):
    Lee la decisión del Orquestador y dirige el flujo al nodo correspondiente.
    """

    decision = state.get("next_step")

    if decision == "TO_ANALYST":
        return "analyst"
    elif decision == "TO_CONSULTANT":
        return "consultant"
    elif decision == "TO_REPORT":
        return "reporter"
    elif decision == "TO_CHAT":
        return END
    else:
        return END


# Definición de la estructura del grafo
graph_builder = StateGraph(State)

# Paso 1: Añadir Nodos
graph_builder.add_node("orchestrator", orchestrator_node)
graph_builder.add_node("analyst", analyst_node)
graph_builder.add_node("consultant", consultant_node)
graph_builder.add_node("reporter", reporter_node)

# Paso 2: Definir el punto de entrada
graph_builder.add_edge(START, "orchestrator")

# Paso 3: Añadir aristas condicionales desde el orquestador (su funcion de condicion es router)
graph_builder.add_conditional_edges(
    "orchestrator",
    router,
    {"analyst": "analyst",
     "consultant": "consultant",
     "reporter": "reporter",
     END: END}
)

# Paso 4: Cierre del flujo (Los workers vuelven al usuario)
graph_builder.add_edge("analyst", END)
graph_builder.add_edge("consultant", END)
graph_builder.add_edge("reporter", END)

# Inicializamos la memoria volátil (persiste el estado del grafo en RAM) particionado por thread_id.
# Cuando se llama a graph.ainvoke con un thread_id existente, LangGraph carga el estado anterior, añade el nuevo mensaje y ejecuta el grafo desde el inicio. 
# Esto implementa la memoria conversacional sin base de datos externa.
memory = MemorySaver()

# Compilación final
graph = graph_builder.compile(checkpointer=memory)