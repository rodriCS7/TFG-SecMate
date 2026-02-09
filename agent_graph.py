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
from langchain_google_genai import ChatGoogleGenerativeAI, HarmBlockThreshold, HarmCategory
from langchain_core.messages import SystemMessage, AIMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.checkpoint.memory import MemorySaver # Para añadir memoria al grafo

# --- MÓDULOS PROPIOS ---
# Separación de responsabilidades: Prompts en un lado, Herramientas en otro
from prompts import ORCHESTRATOR_SYSTEM_PROMPT, ANALYST_SYSTEM_PROMPT, CONSULTANT_RAG_PROMPT
from tools import check_hash_vt, check_url_virustotal, extract_hash_from_text, extract_url_from_text

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

# Configuración del Cliente LangChain (Principal)
# Usamos 'gemini-2.5-flash' por ser el modelo más eficiente y capaz actualmente.
# Temperature 0.3 reduce alucinaciones.
# BLOCK_NONE en seguridad es vital para permitir analizar malware sin bloqueos.

llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    google_api_key=google_key,
    temperature=0.3, 
    safety_settings={
        HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
    }
)


# Definición del Estado del Grafo (La "Memoria" del Bot)
class State(TypedDict):
    # 1. Historial de chat (Append-only: Los mensajes nuevos se añaden al final)
    messages: Annotated[list, add_messages] 
    
    # 2. Contexto de Amenaza (Overwrite: Se sobrescribe con cada análisis nuevo)
    # Aquí guardaremos "Phishing", "Ransomware", etc.
    active_threat: Optional[str]
    
    # 3. Pregunta Refinada (Overwrite: Pasa del Orquestador al Consultor)
    # Si el usuario dice "Sí", aquí guardaremos "¿Qué es un Ransomware?"
    refined_query: Optional[str]

    next_step: Optional[str] # Variable temporal para el router condicional (no se guarda en memoria, solo para lógica de flujo)

# ==========================================
# 2. FUNCIONES AUXILIARES (UTILITIES)
# ==========================================

def clean_response_text(ai_message):
    """
    SANITIZADOR DE RESPUESTAS:
    Corrige un bug conocido de compatibilidad entre Gemini y LangChain donde
    la IA devuelve una lista de objetos JSON en lugar de texto plano.
    Esta función extrae y concatena el texto para evitar que el Router falle.
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
    # Mantenemos el historial para que entienda "Explícame ESO"
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
        "messages": [AIMessage(content=refined_content)], # Guardamos lo que pensó el orquestador (opcional, para debug)
        "next_step": decision, # Variable temporal para el router condicional
        "refined_query": refined_content if decision == "TO_CONSULTANT" else None
    }


def analyst_node(state: State):
    """
    NODO ANALISTA (El Especialista Técnico):
    - Combina Inteligencia Técnica (VirusTotal) + Inteligencia Semántica (Análisis de Texto).
    - Objetivo: Detectar ataques complejos donde la URL puede parecer limpia pero el contexto es malicioso.
    - Implementa lógica HÍBRIDA (IA + Determinista).
    - Usa el SDK Nativo de Google para saltar limitaciones de LangChain con datos de virus.
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
        return {"messages": [SystemMessage(content=f"⚠️ Error VirusTotal: {vt_data['error']}")]}  

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
        f"\n\n🎓 *¿Quieres aprender más?*\n"
        f"Simplemente dime *'Explícame qué es esto'* o *'¿Cómo funciona?'* y te daré más información sobre {detected_topic}."
    )

    # 4. Generaración de Respuesta con Cliente Nativo (Bypass de Seguridad)
    try:
        print(f"🤖 Correlacionando datos ({analysis_type} + Texto) con Gemini (Nativo)...")
        
        client = genai.Client(api_key=google_key)
        
        native_response = client.models.generate_content(
                model="gemini-2.5-flash",
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
    # El grafo de LangGraph pasa un objeto state que contiene todo el historial del chat. 
    # El código recorre los mensajes de atrás hacia adelante (reversed) para encontrar 
    # la última pregunta que hizo el usuario.
    
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

    # Embeddings - cambiamos a HuggingFaceEmbeddings para evitar problemas de cuota con Google en la capa gratuita
    embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
    
    try:
        # Conexión a la BBDD vectorial
        vector_store = Chroma(persist_directory=DB_PATH, embedding_function=embeddings)
        
        # 3. Retrieval
        # Convierte la pregunta en un vector y busca los K fragmentos más cerca matemáticamente (más relevantes).
        results = vector_store.similarity_search(user_question, k=15)
        # A. Extraemos el contexto para la IA
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
        # Context Injection: Inyectamos contexto y pregunta en el prompt RAG
        rag_prompt = CONSULTANT_RAG_PROMPT.format(
            context_text=context_text,
            user_question=user_question
        )

        # 5. GENERACIÓN CON CLIENTE NATIVO (BYPASS DE SEGURIDAD)
        print("🤖 Generando respuesta con Gemini (Nativo)...")
        
        client = genai.Client(api_key=google_key)
        
        native_response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=rag_prompt,
            config=types.GenerateContentConfig(
                safety_settings=[
                    types.SafetySetting(
                        category="HARM_CATEGORY_DANGEROUS_CONTENT",
                        threshold="BLOCK_NONE"
                    ),
                    types.SafetySetting(
                        category="HARM_CATEGORY_HATE_SPEECH",
                        threshold="BLOCK_NONE"
                    ),
                    types.SafetySetting(
                        category="HARM_CATEGORY_HARASSMENT",
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
    elif decision == "TO_CHAT":
        return END
    else:
        return END


# Definición de la estructura del grafo
graph_builder = StateGraph(State)

# A. Añadir Nodos
graph_builder.add_node("orchestrator", orchestrator_node)
graph_builder.add_node("analyst", analyst_node)
graph_builder.add_node("consultant", consultant_node)

# B. Definir Flujo (Aristas)
graph_builder.add_edge(START, "orchestrator") # Punto de entrada

# C. Lógica Condicional (Decision Making)
graph_builder.add_conditional_edges(
    "orchestrator",
    router,
    {"analyst": "analyst", "consultant": "consultant", END: END}
)

# D. Cierre del flujo (Los workers vuelven al usuario)
graph_builder.add_edge("analyst", END)
graph_builder.add_edge("consultant", END)

# Inicializamos la memoria volátil (se borra al reiniciar el bot)
memory = MemorySaver()

# Compilación final
graph = graph_builder.compile(checkpointer=memory)