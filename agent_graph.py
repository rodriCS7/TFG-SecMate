import os
import json
from dotenv import load_dotenv
from typing import Annotated
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

# --- MÓDULOS PROPIOS ---
# Separación de responsabilidades: Prompts en un lado, Herramientas en otro
from prompts import ORCHESTRATOR_SYSTEM_PROMPT, ANALYST_SYSTEM_PROMPT
from tools import check_hash_vt, extract_hash_from_text

# ==========================================
# 1. CONFIGURACIÓN E INICIALIZACIÓN
# ==========================================

# Carga de secretos desde .env para seguridad (evita hardcodear claves)
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
    messages: Annotated[list, add_messages] # append-only para mantener historial

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
    - Recibe el input del usuario.
    - Decide a qué especialista enviar la tarea (Analista, Consultor o Chat).
    - Usa LangChain para invocar al modelo.
    """
    # Inyectamos el System Prompt al principio del contexto
    messages = [SystemMessage(content=ORCHESTRATOR_SYSTEM_PROMPT)] + state['messages']
    
    # Invocamos a la IA
    response = llm.invoke(messages)
    
    # Limpiamos la respuesta por si viene con formato incorrecto (lista)
    response = clean_response_text(response)
    
    return {"messages": [response]}


def analyst_node(state: State):
    """
    NODO ANALISTA (El Especialista Técnico):
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
    
    # 2. Uso de Herramientas: Extracción de Hash y consulta a VirusTotal
    target_hash = extract_hash_from_text(user_text)

    if target_hash:
        print(f"🔍 Hash detectado: {target_hash}")
        print("🌍 Consultando VirusTotal...")
        vt_data = check_hash_vt(target_hash)

        # Manejo de errores de la API externa (VirusTotal)
        if "error" in vt_data:
             return {"messages": [SystemMessage(content=f"⚠️ Error VirusTotal: {vt_data['error']}")]}
        
        # 3. Ingeniería de Prompts (RAG Básico): Inyectamos los datos JSON en el prompt
        full_analysis_prompt = f"""
        {ANALYST_SYSTEM_PROMPT}
        --- DATOS TÉCNICOS DEL ANÁLISIS ---
        {json.dumps(vt_data)}
        """

        # 4. Generación de Respuesta (Lógica Robusta)
        try:
            print("🤖 Generando reporte con Gemini (Cliente Nativo)...")
            
            # BYPASS: Usamos el cliente nativo de Google directamente.
            # Esto evita el error "contents are required" de LangChain cuando
            # Google devuelve respuestas complejas sobre malware.
            client = genai.Client(api_key=google_key)
            
            # 2. Generamos contenido usando la estructura nueva
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
            
            # Validación: Aseguramos que hay texto antes de devolverlo
            if native_response.text:
                final_text = native_response.text
            else:
                raise ValueError("Respuesta vacía de la IA")

            # Envolvemos en AIMessage para mantener compatibilidad con el Grafo
            return {"messages": [AIMessage(content=final_text)]}

        except Exception as e:
            # FALLBACK (Plan B): Si la IA falla (por red o filtros de seguridad duros),
            # generamos un reporte determinista basado en los datos crudos.
            print(f"⚠️ FALLO IA ({e}). ACTIVANDO REPORTE MANUAL.")
            
            malicious = vt_data.get('malicious', 0)
            total = malicious + vt_data.get('undetected', 0) + vt_data.get('harmless', 0)
            names = ", ".join(vt_data.get('names', ['Desconocido']))
            
            # Lógica simple de semáforo
            if malicious > 0:
                verdict = "⛔ **PELIGROSO**"
                advice = "Este archivo ha sido detectado como malware. **NO LO ABRAS.**"
            else:
                verdict = "✅ **SEGURO**"
                advice = "Ningún motor antivirus ha detectado amenazas."

            # Construcción del mensaje manual
            manual_report = (
                f"🤖 *Nota: IA no disponible (Fallback activo). Análisis forense manual:*\n\n"
                f"🛡️ **Informe de Seguridad**\n"
                f"-------------------------\n"
                f"📂 **Archivo:** `{names}`\n"
                f"⚖️ **Veredicto:** {verdict}\n"
                f"📊 **Detecciones:** {malicious}/{total} motores\n"
                f"🔑 **Hash:** `{target_hash}`\n\n"
                f"💡 **Conclusión:** {advice}"
            )
            return {"messages": [SystemMessage(content=manual_report)]}
        
    else:
        return {"messages": [SystemMessage(content="[Analista] No encontré un hash válido. Por favor, envía el hash o sube el archivo.")]}


def consultant_node(state: State):
    """
    NODO CONSULTOR (RAG):
    Futura implementación para consultas sobre PDFs y teoría.
    """
    print("--- 📚 EJECUTANDO NODO CONSULTOR ---")
    return {"messages": [SystemMessage(content="[SISTEMA] El agente Consultor ha recibido la solicitud.")]}

# ==========================================
# 4. CONSTRUCCIÓN DEL GRAFO (Workflow)
# ==========================================

def router(state: State):
    """
    ROUTER (Semáforo):
    Lee la decisión del Orquestador y dirige el flujo al nodo correspondiente.
    """
    last_message = state['messages'][-1].content
    
    if "TO_ANALYST" in last_message: return "analyst"
    elif "TO_CONSULTANT" in last_message: return "consultant"
    else: return END

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

# Compilación final
graph = graph_builder.compile()