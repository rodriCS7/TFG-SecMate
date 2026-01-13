import os
# dotenv: Librería para gestionar variables de entorno (seguridad de claves)
from dotenv import load_dotenv 
# Telegram: Librerías para interactuar con la API del bot
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

# --- LIBRERÍAS DE IA Y ORQUESTACIÓN ---
# LangChain Google: Conector para usar los modelos Gemini
from langchain_google_genai import ChatGoogleGenerativeAI
# Mensajes: Estructuras de datos para definir roles (Sistema vs Usuario)
from langchain_core.messages import SystemMessage, HumanMessage
# LangGraph: Librería para construir el flujo de estados y agentes
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from typing import Annotated
from typing_extensions import TypedDict

# ==========================================
# 1. CONFIGURACIÓN DEL ENTORNO
# ==========================================
# Cargamos las claves desde el archivo .env para no exponerlas en el código
load_dotenv('.env') 

telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
google_key = os.getenv('GOOGLE_API_KEY')

# Validación de seguridad: Si faltan claves, detenemos la ejecución
if not telegram_token or not google_key:
    print("❌ Error crítico: Faltan variables de entorno (TELEGRAM_BOT_TOKEN o GOOGLE_API_KEY).")
    exit()

# ==========================================
# 2. PROMPT ENGINEERING (INGENIERÍA DE PROMPTS)
# ==========================================
# Definimos la "personalidad" y lógica de decisión del Orquestador.
# No responde técnicamente, solo clasifica la intención del usuario.
ORCHESTRATOR_SYSTEM_PROMPT = """
Eres el orquestador de un asistente de ciberseguridad llamado SecMate. 
Tu trabajo es recibir la consulta del usuario y CLASIFICARLA.

Analiza la entrada y decide el siguiente paso:
1. "TO_ANALYST": Si detectas un HASH, IP, URL o petición de análisis técnico.
2. "TO_CONSULTANT": Si es una pregunta teórica o académica sobre ciberseguridad.
3. "TO_CHAT": Saludos o charla general.

TU RESPUESTA DEBE SEGUIR ESTE FORMATO EXACTO:
[DECISION] :: [RAZONAMIENTO] :: [RESPUESTA_AL_USUARIO]
"""

# ==========================================
# 3. ARQUITECTURA LANGGRAPH (EL CEREBRO)
# ==========================================

# A. Definición del Estado (Memoria Compartida)
# 'messages' guardará todo el historial de la conversación.
# 'add_messages' asegura que los mensajes nuevos se añadan a la lista, no la sobrescriban.
class State(TypedDict):
    messages: Annotated[list, add_messages]

# B. Inicialización del Modelo LLM
# Usamos Gemini Flash
# Temperature = 0.3: Baja creatividad para asegurar que siga las reglas de clasificación estrictamente.
llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    google_api_key=google_key,
    temperature=0.3, 
)

# C. Nodo Orquestador
# Este nodo representa al agente que toma la decisión inicial.
def orchestrator_node(state: State):
    # Inyectamos el System Prompt al principio del historial para dar contexto al modelo
    messages = [SystemMessage(content=ORCHESTRATOR_SYSTEM_PROMPT)] + state['messages']
    
    # Invocamos al modelo y obtenemos la respuesta
    response = llm.invoke(messages)
    
    # Devolvemos el mensaje nuevo para actualizar el estado
    return {"messages": [response]}

# D. Construcción del Grafo (Flujo de Trabajo)
graph_builder = StateGraph(State)

# Añadimos el nodo al grafo
graph_builder.add_node("orchestrator", orchestrator_node)

# Definimos el flujo: Inicio -> Orquestador -> Fin (Por ahora es lineal)
graph_builder.add_edge(START, "orchestrator")
graph_builder.add_edge("orchestrator", END)

# Compilamos el grafo para hacerlo ejecutable
graph = graph_builder.compile()


# ==========================================
# 4. INTERFAZ DE TELEGRAM (LA CAPA DE VISTA)
# ==========================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Responde al comando /start iniciando la interacción."""
    await update.message.reply_text('¡Hola! Soy SecMate (vía Google Gemini). ¿En qué puedo ayudarte hoy?')

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Maneja cualquier mensaje de texto entrante.
    Actúa como puente entre Telegram y LangGraph.
    """
    user_text = update.message.text
    print(f"📩 Usuario dice: {user_text}")

    # Convertimos el texto de Telegram a un formato que entienda LangChain
    input_message = HumanMessage(content=user_text)

    try:
        # Ejecutamos el grafo con el mensaje del usuario
        final_state = graph.invoke({'messages': [input_message]})
        
        # Extraemos la última respuesta generada por la IA
        bot_response = final_state['messages'][-1].content

        # --- GESTIÓN DE LÍMITES DE TELEGRAM ---
        # Telegram tiene un límite duro de 4096 caracteres.
        # Cortamos en 4000 para dejar margen a negritas y formato Markdown.
        max_length = 4000 

        if len(bot_response) > max_length:
            # Algoritmo de segmentación: Divide el mensaje en trozos de 4000 caracteres
            for i in range(0, len(bot_response), max_length):
                await update.message.reply_text(bot_response[i:i+max_length])
        else:
            # Envío normal
            await update.message.reply_text(bot_response)

    except Exception as e:
        print(f"❌ Error en el sistema: {e}")
        await update.message.reply_text("Lo siento, ha ocurrido un error interno al procesar tu solicitud.")

# ==========================================
# 5. PUNTO DE ENTRADA (MAIN)
# ==========================================
if __name__ == "__main__":
    # Construimos la aplicación de Telegram
    app = ApplicationBuilder().token(telegram_token).build()

    # Registramos los manejadores (Handlers)
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    print("🤖 SecMate está escuchando y listo para clasificar...")
    # Iniciamos el bucle de escucha (Polling)
    app.run_polling()