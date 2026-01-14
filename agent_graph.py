import os
from dotenv import load_dotenv
from typing import Annotated
from typing_extensions import TypedDict

# LangChain / LangGraph imports
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages

# Importamos nuestros prompts
from prompts import ORCHESTRATOR_SYSTEM_PROMPT

# Cargar el entorno
load_dotenv('.env')
google_key = os.getenv('GOOGLE_API_KEY')

# Validación de seguridad: Si faltan claves, detenemos la ejecución
if not google_key:
    print("❌ Error crítico: Faltan variables de entorno (GOOGLE_API_KEY).")
    exit()

# ==========================================
# ARQUITECTURA LANGGRAPH
# ==========================================


# Definición del Estado (Memoria Compartida)
# 'messages' guardará todo el historial de la conversación.
# 'add_messages' asegura que los mensajes nuevos se añadan a la lista, no la sobrescriban.
class State(TypedDict):
    messages: Annotated[list, add_messages]

# Inicialización del Modelo LLM
# Usamos Gemini Flash
# Temperature = 0.3: Baja creatividad para asegurar que siga las reglas de clasificación estrictamente.
llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    google_api_key=google_key,
    temperature=0.3, 
)

# Nodo Orquestador
# Este nodo representa al agente que toma la decisión inicial.
def orchestrator_node(state: State):
    # Inyectamos el System Prompt al principio del historial para dar contexto al modelo
    messages = [SystemMessage(content=ORCHESTRATOR_SYSTEM_PROMPT)] + state['messages']
    
    # Invocamos al modelo y obtenemos la respuesta
    response = llm.invoke(messages)
    
    # Devolvemos el mensaje nuevo para actualizar el estado
    return {"messages": [response]}

# Nodos Workers (de momento es esqueleto)
def analyst_node(state: State):
    # Lógica de Virustotal, etc en el futuro
    print("🔧 Nodo Analyst invocado (pendiente de implementación).")
    return {"messages": [SystemMessage(content="[SISTEMA] El agente Analista ha recibido la solicitud")]}

def consultant_node(state: State):
    # Lógica de consulta teórica en el futuro
    print("🔧 Nodo Consultant invocado (pendiente de implementación).")
    return {"messages": [SystemMessage(content="[SISTEMA] El agente Consultor ha recibido la solicitud")]}

# Funcion ROUTER

def router(state: State):
    # Obtenemos el último mensaje (La respuesta del orquestador)
    last_message = state['messages'][-1].content

    # Buscamos las palabras definidas en el promt del orquestador (TO_ANALYST, TO_CONSULTANT, TO_CHAT)
    if "TO_ANALYST" in last_message:
        return "analyst"
    elif "TO_CONSULTANT" in last_message:
        return "consultant"
    else:
        return END

# Construcción del Grafo (Flujo de Trabajo)
graph_builder = StateGraph(State)

# Añadimos todos los nodos
graph_builder.add_node("orchestrator", orchestrator_node)
graph_builder.add_node("analyst", analyst_node)
graph_builder.add_node("consultant", consultant_node)

# Definimos el punto de entrada
graph_builder.add_edge(START, "orchestrator")

# Añadimos la lógica condicional
# "Desde el orquestador, ejecuta la función 'router' para decidir a donde ir"
graph_builder.add_conditional_edges(
    "orchestrator", # Nodo de origen
    router, # Funcion que decide
    {   # posibles caminos: {valor_devuelto: nodo_destino}
        "analyst": "analyst",
        "consultant": "consultant",
        END: END
    }
)

# Cerramos los caminos de los workers (no están implementados aún)
graph_builder.add_edge("analyst", END)
graph_builder.add_edge("consultant", END)

# Compilamos el grafo para hacerlo ejecutable
graph = graph_builder.compile()