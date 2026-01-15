import os
from dotenv import load_dotenv
# Librerías de Telegram: Gestor de actualizaciones, filtros y contextos
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes
# Librería de LangChain para encapsular mensajes hacia el grafo
from langchain_core.messages import HumanMessage

# --- IMPORTACIONES PROPIAS (Módulos del TFG) ---
from agent_graph import graph      # El cerebro (Grafo de LangGraph)
from tools import get_file_hash    # Herramienta para cálculo SHA-256

# ==========================================
# 1. CONFIGURACIÓN E INICIALIZACIÓN
# ==========================================

# Cargar variables de entorno (Token) para no exponer secretos en el código
load_dotenv('.env') 
telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')

# Validación de seguridad: Sin token no podemos arrancar
if not telegram_token:
    print("❌ Error crítico: Falta la variable TELEGRAM_BOT_TOKEN en .env")
    exit()

# ==========================================
# 2. LÓGICA DE CONEXIÓN CON LA IA (PUENTE)
# ==========================================

async def process_with_graph(update: Update, text_input: str):
    """
    Función Puente: Conecta la interfaz de Telegram con el cerebro (LangGraph).
    
    Args:
        update: Objeto de actualización de Telegram.
        text_input: El texto que se enviará al grafo (puede ser mensaje del usuario 
                    o un prompt sintético generado tras subir un archivo).
    """
    try:
        print(f"🧠 Enviando al Grafo: '{text_input[:30]}...'")
        
        # 1. Encapsulamos el texto en un objeto HumanMessage de LangChain
        input_message = HumanMessage(content=text_input)
        
        # 2. Invocamos el Grafo (El cerebro decide si va al Analista o al Consultor)
        final_state = graph.invoke({'messages': [input_message]})
        
        # 3. Extraemos la última respuesta generada por la IA
        bot_response = final_state['messages'][-1].content
        
        # 4. Gestión de límites de Telegram (Splitter)
        # Telegram no permite mensajes de más de 4096 caracteres.
        max_length = 4000 
        if len(bot_response) > max_length:
            # Si es muy largo, lo troceamos y enviamos en partes
            for i in range(0, len(bot_response), max_length):
                await update.message.reply_text(bot_response[i:i+max_length])
        else:
            # Envío normal
            await update.message.reply_text(bot_response)
            
    except Exception as e:
        print(f"❌ Error en la ejecución del Grafo: {e}")
        await update.message.reply_text(f"⚠️ Error interno del sistema: {e}")

# ==========================================
# 3. MANEJADOR UNIVERSAL DE MENSAJES
# ==========================================

async def handle_any_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    MANEJADOR UNIVERSAL (Estrategia 'Catch-All'):
    Recibe CUALQUIER tipo de mensaje (Texto, Documento, Foto) y decide qué hacer.
    
    Motivo: Algunos clientes de Telegram (Desktop) envían archivos con tipos MIME 
    no estándar que los filtros específicos (filters.Document) a veces ignoran.
    Esta función garantiza que el bot reaccione siempre.
    """
    msg = update.message
    
    # CASO A: El usuario envió un DOCUMENTO (PDF, TXT, EXE, etc.)
    if msg.document:
        print("📂 DETECTADO: Documento adjunto")
        await process_file(update, msg.document)
        return

    # CASO B: El usuario envió una FOTO (Imagen comprimida)
    if msg.photo:
        print("📸 DETECTADO: Foto/Imagen")
        # Telegram envía varias versiones de la foto. msg.photo[-1] es la de mayor calidad.
        await process_file(update, msg.photo[-1])
        return

    # CASO C: El usuario envió TEXTO plano
    if msg.text:
        print(f"📩 DETECTADO: Texto -> {msg.text}")
        await process_with_graph(update, msg.text)
        return

    # CASO D: Tipo desconocido (Audio, Sticker, Ubicación...)
    print(f"⚠️ DETECTADO: Tipo no soportado ({msg})")
    await update.message.reply_text("Lo siento, mi sistema solo procesa texto o archivos para análisis.")

# ==========================================
# 4. LÓGICA DE PROCESAMIENTO DE ARCHIVOS
# ==========================================

async def process_file(update: Update, file_object):
    """
    Lógica común para descargar, analizar y limpiar archivos.
    Sigue el principio de Privacidad: Descarga -> Hash -> Borrado inmediato.
    """
    status_msg = await update.message.reply_text("📥 Descargando archivo para análisis forense...")
    download_path = None
    
    try:
        # 1. Obtener metadatos y descargar
        file_info = await file_object.get_file()
        
        # Intentamos obtener el nombre real. Si es una foto, inventamos uno genérico.
        file_name = getattr(file_object, 'file_name', 'archivo_imagen.jpg')
        
        # Ruta temporal en el servidor local
        download_path = f"temp_{file_name}"
        await file_info.download_to_drive(download_path)
        print(f"   💾 Archivo guardado temporalmente en: {download_path}")
        
        # 2. Calcular HUELLA DIGITAL (Hash SHA-256)
        # Esto es clave: No enviamos el archivo a la nube, enviamos su hash.
        file_hash = get_file_hash(download_path)
        print(f"   🔑 Hash SHA-256: {file_hash}")
        
        # 3. LIMPIEZA (Privacidad)
        # Borramos el archivo del disco inmediatamente después de calcular el hash.
        if os.path.exists(download_path):
            os.remove(download_path)
            
        if file_hash:
            await status_msg.edit_text(f"✅ Hash calculado.\n🕵️‍♂️ Consultando base de datos de amenazas...")
            
            # 4. INYECCIÓN DE PROMPT (Prompt Injection Benigna)
            # Creamos un mensaje sintético como si el usuario hubiera escrito:
            # "Analiza el hash X del archivo Y"
            # Esto activa automáticamente el nodo 'Analista' en el grafo.
            prompt_sintetico = f"Analiza el hash {file_hash} del archivo {file_name}"
            await process_with_graph(update, prompt_sintetico)
        else:
            await status_msg.edit_text("❌ Error: No se pudo generar la huella digital del archivo.")

    except Exception as e:
        print(f"❌ Error procesando archivo: {e}")
        # Aseguramos limpieza incluso si hay error
        if download_path and os.path.exists(download_path):
            os.remove(download_path)
        await status_msg.edit_text("Ocurrió un error técnico al procesar el archivo.")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Responde al comando /start"""
    await update.message.reply_text('¡Hola! Soy SecMate. Envíame un texto (dudas) o un archivo (análisis de virus).')

# ==========================================
# 5. PUNTO DE ENTRADA (MAIN)
# ==========================================
if __name__ == "__main__":
    # Construcción de la App
    app = ApplicationBuilder().token(telegram_token).build()

    # 1. Manejador de Comandos (/start)
    app.add_handler(CommandHandler("start", start))
    
    # 2. MANEJADOR MÁGICO
    # filters.ALL captura todo. ~filters.COMMAND excluye comandos (para que /start no entre aquí).
    # Esto asegura que NINGÚN mensaje se pierda.
    app.add_handler(MessageHandler(filters.ALL & ~filters.COMMAND, handle_any_message))
    
    print("🤖 SecMate (Modo Universal) está escuchando...")
    # Bucle infinito de escucha (Polling)
    app.run_polling()