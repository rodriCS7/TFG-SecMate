import os
from dotenv import load_dotenv
from datetime import datetime

# Imports para el SDK de google
from google import genai
from google.genai import types

# Librerías de Telegram: Gestor de actualizaciones, filtros y contextos
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes
from telegram.constants import ParseMode

# Librería de LangChain para encapsular mensajes hacia el grafo
from langchain_core.messages import HumanMessage

# --- IMPORTACIONES PROPIAS (Módulos del TFG) ---
from agent_graph import graph      # El cerebro (Grafo de LangGraph)
from tools import get_file_hash, get_new_critical_cves    # Herramienta para cálculo SHA-256 y consulta de CVEs recientes
from prompts import BOLETIN_DE_SEGURIDAD_PROMPT

# ==========================================
# 1. CONFIGURACIÓN E INICIALIZACIÓN
# ==========================================

# Cargar variables de entorno (Token) para no exponer secretos en el código
load_dotenv('.env') 
telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
google_api_key = os.getenv('GOOGLE_API_KEY')

# Validación de seguridad: Sin token no podemos arrancar
if not telegram_token:
    print("❌ Error crítico: Falta la variable TELEGRAM_BOT_TOKEN en .env")
    exit()

if not google_api_key:
    print("❌ Error crítico: Falta la variable GOOGLE_API_KEY en .env")
    exit()

client = genai.Client(api_key=google_api_key)

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
        # 1. Identificar al usuario (thread_id)
        chat_id = update.effective_chat.id
        user_name = update.effective_user.first_name

        print(f"🧠 [{user_name} - {chat_id}] Enviando al Grafo: '{text_input[:30]}...'")
        
        # 2. Configuración de Memoria para este usuario
        # El 'thread_id' permite al grafo mantener contexto por usuario.
        config = {"configurable": {"thread_id": str(chat_id)}}

        # 3. Encapsulamos el texto en un objeto HumanMessage de LangChain
        input_message = HumanMessage(content=text_input)
        
        # 4. Invocamos el Grafo de forma asincrona para no bloquear el bot si hay muchos usuarios
        # Le pasamos la configuración
        final_state = await graph.ainvoke(
            {'messages': [input_message]}, 
            config=config
        )
        
        # 5. Extraemos la última respuesta generada por la IA
        raw_response = final_state['messages'][-1].content

        # --- GESTIÓN DE ARCHIVOS (REPORTER) ---
        if "FILE_GENERATED::" in raw_response:
            # Es una ruta de archivo
            file_path = raw_response.split("FILE_GENERATED::")[1].strip()

            if os.path.exists(file_path):
                print(f"📤 Enviando documento: {file_path}")
                await update.message.reply_document(
                    document=open(file_path, 'rb'),
                    caption="📄 Aquí tienes el informe técnico solicitado."
                )
                # Borramos el temporal
                os.remove(file_path)
            else:
                await update.message.reply_text("⚠️ Error: El archivo de reporte no se pudo encontrar.")
            return # Salimos de la función porque ya respondimos al usuario con el archivo
        

        # --- Limpiamos la respuesta ---
        # Si el bot responde con formato "ACCIÓN :: RAZÓN :: MENSAJE", nos quedamos solo con el MENSAJE.
        if "::" in raw_response:
            # Dividimos por "::" y cogemos el último trozo (-1)
            bot_response = raw_response.split("::")[-1].strip()
        else:
            bot_response = raw_response

        # 6. Gestión de límites de Telegram (Splitter)
        # Telegram no permite mensajes de más de 4096 caracteres.
        max_length = 4000 

        # Si el mensaje es corto
        if len(bot_response) <= max_length:
            try:
                # INTENTO A: Enviar bonito (Markdown)
                await update.message.reply_text(
                    bot_response, 
                    parse_mode=ParseMode.MARKDOWN
                )
            except Exception as e:
                print(f"⚠️ Error de formato Markdown ({e}). Enviando plano.")
                # INTENTO B: Enviar feo (Texto Plano) - FALLBACK
                await update.message.reply_text(bot_response)

        # Si el mensaje es muy largo (Troceado)
        else:
            for i in range(0, len(bot_response), max_length):
                chunk = bot_response[i:i+max_length]
                try:
                    await update.message.reply_text(
                        chunk, 
                        parse_mode=ParseMode.MARKDOWN
                    )
                except Exception as e:
                    await update.message.reply_text(chunk)
            
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

    # --- PROTECCIÓN CONTRA CRASHEOS ---
    # Si update.message es None (ej: Edición de mensaje), lo ignoramos
    if not update.message:
        return
    
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
            await status_msg.edit_text("✅ Hash calculado.\n🕵️‍♂️ Consultando base de datos de amenazas...")
            
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
    await update.message.reply_text('¡Hola! Soy SecMate. Consúltame dudas sobre ciberseguridad o envíame archivos para que los analice.')


# === Sistema de alertas automáticas (NIST CVEs) ===

async def check_new_cves (context: ContextTypes.DEFAULT_TYPE):
    """
    Tarea programada: 
    1. Consulta la API del NIST.
    2. Si hay CVEs críticos, llama DIRECTAMENTE a Gemini (Bypass del Grafo).
    3. Envía la alerta formateada.
    """

    job = context.job
    chat_id = job.data or job.chat_id
    
    print(f"⏰ Ejecutando escaneo de vulnerabilidades para chat {chat_id}...")

    # 1. Buscamos datos crudos del NIST
    new_cves_text = get_new_critical_cves()
    
    # Obtienes la fecha actual en formato día/mes/año (ej: 05/02/2026) para incluirla en el boletín de seguridad.
    fecha_actual = datetime.now().strftime("%d/%m/%Y")
    
    if new_cves_text:
        print("   🆕 Nuevas vulnerabilidades críticas encontradas.")
        
        # 2. Formateamos el prompt 
        formatted_prompt = BOLETIN_DE_SEGURIDAD_PROMPT.format(
            cves_text=new_cves_text,
            date=fecha_actual
        )
        
        try:
            # 3. LLAMADA DIRECTA CON NUEVO SDK + BYPASS SEGURIDAD
            # Usamos .aio para llamadas asíncronas

            response = await client.aio.models.generate_content(
                model='gemini-3-flash-preview',
                contents=formatted_prompt,
                config=types.GenerateContentConfig(
                    safety_settings=[
                        types.SafetySetting(
                            category="HARM_CATEGORY_DANGEROUS_CONTENT",
                            threshold="BLOCK_NONE"
                        )
                    ]
                )
            )
            
            bot_response = response.text
            
            # 4. ENVÍO SEGURO
            try:
                await context.bot.send_message(
                    chat_id=chat_id, 
                    text=bot_response, 
                    parse_mode=ParseMode.MARKDOWN
                )
            except Exception as telegram_error:
                print(f"⚠️ Falló el Markdown ({telegram_error}). Enviando plano.")
                await context.bot.send_message(
                    chat_id=chat_id, 
                    text=bot_response
                )

        except Exception as e:
            print(f"❌ Error conectando con Gemini Directo: {e}")
    else:
        print(f"✅ Sin novedades críticas para {chat_id}.")


async def subscribe (update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Comando /subscribe para activar el boletin de seguridad diario"""
    chat_id = update.effective_message.chat_id

    # Limpiamos trabajos anteriores
    current_jobs = context.job_queue.get_jobs_by_name(str(chat_id))
    for job in current_jobs:
        job.schedule_removal()

    # Programamos: Cada 24 horas (86400 segundos)
    # first=5: La primera comprobación se hace a los 5 segundos
    context.job_queue.run_repeating(
        check_new_cves,
        interval = 86400,
        first = 5,
        chat_id = chat_id,
        data = chat_id,
        name = str(chat_id)
    )

    await update.message.reply_text("✅ Has sido suscrito al boletín diario de vulnerabilidades críticas. Recibirás alertas cada 24 horas.")

# ==========================================
# 5. PUNTO DE ENTRADA (MAIN)
# ==========================================
if __name__ == "__main__":
    # Construcción de la App
    app = ApplicationBuilder().token(telegram_token).build()

    # 1. Manejador de Comandos (/start)
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("subscribe", subscribe))
    
    # 2. MANEJADOR MÁGICO
    # filters.ALL captura todo. ~filters.COMMAND excluye comandos (para que /start no entre aquí).
    # Esto asegura que NINGÚN mensaje se pierda.
    app.add_handler(MessageHandler(filters.ALL & ~filters.COMMAND, handle_any_message))
    
    print("🤖 SecMate está escuchando...")
    # Bucle infinito de escucha (Polling)
    app.run_polling()