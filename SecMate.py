from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

import os
from dotenv import load_dotenv

# 1. Cargar el entorno
load_dotenv('.env')

telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
openai_key = os.getenv('OPENAI_API_KEY')

# Verificar que las variables de entorno se han cargado correctamente
if telegram_token:
    print(f"✅ Token cargado correctamente")
else:
    print(f"❌ Error: no se ha podido cargar el token")

# 2. Definir la funcion que responde al comando /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text('Hello! I am SecMate.')

# 3. Construir la aplicación
app = ApplicationBuilder().token(telegram_token).build()

# 4. Conectar el comando '/start' con la funcion 'start'
app.add_handler(CommandHandler("start", start))

# 5. Poner el bot a escuchar
print("🤖 SecMate está escuchando...")
app.run_polling()
