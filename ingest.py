# ================================================
# INGESTA DE DOCUMENTOS A BASE DE DATOS VECTORIAL
# ================================================
# Script para convertir texto humano (PDFs) en "matemáticas" vectores
# que los modelos de lenguaje pueden buscar rápidamente.

import os
import shutil
import time
from dotenv import load_dotenv

# Librerías
from langchain_community.document_loaders import PyPDFDirectoryLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_google_genai import GoogleGenerativeAIEmbeddings

# Cargar entorno
load_dotenv('.env')
google_key = os.getenv('GOOGLE_API_KEY')

if not google_key:
    print("❌ Error: Falta GOOGLE_API_KEY")
    exit()

# Configuración
DATA_PATH = "data"
DB_PATH = "chroma_db"
BATCH_SIZE = 20  # Enviaremos 20 trozos cada vez
SLEEP_TIME = 2   # Esperaremos 2 segundos entre envíos

def main():
    print(f"📂 Buscando documentos en '{DATA_PATH}'...")
    
    loader = PyPDFDirectoryLoader(DATA_PATH)
    raw_documents = loader.load()
    
    if not raw_documents:
        print("⚠️ No hay PDFs en 'data/'.")
        return

    print(f"   ✅ Se han leído {len(raw_documents)} páginas.")

    # Troceado/Chunking de documentos
    # Para no saturar la memoria y mantener contexto relevante
    print("✂️  Troceando documentos...")
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=200, # Dejamos que se solapen para no cortar contexto a medias
        add_start_index=True
    )
    chunks = text_splitter.split_documents(raw_documents)
    print(f"    Total fragmentos a procesar: {len(chunks)}")

    # Limpiar BD anterior
    if os.path.exists(DB_PATH):
        shutil.rmtree(DB_PATH)

    # Configurar Embeddings (Palabras a Vectores/Coordenadas numéricas)
    # Palabras con significados similares tendrán números parecidos y estarán "cerca" en 
    # el espacio matemático. "Virus" estará cerca de "Malware" y lejos de "Bocadillo".
    print("💾 Iniciando base de datos con 'text-embedding-004'...")
    embeddings = GoogleGenerativeAIEmbeddings(
        model="models/text-embedding-004",
        google_api_key=google_key
    )

    # Inicializar base de datos vacía
    # Chroma es una base de datos vectorial ligera y rápida
    vector_store = Chroma(
        embedding_function=embeddings,
        persist_directory=DB_PATH
    )

    # PROCESAMIENTO POR LOTES (BATCHING)
    # Evitamos saturar la API de Google con demasiadas peticiones
    # Enviamos BATCH_SIZE fragmentos y esperamos SLEEP_TIME segundos
    total_batches = (len(chunks) // BATCH_SIZE) + 1
    print(f"🚀 Iniciando ingesta en {total_batches} lotes...")

    for i in range(0, len(chunks), BATCH_SIZE):
        batch = chunks[i : i + BATCH_SIZE]
        if not batch: continue
        
        print(f"   🔹 Procesando lote {i//BATCH_SIZE + 1}/{total_batches} ({len(batch)} docs)...")
        
        try:
            # Añadimos los documentos a la BD
            vector_store.add_documents(batch)
            # Descanso para no enfadar a Google
            time.sleep(SLEEP_TIME) 
        except Exception as e:
            print(f"   ❌ Error en el lote: {e}")
            # Si falla, esperamos más tiempo y reintentamos una vez
            time.sleep(10)
            try:
                vector_store.add_documents(batch)
                print("   ✅ Reintento exitoso.")
            except:
                print("   💀 El lote se perdió definitivamente.")

    print(f"✅ ¡Éxito! Base de datos guardada en '{DB_PATH}'.")

if __name__ == "__main__":
    main()