# ================================================
# INGESTA DE DOCUMENTOS (RAG OFFLINE)
# ================================================
# Script de ETL (Extract, Transform, Load) para la base de conocimiento.
#
# ARQUITECTURA:
# Utiliza un modelo de Embeddings Local (HuggingFace) para convertir
# los documentos PDF en vectores almacenados en ChromaDB.
# Esto garantiza privacidad, baja latencia y funcionamiento sin conexión.

import os
import shutil
from dotenv import load_dotenv

# Librerías de LangChain y Comunidad
from langchain_community.document_loaders import PyPDFDirectoryLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

# Cargar entorno
load_dotenv('.env')

# Constantes de Configuración
DATA_PATH = "data"       # Carpeta origen de PDFs
DB_PATH = "chroma_db"    # Carpeta destino de Vectores

def main():
    print(f"📂 Iniciando proceso de ingesta desde '{DATA_PATH}'...")
    
    # 1. EXTRACCIÓN (LOAD)
    # Cargamos todos los PDFs del directorio especificado.
    loader = PyPDFDirectoryLoader(DATA_PATH)
    raw_documents = loader.load()
    
    if not raw_documents:
        print("⚠️ Advertencia: No se encontraron documentos en 'data/'.")
        return

    print(f"   ✅ Documentos cargados. Total páginas: {len(raw_documents)}")

    # 2. TRANSFORMACIÓN (SPLIT)
    # Dividimos el texto en fragmentos (chunks) para optimizar la búsqueda semántica.
    # El solapamiento (overlap) preserva el contexto entre cortes de párrafo.
    print("✂️  Procesando y segmentando texto...")
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,      # Caracteres por fragmento
        chunk_overlap=200,    # Contexto compartido entre fragmentos para mejorar la relevancia en búsquedas
        add_start_index=True
    )
    chunks = text_splitter.split_documents(raw_documents)
    print(f"    Fragmentos generados: {len(chunks)}")

    # 3. LIMPIEZA PREVIA (RESET)
    # Eliminamos la base de datos existente para garantizar una ingesta limpia
    # y evitar duplicados si el script se ejecuta múltiples veces.
    if os.path.exists(DB_PATH):
        print("🧹 Limpiando base de datos anterior para evitar redundancia...")
        shutil.rmtree(DB_PATH)

    # 4. MODELADO (EMBEDDINGS)
    # Inicializamos el modelo de lenguaje local.
    # 'all-MiniLM-L6-v2' es un modelo SOTA (State Of The Art) para tareas de 
    # similitud semántica, optimizado para ejecutarse en CPU.
    print("💾 Cargando modelo de embeddings (HuggingFace Local)...")
    embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

    # 5. CARGA (LOAD TO VECTOR STORE)
    # Generamos los vectores y los persistimos en disco usando ChromaDB.
    print("🚀 Generando índices vectoriales y guardando en disco...")
    
    vector_store = Chroma.from_documents(
        documents=chunks,
        embedding=embeddings,
        persist_directory=DB_PATH
    )

    print(f"✅ ¡Ingesta completada! Base de conocimiento actualizada en '{DB_PATH}'.")

if __name__ == "__main__":
    main()