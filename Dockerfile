# 1. IMAGEN BASE
FROM python:3.11-slim

# 2. VARIABLES DE ENTORNO DE PYTHON
# PYTHONDONTWRITEBYTECODE=1 --> Evita generar archivos .pyc (basura)
# PYTHONUNBUFFERED=1 --> Fuerza que los logs salgan instantáneamente en la consola (para ver errores)
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 3. DIRECTORIO DE TRABAJO
WORKDIR /app

# 4. INSTALAR DEPENDENCIAS DEL SISTEMA
# 'build-essential' y 'curl' son necesarios para compilar algunas librerías de C++ que usa ChromaDB
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 5. INSTALAR DEPENDENCIAS DE PYTHON
# Copiamos primero el requirements.txt para aprovechar la caché de Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 6. COPIAR EL CÓDIGO FUENTE
# Copiamos todo el resto del proyecto (respetando el .dockerignore)
COPY . .

# 7. COMANDO DE ARRANQUE
# Ejecutamos el bot
CMD ["python", "SecMate.py"]