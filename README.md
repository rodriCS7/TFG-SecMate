# 🛡️ SecMate — Asistente de Ciberseguridad Multi-Agente

> Trabajo de Fin de Grado · Grado en Ingeniería de la Ciberseguridad · URJC 2025/2026

SecMate es un bot de Telegram basado en **Agentic AI** que integra análisis técnico de amenazas en tiempo real con una base de conocimiento académica local. A diferencia de los chatbots genéricos, SecMate **actúa**: analiza archivos sospechosos, detecta phishing semántico, consulta vulnerabilidades CVE y genera informes PDF técnicos de forma autónoma.

---

## ✨ Capacidades

| Función | Descripción |
|---|---|
| 🔍 **Análisis de Malware** | Envía un archivo o hash SHA-256 y obtén un veredicto basado en 70+ motores antivirus (VirusTotal) |
| 🎣 **Detección de Phishing** | Pega un mensaje sospechoso y el sistema detecta urgencia, suplantación y URLs maliciosas |
| 📚 **Consultor RAG** | Pregunta conceptos de ciberseguridad y recibe respuestas basadas en los apuntes de la carrera |
| 📄 **Generación de Informes** | Solicita un informe y el sistema genera un PDF técnico descargable |
| 🚨 **Boletín CVEs** | Suscríbete con `/subscribe` para recibir alertas diarias de vulnerabilidades críticas (CVSS ≥ 9.0) |

---

## 🏗️ Arquitectura

El sistema implementa un grafo de estado multi-agente con **LangGraph**, donde un Orquestador central enruta las peticiones hacia agentes especializados:

<img src="https://github.com/rodrics7/SecMate/blob/master/diagrama_arquitectura_SecMate.jpg" alt="Esquema de la arquitectura multi-agente de SecMate" width="100%">

- **Orquestador**: Clasifica la intención del usuario y decide el flujo de ejecución.
- **Analista CTI**: Análisis híbrido (VirusTotal API + análisis semántico con Gemini).
- **Consultor RAG**: Respuestas teóricas basadas exclusivamente en documentación local (RAG).
- **Reportero**: Genera informes PDF estructurados consolidando el contexto de la sesión.

---

## 🚀 Despliegue rápido

### Requisitos previos
- Motor de contenedores **Docker** instalado.
- API Key de [Telegram BotFather](https://t.me/BotFather).
- API Key de [Google AI Studio](https://aistudio.google.com/) (Gemini).
- API Key de [VirusTotal](https://www.virustotal.com/) (capa gratuita).

### 1. Clonar el repositorio y configurar entorno
```bash
git clone https://github.com/tu-usuario/SecMate.git
cd SecMate
cp .env.example .env  # Editar .env con tus claves
```
```env
TELEGRAM_BOT_TOKEN=tu_token_aqui
GOOGLE_API_KEY=tu_api_key_aqui
VT_API_KEY=tu_api_key_aqui
GEMINI_MODEL=modelo_llm
```

> ⚠️ `GEMINI_MODEL` solo acepta modelos de Google Gemini 
> (gemini-3.0-flash-preview, gemini-1.5-pro, etc.). 
> Consulta los modelos disponibles en 
> [Google AI Studio](https://aistudio.google.com/).

### 2. Construir la base de conocimiento RAG
Añade tus apuntes o manuales en formato PDF dentro de la carpeta data/.

### 3. Arrancar el bot
```bash
# Con entorno virtual
pip install -r requirements.txt
python SecMate.py

# Con Docker (recomendado)

# Construir la imagen
docker build -t secmate .

# Ejecutar el contenedor con volumen de persistencia
docker run -d \
  --name secmate \
  --env-file .env \
  -v ./data:/app/data \
  -v secmate_db:/app/chroma_db \
  secmate

# Monitorizar el proceso de ingesta y arranque
docker logs -f secmate
```

---

## 📁 Estructura del proyecto

```
SecMate/
├── SecMate.py          # Interfaz Telegram y punto de entrada
├── agent_graph.py      # Grafo LangGraph y lógica de agentes
├── tools.py            # Integraciones externas (VirusTotal, NIST, PDF)
├── prompts.py          # System prompts de cada agente
├── ingest.py           # Pipeline ETL para la base de conocimiento RAG
├── data/               # PDFs para el sistema RAG
├── chroma_db/          # Base de datos vectorial (generada por ingest.py)
├── Dockerfile
├── requirements.txt
└── .env                # Secretos (no incluido en el repositorio)
```

---

## 🛠️ Stack tecnológico

- **[LangGraph](https://langchain-ai.github.io/langgraph/)** — Orquestación del grafo de agentes y memoria conversacional
- **[Google Gemini Flash](https://deepmind.google/technologies/gemini/)** — Motor LLM principal
- **[ChromaDB](https://www.trychroma.com/)** — Base de datos vectorial local para RAG
- **[HuggingFace sentence-transformers](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2)** — Modelo de embeddings local (`all-MiniLM-L6-v2`)
- **[python-telegram-bot](https://python-telegram-bot.org/)** — Interfaz asíncrona con Telegram
- **[VirusTotal API v3](https://docs.virustotal.com/)** — Inteligencia de amenazas
- **[NIST NVD API](https://nvd.nist.gov/developers)** — Base de datos de vulnerabilidades CVE
- **[FPDF](https://pyfpdf.github.io/fpdf2/)** — Generación programática de informes PDF

---

## 💬 Uso

```
# Análisis de archivo
→ Adjunta cualquier archivo al chat

# Análisis de URL o hash
→ "Analiza este hash: 275a021bbfb6489e54d..."
→ "¿Es phishing? http://ejemplo-sospechoso.com"

# Consulta teórica
→ "¿Qué es un RAT?"
→ "¿Cómo funciona el ransomware?"

# Generar informe
→ "Genera un informe de lo analizado"

# Boletín CVEs
→ /subscribe
```

---

## 👨‍💻 Autor

**Rodrigo Chivo Sánchez** · Grado en Ingeniería de la Ciberseguridad · URJC  