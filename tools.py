import os
import re
import hashlib
import requests
import base64
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from fpdf import FPDF

load_dotenv('.env')
VT_KEY = os.getenv('VT_API_KEY')

if not VT_KEY:
    print("⚠️ Error: Falta la API Key de VirusTotal.")

# =============================
# Para el módulo de VirusTotal
# =============================

def get_file_hash(file_path):

    # Calcula el hash SHA-256 de un archivo local

    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""): # Lectura incremental para no cargar archivos grandes enteros en memoria
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None
    

def extract_hash_from_text(text):

    # Busca cadenas de caracteres que parezcan un hash (MD5, SHA1, SHA256) en un texto.
    # Buscamos cadenas de 32, 40 o 64 caracteres hexadecimales

    match = re.search(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', text)
    if match:
        return match.group(0)
    return None


def check_hash_vt(file_hash):

    # Consulta a VirusTotal y devuelve un diccionario con los datos crudos.

    if not VT_KEY:
        return {"error": "Falta la clave de API de VirusTotal."}
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_KEY}

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            attrs = data['data']['attributes']
            stats = attrs['last_analysis_stats']

            # Devolvemos los datos estructurados para que el LLM los entienda
            return {
                "found": True,
                "hash": file_hash,
                "malicious": stats['malicious'],
                "suspicious": stats['suspicious'],
                "harmless": stats['harmless'],
                "undetected": stats['undetected'],
                "reputation": attrs.get('reputation', 0),
                "tags": attrs.get('tags', []),
                "names": attrs.get('names', [])[:5],  # Solo los primeros 5 nombres
            }
    
        elif response.status_code == 404:
            return {"found": False, "hash": file_hash, "msg": "No encontrado en VirusTotal."}
        else:
            return {"error": f"Error en la consulta a VirusTotal: {response.status_code}"}
    
    except Exception as e:
        return {"error": f"Error al conectar con VirusTotal: {str(e)}"}


# ==========================
# Para el módulo de Phising
# ==========================

def extract_url_from_text(text):

    """
    Extrae la primera URL encontrada en un texto.
    Soporta:
    - Protocolos: http://, https://
    - Subdominios comunes: www.
    - Dominios: ejemplo.com, sitio.org
    """

    url_pattern = r"\b((?:https?://|www\.|[a-zA-Z0-9-]+\.[a-z]{2,})\S+)\b"
    
    match = re.search(url_pattern, text, re.IGNORECASE)
    
    if match:
        url = match.group(0)
        
        # FILTRO ANTI-FALSOS POSITIVOS
        # Evita que detecte nombres de archivos comunes como URLs (ej: reporte.pdf)
        # Si termina en una extensión de archivo típica y no tiene http/www, lo ignoramos.
        excluded_extensions = ('.pdf', '.jpg', '.png', '.exe', '.docx', '.txt')
        if url.lower().endswith(excluded_extensions) and not url.startswith(('http', 'www')):
            return None

        # NORMALIZACIÓN
        # Si detectamos "google.com" o "www.google.com", le añadimos "http://"
        # VirusTotal necesita el protocolo para procesarlo correctamente.
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        return url.strip()
        
    return None


def check_url_virustotal(url_to_scan):
    """
    Consulta la reputación de una URL en VirusTotal.
    """
    
    try:
        # 1. Preparar el ID de la URL codificada en base64 sin padding (requisito de VT)
        # Codificamos la URL y quitamos los '=' del final
        url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip('=')

        headers = {
            "accept": "application/json",
            "x-apikey": VT_KEY
        }

        # 2. Consultar el reporte (Endpoint: /urls/{id})
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(endpoint, headers=headers)

        if response.status_code == 200:
            data = response.json()
            attributes = data['data']['attributes']
            stats = attributes['last_analysis_stats']
            
            # Devolvemos un resumen estructurado
            return {
                "url": url_to_scan,
                "malicious": stats['malicious'],
                "suspicious": stats['suspicious'],
                "harmless": stats['harmless'],
                "undetected": stats['undetected'],
                "total_engines": sum(stats.values()),
                "title": attributes.get('title', 'Sin título'),
                "reputation": attributes.get('reputation', 0),
                "categories": attributes.get('categories', {})
            }
        
        elif response.status_code == 404:
            return {"error": f"VirusTotal no tiene información previa sobre la URL ({url_to_scan})."}
        else:
            return {"error": f"Error al conectar con VirusTotal (Código: {response.status_code})"}

    except Exception as e:
        return {"error": f"Error interno analizando URL: {str(e)}"}
    

# =============================
# Para el boletín de seguridad
# =============================

def get_new_critical_cves():
    
    #Consulta la API de NVD para obtener las vulnerabilidades críticas (CVSS >= 9.0) publicadas en las últimas 24 horas.
    
    try:
        # 1. Calcular rango de fechas (últimas 24 horas)
        now = datetime.now(timezone.utc)
        yesterday = now - timedelta(days=1)

        # Formato NIST: YYYY-MM-DDTHH:MM:SS.SSS
        pub_start_date = yesterday.strftime('%Y-%m-%dT%H:%M:%S.000')
        pub_end_date = now.strftime('%Y-%m-%dT%H:%M:%S.000')

        # Filtramos por severidad CRÍTICA (CVSS >= 9.0) y por fecha de publicación
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?pubStartDate={pub_start_date}"
            f"&pubEndDate={pub_end_date}"
            f"&cvssV3Severity=CRITICAL"
        )

        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return None

        data = response.json()

        if data.get('totalResults', 0) == 0:
            return None

        cve_list = []
        for item in data.get('vulnerabilities', []):
            cve = item['cve']
            cve_id = cve['id']

            # 2. FILTRO CLIENT-SIDE: descartar CVEs sin CVSSv3
            # La API devuelve CVEs con solo CVSSv2 aunque se pida cvssV3Severity=CRITICAL
            metrics = cve.get('metrics', {})
            cvss_v3_data = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))

            # Descartamos CVEs sin CVSSv3
            if not cvss_v3_data:
                print(f"   ⚠️ {cve_id} descartado: sin puntuación CVSSv3.")
                continue
            
            # Descartamos CVEs con CVSSv3 < 9.0 (No críticos)
            base_score = cvss_v3_data[0]['cvssData']['baseScore']
            if base_score < 9.0:
                print(f"   ⚠️ {cve_id} descartado: CVSS {base_score} < 9.0.")
                continue
            
            # Descartar CVEs con identificador anterior a 2024
            # Son CVEs indexados o modificados recientemente que caen en la ventana de las 24 horas
            cve_year = int(cve_id.split('-')[1])
            if cve_year < datetime.now().year - 1:
                print(f"   ⚠️ {cve_id} descartado: CVE del año {cve_year}.")
                continue
            
            # 3. Extraer descripción en inglés
            desc = "Sin descripción disponible"
            for d in cve.get('descriptions', []):
                if d['lang'] == 'en':
                    desc = d['value']
                    break
            
            cve_list.append(
                f"ID: {cve_id} | CVSS: {base_score} | Descripcion: {desc[:150]}..."
            )

        # Si tras el filtrado no queda ningún CVE realmente crítico
        if not cve_list:
            return None

        return "\n".join(cve_list)
    
    except Exception as e:
        print(f"⚠️ Error al consultar NVD: {str(e)}")
        return None

# ==============================
# Para el módulo de reportes PDF
# ==============================

def sanitize_text_for_pdf(text):
    
    # Limpia el texto de emojis y caracteres no soportados por FPDF.

    # Mapeo básico de caracteres problemáticos
    replacements = {
        "“": '"', "”": '"', "‘": "'", "’": "'", "–": "-", "—": "-",
        "⚠️": "[ALERTA]", "⛔": "[PELIGRO]", "✅": "[OK]", "ℹ️": "[INFO]", 
        "🛡️": "[SEGURIDAD]", "🔍": "[ANALISIS]"
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)

    # Intentamos codificar a latin-1, reemplazando los caracteres unicode residuales por '?'
    return text.encode('latin-1', 'replace').decode('latin-1')


class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Informe de Seguridad - SecMate', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Página {self.page_no()}', 0, 0, 'C')


def generate_pdf_report(content_dict, filename="reporte_seguridad.pdf"):
    
    # Genera un PDF profesional con los datos del análisis.
    
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # 1. Título del Reporte
    pdf.set_font("Arial", "B", 16)
    pdf.set_text_color(200, 0, 0) # Rojo oscuro para el título
    title = sanitize_text_for_pdf(f"REPORTE: {content_dict.get('amenaza', 'Amenaza Desconocida')}")
    pdf.multi_cell(0, 10, title, align='L')
    pdf.ln(5)

    # 2. Fecha y Hora
    pdf.set_font("Arial", "I", 10)
    pdf.set_text_color(0, 0, 0)
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    pdf.cell(0, 10, f"Fecha de generacion: {timestamp}", 0, 1)
    pdf.ln(5)

    # 3. Cuerpo del Informe (Detalles Técnicos)
    pdf.set_font("Arial", "B", 12)
    pdf.set_fill_color(230, 230, 230) # Gris claro
    pdf.cell(0, 10, "1. ANALISIS TECNICO", 0, 1, 'L', fill=True)
    pdf.ln(2)
    
    pdf.set_font("Arial", "", 11)
    detalles = sanitize_text_for_pdf(content_dict.get('detalles', 'Sin detalles.'))
    pdf.multi_cell(0, 8, detalles)
    pdf.ln(5)

    # 4. Recomendaciones
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "2. CONCLUSIONES Y RECOMENDACIONES", 0, 1, 'L', fill=True)
    pdf.ln(2)
    
    pdf.set_font("Arial", "", 11)
    raw_recos = content_dict.get('recomendaciones', 'Sin recomendaciones.')
    
    # TRUCO VISUAL: Forzamos salto de línea antes de cada guion
    # Reemplazamos "- " por "\n- " (Salto + Guion)
    formatted_recos = raw_recos.replace("- ", "\n- ").strip()
    
    # Si al principio nos ha quedado un salto extra, lo quitamos
    if formatted_recos.startswith("\n"):
        formatted_recos = formatted_recos[1:]

    recos = sanitize_text_for_pdf(formatted_recos)
    pdf.multi_cell(0, 8, recos)
    
    # Guardar
    output_path = f"temp_{filename}"
    pdf.output(output_path)
    return output_path