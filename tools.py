import os
import re
import hashlib
import requests
import base64
from dotenv import load_dotenv

load_dotenv('.env')
VT_KEY = os.getenv('VT_API_KEY')

if not VT_KEY:
    print(f"⚠️ Error: Falta la API Key de VirusTotal.")
    exit()

# Para el módulo de VirusTotal
def get_file_hash(file_path):
    """Calcula el hash SHA-256 de un archivo local."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None
    
def extract_hash_from_text(text):
    """Busca cadenas de caracteres que parezcan un hash (MD5, SHA1, SHA256) en un texto."""
    # Buscamos cadenas de 32, 40 o 64 caracteres hexadecimales
    match = re.search(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', text)
    if match:
        return match.group(0)
    return None

def check_hash_vt(file_hash):
    """Consulta a VirusTotal y devuelve un diccionario con los datos crudos."""
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

# Para el módulo de Phising
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
        enpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(enpoint, headers=headers)

        if response.status_code == 200:
            data = response.json()
            attributes = data['data']['attributes']
            stats = attributes['last_analysis_stats']
            
            malicious = stats['malicious']
            suspicious = stats['suspicious']
            total_engines = sum(stats.values())
            
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
            return f"ℹ️ VirusTotal no tiene información previa sobre esta URL ({url_to_scan}). Podría ser nueva o muy específica."
        
        else:
            return f"⚠️ Error al conectar con VirusTotal (Código: {response.status_code})"

    except Exception as e:
        return f"⚠️ Error interno analizando URL: {str(e)}"
    

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
        excluded_extensions = ('.pdf', '.jpg', '.png', '.exe', '.docx', '.txt', '.py')
        if url.lower().endswith(excluded_extensions) and not url.startswith(('http', 'www')):
            return None

        # NORMALIZACIÓN
        # Si detectamos "google.com" o "www.google.com", le añadimos "http://"
        # VirusTotal necesita el protocolo para procesarlo correctamente.
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        return url.strip()
        
    return None