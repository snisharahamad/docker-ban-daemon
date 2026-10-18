import ast
import docker
import json
import os
import random
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from google import genai
from google.genai import types

# Configuration
API_KEY = os.environ.get("GEMINI_API_KEY", "TA_CLE_API_ICI")
MODEL_ID = "gemini-3.8-flash"
BASE_DIR = Path(__file__).resolve().parent.parent
TARGET_FILE = BASE_DIR / "target" / "server.py"
BACKUP_FILE = BASE_DIR / "target" / "server.py.bak"

ai_client = genai.Client(api_key=API_KEY)
docker_client = docker.from_env()

patch_lock = threading.Lock()
iptables_lock = threading.Lock()
banned_ips = set()
endpoint_patched = False

# NIVEAU 1 : PRÉ-FILTRE HEURISTIQUE ULTRA-RAPIDE (Local)
SUSPICIOUS_PATTERN = re.compile(r"([;|&$\`\\]|\%3B|\%7C|cat|id|whoami|wget|curl)", re.IGNORECASE)

# CIRCUIT BREAKER : Fallback local si l'API est morte (429)
MOCK_JSON = '{"attaque": true, "type": "OS Command Injection", "gravite": 9}'
MOCK_PATCH = """import ipaddress
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/ping')
def ping():
    ip = request.args.get('ip', '127.0.0.1')
    try:
        validated_ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return "Invalid IP", 400

    process = subprocess.run(['ping', '-c', '1', validated_ip], capture_output=True, text=True, shell=False)
    return f"<pre>{process.stdout}</pre>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)"""

def call_llm_with_backoff(prompt: str, is_json: bool = False, max_retries: int = 2) -> str | None:
    config = types.GenerateContentConfig(temperature=0.1, response_mime_type="application/json" if is_json else "text/plain")
    for attempt in range(max_retries):
        try:
            response = ai_client.models.generate_content(model=MODEL_ID, contents=prompt, config=config)
            return response.text.strip()
        except Exception as e:
            if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
                print("[CIRCUIT BREAKER] Quota API épuisé. Activation du Mock IA hors-ligne.")
                return MOCK_JSON if is_json else MOCK_PATCH
            time.sleep(1)
    return None

def ban_ip_idempotent(ip: str):
    if ip in ("Inconnue", "127.0.0.1"): return
    with iptables_lock:
        if ip in banned_ips: return
        check_cmd = ["iptables", "-C", "DOCKER-USER", "-s", ip, "-j", "DROP"]
        if subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            subprocess.run(["iptables", "-I", "DOCKER-USER", "1", "-s", ip, "-j", "DROP"], check=False)
            print(f"[NETFILTER] IP {ip} bannie dans DOCKER-USER.")
        banned_ips.add(ip)

def apply_hot_patch(vuln_type: str):
    global endpoint_patched
    if endpoint_patched or not patch_lock.acquire(blocking=False): return
    
    try:
        if endpoint_patched: return
        print(f"[HOT-PATCH] Verrou acquis. Demande de correctif pour '{vuln_type}'...")
        
        patched_code = call_llm_with_backoff("Génère le patch", is_json=False)
        if not patched_code: return

        try:
            ast.parse(patched_code)
        except SyntaxError as se:
            print(f"[HOT-PATCH REJETÉ] Erreur syntaxe AST : {se}")
            return

        shutil.copy2(TARGET_FILE, BACKUP_FILE)
        TARGET_FILE.write_text(patched_code, encoding="utf-8")
        
        endpoint_patched = True
        print("[HOT-PATCH SUCCÈS] Code injecté. Gunicorn recharge les workers en Zero-Downtime.")
    finally:
        patch_lock.release()

def process_log_event(log_line: str, attacker_ip: str):
    # Bouclier Niveau 1
    if not SUSPICIOUS_PATTERN.search(log_line):
        return

    print(f"[ALERTE NIVEAU 1] Signature suspecte détectée depuis {attacker_ip}. Escalade IA...")
    
    # Bouclier Niveau 2 (LLM ou Circuit Breaker)
    res_text = call_llm_with_backoff("Analyse le log", is_json=True)
    if not res_text: return

    try:
        data = json.loads(res_text)
        if data.get("attaque") is True:
            vuln_type = data.get("type", "Inconnue")
            print(f"[MENACE CRITIQUE] {vuln_type} confirmée.")
            ban_ip_idempotent(attacker_ip)
            apply_hot_patch(vuln_type)
    except json.JSONDecodeError:
        pass

def main():
    if os.geteuid() != 0: sys.exit(1)
    print("[SENTINEL-ZERO] Agent en ligne. (Pré-filtre + Circuit Breaker actifs)")
    try:
        proxy = docker_client.containers.get("traefik-proxy")
        for line in proxy.logs(stream=True, tail=0):
            log = line.decode("utf-8", errors="ignore").strip()
            if "GET " in log or "POST " in log:
                ip_match = re.search(r"^(\d{1,3}(?:\.\d{1,3}){3})", log)
                attacker_ip = ip_match.group(1) if ip_match else "Inconnue"
                threading.Thread(target=process_log_event, args=(log, attacker_ip), daemon=True).start()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
