import time
import re
import httpx
import sqlite3
from datetime import datetime
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

app = FastAPI(title="Cloudflare Mini - SaaS WAF")

DB_FILE = "waf_database.db"

# --- 1. SETUP DATABASE (DOMAIN, USER, LOG) ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Tabel Klien / Domain
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            domain TEXT PRIMARY KEY, origin_server TEXT NOT NULL,
            waf_enabled BOOLEAN NOT NULL, rate_limit INTEGER NOT NULL
        )
    ''')
    
    # Tabel Pengguna (Admin & User)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY, password TEXT NOT NULL, role TEXT NOT NULL
        )
    ''')
    
    # Masukkan akun default jika belum ada
    cursor.execute("INSERT OR IGNORE INTO users VALUES ('admin', 'admin123', 'admin')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES ('user', 'user123', 'user')")
    
    # Tabel Log Serangan
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
            ip_address TEXT, domain TEXT, threat_type TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()
templates = Jinja2Templates(directory="templates")

# --- 2. SKEMA DATA API ---
class ClientConfig(BaseModel):
    domain: str
    origin_server: str
    waf_enabled: bool = True
    rate_limit: int = 10

class LoginData(BaseModel):
    username: str
    password: str

# --- 3. ENDPOINT DASHBOARD & API MANAJEMEN ---

@app.get("/admin/dashboard", response_class=HTMLResponse)
async def dashboard_ui(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {})

# API Login (Simulasi Sederhana)
@app.post("/api/login")
def login(data: LoginData):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username=? AND password=?", (data.username, data.password))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {"status": "success", "role": user[0], "username": data.username}
    raise HTTPException(status_code=401, detail="Username atau password salah")

# API Baca Data Klien
@app.get("/admin/api/domains")
def get_all_domains():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT domain, origin_server, waf_enabled, rate_limit FROM clients")
    rows = cursor.fetchall()
    conn.close()
    return [{"domain": r[0], "origin_server": r[1], "waf_enabled": bool(r[2]), "rate_limit": r[3]} for r in rows]

# API Tambah Klien Baru
@app.post("/admin/api/domains")
def add_domain(config: ClientConfig):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO clients (domain, origin_server, waf_enabled, rate_limit) VALUES (?, ?, ?, ?)",
        (config.domain, config.origin_server, config.waf_enabled, config.rate_limit)
    )
    conn.commit()
    conn.close()
    return {"message": "Domain berhasil disimpan"}

# API Edit Klien
@app.put("/admin/api/domains/{target_domain}")
def update_domain(target_domain: str, config: ClientConfig):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT domain FROM clients WHERE domain=?", (target_domain,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Domain tidak ditemukan")
        
    cursor.execute(
        "UPDATE clients SET domain=?, origin_server=?, waf_enabled=?, rate_limit=? WHERE domain=?",
        (config.domain, config.origin_server, config.waf_enabled, config.rate_limit, target_domain)
    )
    conn.commit()
    conn.close()
    return {"message": "Domain berhasil diperbarui"}

# API Hapus Klien
@app.delete("/admin/api/domains/{target_domain}")
def delete_domain(target_domain: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM clients WHERE domain=?", (target_domain,))
    conn.commit()
    conn.close()
    return {"message": "Domain dihapus"}

# API Baca Log Serangan
@app.get("/admin/api/logs")
def get_attack_logs():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, ip_address, domain, threat_type FROM attack_logs ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    return [{"timestamp": r[0], "ip_address": r[1], "domain": r[2], "threat_type": r[3]} for r in rows]


# --- 4. ENGINE KEAMANAN (WAF & RATE LIMIT) ---
TIME_WINDOW = 10 
REQUEST_LOGS = {}
PERMANENT_BANNED_IPS = set()
WAF_PATTERNS = [
    r"(\%27)|(\')", r"((\%3D)|(=))[^\n]*(\%27|\')", r"\w*((\%27)|(\'))((-)|(OR|or)|(UNION|union))",
    r"<script[^>]*>[\s\S]*?</script>", r"javascript:", r"onerror\s*="
]

def is_malicious(text: str) -> bool:
    for pattern in WAF_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False

def log_attack(ip: str, domain: str, threat: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO attack_logs (timestamp, ip_address, domain, threat_type) VALUES (?, ?, ?, ?)", (now, ip, domain, threat))
    conn.commit()
    conn.close()

def get_client_config(domain: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT origin_server, waf_enabled, rate_limit FROM clients WHERE domain=?", (domain,))
    row = cursor.fetchone()
    conn.close()
    return {"origin_server": row[0], "waf_enabled": bool(row[1]), "rate_limit": row[2]} if row else None

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def reverse_proxy(request: Request, path: str):
    if str(request.url.path).startswith(("/admin/", "/api/")):
        return JSONResponse(status_code=404, content={"error": "Not Found"})

    client_ip = request.client.host
    host_header = request.headers.get("host", "").split(":")[0]
    client_config = get_client_config(host_header)
    
    if not client_config:
        return JSONResponse(status_code=404, content={"error": f"Domain '{host_header}' tidak terdaftar."})

    if client_ip in PERMANENT_BANNED_IPS:
        return JSONResponse(status_code=403, content={"status": "blocked", "reason": "Banned"})

    # Cek WAF
    if client_config["waf_enabled"] and is_malicious(str(request.url)):
        PERMANENT_BANNED_IPS.add(client_ip)
        log_attack(client_ip, host_header, "SQLi/XSS Injection")
        return JSONResponse(status_code=403, content={"status": "blocked", "reason": "Malicious payload detected"})

    # Cek Rate Limit
    current_time = time.time()
    REQUEST_LOGS.setdefault(client_ip, [])
    REQUEST_LOGS[client_ip] = [t for t in REQUEST_LOGS[client_ip] if current_time - t < TIME_WINDOW]
    
    if len(REQUEST_LOGS[client_ip]) >= client_config["rate_limit"]:
        log_attack(client_ip, host_header, "DDoS / Flood Rate Limit")
        return JSONResponse(status_code=429, content={"status": "blocked", "reason": "Too many requests"})

    REQUEST_LOGS[client_ip].append(current_time)

    # Proxy Request
    async with httpx.AsyncClient(base_url=client_config["origin_server"]) as client:
        url = httpx.URL(path=request.url.path, query=request.url.query.encode("utf-8"))
        body = await request.body()
        proxy_req = client.build_request(
            request.method, url, content=body,
            headers={k: v for k, v in request.headers.items() if k.lower() != "host"}
        )
        try:
            proxy_resp = await client.send(proxy_req, stream=True)
            return Response(content=await proxy_resp.aread(), status_code=proxy_resp.status_code, headers=dict(proxy_resp.headers))
        except httpx.RequestError:
            return JSONResponse(status_code=502, content={"error": "Bad Gateway"})