import time
import re
import httpx
import sqlite3
import socket
from datetime import datetime
from fastapi import FastAPI, Request, Response, HTTPException, Header
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="Cloudflare Mini - WAF Enterprise")

DB_FILE = "waf_database.db"

# --- 1. SETUP DATABASE BARU ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS clients (domain TEXT PRIMARY KEY, origin_server TEXT NOT NULL, waf_enabled BOOLEAN NOT NULL, rate_limit INTEGER NOT NULL, status TEXT NOT NULL, owner TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL, role TEXT NOT NULL)''')
    cursor.execute("INSERT OR IGNORE INTO users VALUES ('admin', 'admin123', 'admin')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES ('user', 'user123', 'user')")
    cursor.execute('''CREATE TABLE IF NOT EXISTS attack_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, ip_address TEXT, domain TEXT, threat_type TEXT)''')
    conn.commit()
    conn.close()

init_db()
templates = Jinja2Templates(directory="templates")

class ClientConfig(BaseModel):
    domain: str
    origin_server: Optional[str] = "" # Dibuat opsional agar bisa diisi otomatis jika kosong
    waf_enabled: bool = True
    rate_limit: int = 20

class AuthData(BaseModel):
    username: str
    password: str

@app.get("/admin/dashboard", response_class=HTMLResponse)
async def dashboard_ui(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {})

# --- ENDPOINT AUTENTIKASI ---
@app.post("/api/login")
def login(data: AuthData):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username=? AND password=?", (data.username, data.password))
    user = cursor.fetchone()
    conn.close()
    if user: return {"status": "success", "role": user[0], "username": data.username}
    raise HTTPException(status_code=401, detail="Username atau password salah")

@app.post("/api/register")
def register(data: AuthData):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username=?", (data.username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Username sudah dipakai")
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (data.username, data.password, 'user'))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Akun berhasil dibuat"}

# --- ENDPOINT API MANAJEMEN DOMAIN ---
@app.get("/admin/api/domains")
def get_all_domains(x_role: str = Header(...), x_username: str = Header(...)):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    if x_role == 'admin':
        cursor.execute("SELECT domain, origin_server, waf_enabled, rate_limit, status, owner FROM clients")
    else:
        cursor.execute("SELECT domain, origin_server, waf_enabled, rate_limit, status, owner FROM clients WHERE owner=?", (x_username,))
    rows = cursor.fetchall()
    conn.close()
    return [{"domain": r[0], "origin_server": r[1], "waf_enabled": bool(r[2]), "rate_limit": r[3], "status": r[4], "owner": r[5]} for r in rows]

@app.post("/admin/api/domains")
def add_domain(config: ClientConfig, x_role: str = Header(...), x_username: str = Header(...)):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # --- OTOMATISASI PENCARIAN IP (AUTO-DISCOVERY) ---
    origin = config.origin_server
    if not origin or origin.strip() == "":
        try:
            # Mengubah nama domain menjadi alamat IP asli via DNS Lookup
            ip_address = socket.gethostbyname(config.domain)
            origin = f"http://{ip_address}"
        except socket.gaierror:
            origin = "http://127.0.0.1" # Fallback jika domain tidak ditemukan
    
    status = 'approved' if x_role == 'admin' else 'pending'
    waf_status = config.waf_enabled if x_role == 'admin' else False
    
    cursor.execute("INSERT OR REPLACE INTO clients VALUES (?, ?, ?, ?, ?, ?)", 
                   (config.domain, origin, waf_status, config.rate_limit, status, x_username))
    conn.commit()
    conn.close()
    return {"message": "Pengajuan berhasil"}

# Endpoint Khusus Admin untuk ACC Domain
@app.put("/admin/api/domains/{target_domain}/approve")
def approve_domain(target_domain: str, x_role: str = Header(...)):
    if x_role != 'admin': raise HTTPException(status_code=403, detail="Akses ditolak")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE clients SET status='approved', waf_enabled=1 WHERE domain=?", (target_domain,))
    conn.commit()
    conn.close()
    return {"message": "Domain disetujui"}

@app.delete("/admin/api/domains/{target_domain}")
def delete_domain(target_domain: str, x_role: str = Header(...), x_username: str = Header(...)):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    if x_role == 'admin': cursor.execute("DELETE FROM clients WHERE domain=?", (target_domain,))
    else: cursor.execute("DELETE FROM clients WHERE domain=? AND owner=?", (target_domain, x_username))
    conn.commit()
    conn.close()
    return {"message": "Domain dihapus"}

@app.get("/admin/api/logs")
def get_attack_logs():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, ip_address, domain, threat_type FROM attack_logs ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    return [{"timestamp": r[0], "ip_address": r[1], "domain": r[2], "threat_type": r[3]} for r in rows]

# --- ENGINE KEAMANAN (WAF & RATE LIMIT) ---
TIME_WINDOW = 10 
REQUEST_LOGS = {}
PERMANENT_BANNED_IPS = set()
WAF_PATTERNS = [r"(\%27)|(\')", r"((\%3D)|(=))[^\n]*(\%27|\')", r"\w*((\%27)|(\'))((-)|(OR|or)|(UNION|union))", r"<script[^>]*>[\s\S]*?</script>", r"javascript:", r"onerror\s*="]

def is_malicious(text: str): return any(re.search(p, text, re.IGNORECASE) for p in WAF_PATTERNS)

def log_attack(ip: str, domain: str, threat: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO attack_logs (timestamp, ip_address, domain, threat_type) VALUES (?, ?, ?, ?)", (now, ip, domain, threat))
    conn.commit()
    conn.close()

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def reverse_proxy(request: Request, path: str):
    if str(request.url.path).startswith(("/admin/", "/api/")): return JSONResponse(status_code=404, content={"error": "Not Found"})
    client_ip = request.client.host
    host_header = request.headers.get("host", "").split(":")[0]
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT origin_server, waf_enabled, rate_limit, status FROM clients WHERE domain=?", (host_header,))
    row = cursor.fetchone()
    conn.close()
    
    if not row: return JSONResponse(status_code=404, content={"error": "Domain tidak terdaftar."})
    client_config = {"origin": row[0], "waf_enabled": bool(row[1]), "rate_limit": row[2], "status": row[3]}
    
    if client_config["status"] == "pending":
        return JSONResponse(status_code=403, content={"error": "Domain ini sedang menunggu persetujuan Admin."})

    if client_ip in PERMANENT_BANNED_IPS: return JSONResponse(status_code=403, content={"status": "blocked", "reason": "Banned"})
    if client_config["waf_enabled"] and is_malicious(str(request.url)):
        PERMANENT_BANNED_IPS.add(client_ip)
        log_attack(client_ip, host_header, "SQLi/XSS Injection")
        return JSONResponse(status_code=403, content={"status": "blocked", "reason": "Malicious payload detected"})

    current_time = time.time()
    REQUEST_LOGS.setdefault(client_ip, [])
    REQUEST_LOGS[client_ip] = [t for t in REQUEST_LOGS[client_ip] if current_time - t < TIME_WINDOW]
    if len(REQUEST_LOGS[client_ip]) >= client_config["rate_limit"]:
        log_attack(client_ip, host_header, "DDoS / Flood Rate Limit")
        return JSONResponse(status_code=429, content={"status": "blocked", "reason": "Too many requests"})

    REQUEST_LOGS[client_ip].append(current_time)
    async with httpx.AsyncClient(base_url=client_config["origin"]) as client:
        url = httpx.URL(path=request.url.path, query=request.url.query.encode("utf-8"))
        try:
            proxy_resp = await client.send(client.build_request(request.method, url, content=await request.body(), headers={k: v for k, v in request.headers.items() if k.lower() != "host"}), stream=True)
            
            custom_headers = dict(proxy_resp.headers)
            custom_headers["X-Protected-By"] = "Cloudflare Mini - WAF Enterprise"
            custom_headers["X-WAF-Status"] = "Active"
            
            return Response(content=await proxy_resp.aread(), status_code=proxy_resp.status_code, headers=custom_headers)
        except httpx.RequestError: return JSONResponse(status_code=502, content={"error": "Bad Gateway"})