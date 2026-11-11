import time
import re
import httpx
import sqlite3
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import os

app = FastAPI(title="Cloudflare Mini - SaaS WAF")

# --- 1. SETUP DATABASE SQLITE ---
DB_FILE = "waf_database.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            domain TEXT PRIMARY KEY,
            origin_server TEXT NOT NULL,
            waf_enabled BOOLEAN NOT NULL,
            rate_limit INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db() # Jalankan pembuatan tabel saat aplikasi dimulai

# Setup Template HTML
# Pastikan folder 'templates' ada di direktori yang sama dengan main.py
templates = Jinja2Templates(directory="templates")

# --- 2. SKEMA DATA API ---
class ClientConfig(BaseModel):
    domain: str
    origin_server: str
    waf_enabled: bool = True
    rate_limit: int = 10

# --- 3. ENDPOINT DASHBOARD ADMIN ---
# Endpoint untuk menampilkan halaman HTML
@app.get("/admin/dashboard", response_class=HTMLResponse)
async def dashboard_ui(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

# Endpoint untuk membaca daftar klien dari Database
@app.get("/admin/api/domains")
def get_all_domains():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT domain, origin_server, waf_enabled, rate_limit FROM clients")
    rows = cursor.fetchall()
    conn.close()
    
    result = []
    for row in rows:
        result.append({
            "domain": row[0],
            "origin_server": row[1],
            "waf_enabled": bool(row[2]),
            "rate_limit": row[3]
        })
    return result

# Endpoint untuk menyimpan klien baru ke Database
@app.post("/admin/api/domains")
def add_domain(config: ClientConfig):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT OR REPLACE INTO clients (domain, origin_server, waf_enabled, rate_limit) VALUES (?, ?, ?, ?)",
            (config.domain, config.origin_server, config.waf_enabled, config.rate_limit)
        )
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))
    conn.close()
    return {"message": "Domain berhasil disimpan"}


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

# Fungsi bantu mengambil data klien dari DB saat ada request masuk
def get_client_config(domain: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT origin_server, waf_enabled, rate_limit FROM clients WHERE domain=?", (domain,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"origin_server": row[0], "waf_enabled": bool(row[1]), "rate_limit": row[2]}
    return None

# --- 5. MIDDLEWARE PROXY DINAMIS ---
# Menangkap semua request KECUALI yang mengarah ke /admin/...
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def reverse_proxy(request: Request, path: str):
    url_path = str(request.url.path)
    
    # Jangan proxy-kan halaman admin (biarkan diakses langsung)
    if url_path.startswith("/admin/"):
        return JSONResponse(status_code=404, content={"error": "Not Found"})

    client_ip = request.client.host
    host_header = request.headers.get("host", "").split(":")[0]
    
    # 1. Cari target server di database SQLite
    client_config = get_client_config(host_header)
    
    if not client_config:
        return JSONResponse(
            status_code=404, 
            content={"error": f"Domain '{host_header}' tidak terdaftar di Cloudflare Mini."}
        )

    # 2. Proses Keamanan
    if client_ip in PERMANENT_BANNED_IPS:
        return JSONResponse(status_code=403, content={"status": "blocked", "reason": "IP permanently banned"})

    if client_config["waf_enabled"] and is_malicious(str(request.url)):
        PERMANENT_BANNED_IPS.add(client_ip)
        return JSONResponse(status_code=403, content={"status": "blocked", "reason": "Malicious payload detected"})

    current_time = time.time()
    if client_ip not in REQUEST_LOGS:
        REQUEST_LOGS[client_ip] = []
    REQUEST_LOGS[client_ip] = [t for t in REQUEST_LOGS[client_ip] if current_time - t < TIME_WINDOW]
    
    if len(REQUEST_LOGS[client_ip]) >= client_config["rate_limit"]:
        PERMANENT_BANNED_IPS.add(client_ip)
        return JSONResponse(status_code=429, content={"status": "blocked", "reason": "Too many requests"})

    REQUEST_LOGS[client_ip].append(current_time)

    # 3. Teruskan (Proxy) ke Origin Server
    target_server = client_config["origin_server"]
    
    async with httpx.AsyncClient(base_url=target_server) as client:
        url = httpx.URL(path=request.url.path, query=request.url.query.encode("utf-8"))
        body = await request.body()
        
        proxy_req = client.build_request(
            request.method,
            url,
            headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
            content=body
        )
        
        try:
            proxy_resp = await client.send(proxy_req, stream=True)
            return Response(
                content=await proxy_resp.aread(),
                status_code=proxy_resp.status_code,
                headers=dict(proxy_resp.headers)
            )
        except httpx.RequestError:
            return JSONResponse(status_code=502, content={"error": "Bad Gateway. Origin server down."})