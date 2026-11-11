import time
import re
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

app = FastAPI(title="Cloudflare Mini - Standalone WAF")

# --- KONFIGURASI ---
TARGET_SERVER = "https://example.com"  # Ganti dengan domain/IP server asli

RATE_LIMIT = 5      # Batas request
TIME_WINDOW = 10    # Dalam rentang detik

REQUEST_LOGS = {}
PERMANENT_BANNED_IPS = set()

WAF_PATTERNS = [
    r"(\%27)|(\')", r"((\%3D)|(=))[^\n]*(\%27|\')", r"\w*((\%27)|(\'))((-)|(OR|or)|(UNION|union))", # Pola SQLi
    r"<script[^>]*>[\s\S]*?</script>", r"javascript:", r"onerror\s*=" # Pola XSS
]

def is_malicious(text: str) -> bool:
    for pattern in WAF_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False

# --- MIDDLEWARE KEAMANAN ---
@app.middleware("http")
async def security_gateway(request: Request, call_next):
    client_ip = request.client.host
    current_time = time.time()
    url_path = str(request.url)

    # 1. Cek Blokir
    if client_ip in PERMANENT_BANNED_IPS:
        return JSONResponse(status_code=403, content={"status": "blocked", "reason": "IP permanently banned"})

    # 2. Cek WAF (SQLi / XSS)
    if is_malicious(url_path):
        PERMANENT_BANNED_IPS.add(client_ip)
        print(f"[WAF] Serangan dicegah dari {client_ip} pada URL: {url_path}")
        return JSONResponse(status_code=403, content={"status": "blocked", "reason": "Malicious payload detected"})

    # 3. Cek Rate Limit
    if client_ip not in REQUEST_LOGS:
        REQUEST_LOGS[client_ip] = []
    
    REQUEST_LOGS[client_ip] = [t for t in REQUEST_LOGS[client_ip] if current_time - t < TIME_WINDOW]
    
    if len(REQUEST_LOGS[client_ip]) >= RATE_LIMIT:
        PERMANENT_BANNED_IPS.add(client_ip)
        print(f"[RATE LIMIT] IP {client_ip} diblokir karena flooding.")
        return JSONResponse(status_code=429, content={"status": "blocked", "reason": "Too many requests"})

    REQUEST_LOGS[client_ip].append(current_time)
    
    return await call_next(request)

# --- REVERSE PROXY ENGINE ---
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def reverse_proxy(request: Request, path: str):
    async with httpx.AsyncClient(base_url=TARGET_SERVER) as client:
        url = httpx.URL(path=request.url.path, query=request.url.query.encode("utf-8"))
        body = await request.body()
        
        proxy_req = client.build_request(
            request.method,
            url,
            headers={k: v for k, v in request.headers.items() if k.lower() != "host"}, # Hindari konflik host
            content=body
        )
        
        try:
            proxy_resp = await client.send(proxy_req, stream=True)
            return Response(
                content=await proxy_resp.aread(),
                status_code=proxy_resp.status_code,
                headers=dict(proxy_resp.headers)
            )
        except httpx.RequestError as e:
            print(f"[PROXY ERROR] Gagal menghubungi target: {e}")
            return JSONResponse(status_code=502, content={"error": "Bad Gateway"})