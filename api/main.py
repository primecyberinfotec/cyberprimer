"""
Cyber Primer Infortech — API do Scanner Demo
Deploy no Render.com (free tier)

Rota principal:
  GET /demo?domain=seusite.com.br
  → Roda os módulos rápidos (sem port scan, sem brute-force)
  → Retorna JSON com score, flags e dados básicos

Tempo de resposta esperado: 8–20 segundos
"""

import time
import sys
import os
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Adiciona o diretório pai ao path para importar os módulos do scanner
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.ip_info    import get_ip_info
from modules.ssl_checker import check_ssl
from modules.dns_enum   import enumerate_dns
from modules.web_info   import get_web_info
from modules.osint      import run_osint


app = FastAPI(
    title="Cyber Primer — Scanner API",
    description="API pública de demonstração. Scan passivo baseado em dados públicos.",
    version="1.0.0",
)

# ── CORS — permite chamadas do GitHub Pages ─────────────────────────────────
# Troque pela URL exata do seu GitHub Pages
ALLOWED_ORIGINS = [
    "https://primecyberinfotec.github.io",   # GitHub Pages
    "https://seudominiocustom.com.br",        # Se tiver domínio próprio
    "http://localhost:5500",                   # Live Server local (desenvolvimento)
    "http://127.0.0.1:5500",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET"],
    allow_headers=["*"],
)

# ── RATE LIMITING simples em memória ────────────────────────────────────────
from collections import defaultdict
_last_scan: dict = defaultdict(float)
RATE_LIMIT_SECONDS = 60   # 1 scan por IP a cada 60 segundos


def check_rate_limit(client_ip: str):
    now = time.time()
    last = _last_scan.get(client_ip, 0)
    if now - last < RATE_LIMIT_SECONDS:
        wait = int(RATE_LIMIT_SECONDS - (now - last))
        raise HTTPException(
            status_code=429,
            detail=f"Aguarde {wait}s antes de fazer outro scan."
        )
    _last_scan[client_ip] = now


# ── VALIDAÇÃO DE DOMÍNIO ────────────────────────────────────────────────────
import re
DOMAIN_RE = re.compile(
    r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$'
)

def validate_domain(domain: str) -> str:
    d = domain.strip().lower()
    d = re.sub(r'^https?://', '', d)
    d = re.sub(r'^www\.', '', d)
    d = d.split('/')[0].split('?')[0]
    if not DOMAIN_RE.match(d):
        raise HTTPException(status_code=400, detail=f"Domínio inválido: {domain}")
    # Bloqueia scan do próprio servidor (loopback, etc.)
    if d in ('localhost', '127.0.0.1', '0.0.0.0'):
        raise HTTPException(status_code=400, detail="Domínio não permitido.")
    return d


# ── SCORE (mesmo algoritmo do report_preview.py) ────────────────────────────
def calc_score(dns_mod, ssl_mod, web_mod, osint_mod):
    cert        = ssl_mod.get("certificate", {})
    sec_headers = web_mod.get("security_headers", {})
    headers_pct = sec_headers.get("percentage", 0)
    spf_ok      = dns_mod.get("spf",   {}).get("exists", False)
    dmarc_ok    = dns_mod.get("dmarc", {}).get("exists", False)
    breach_cnt  = osint_mod.get("hibp", {}).get("count", 0)
    vt_malicious= osint_mod.get("virustotal", {}).get("malicious", 0)

    # Penalidades
    p_spf    = -8  if not spf_ok                    else 0
    p_dmarc  = -8  if not dmarc_ok                  else 0
    p_hdrs   = (-10 if headers_pct < 50 else -6 if headers_pct < 70 else -3 if headers_pct < 80 else 0)
    p_ssl    = (-20 if cert.get("expired")
                else -10 if cert.get("expiring_soon") else 0)
    p_breach = -min(breach_cnt * 10, 20)
    p_vt     = -10 if vt_malicious > 0              else 0

    total_penalty = abs(p_spf + p_dmarc + p_hdrs + p_ssl + p_breach + p_vt)
    score         = max(0, min(100, 100 - total_penalty))

    breakdown = {
        "spf":    p_spf,
        "dmarc":  p_dmarc,
        "headers": p_hdrs,
        "ssl":    p_ssl,
        "breach": p_breach,
        "vt":     p_vt,
        "cve":    0,    # Demo não roda port scan completo nem NVD
    }
    return score, breakdown


# ── ROTA PRINCIPAL ───────────────────────────────────────────────────────────
@app.get("/demo")
async def scan_demo(
    domain:   str = Query(..., description="Domínio a analisar, ex: seusite.com.br"),
    request_ip: str | None = None,
):
    """
    Roda o scan demo (módulos rápidos):
      - ip_info  (IP, geo, CDN, Shodan InternetDB)
      - ssl      (certificado, TLS)
      - dns_enum (SPF, DMARC — sem brute-force de subdomínios)
      - web_info (cabeçalhos HTTP)
      - osint    (HIBP, Google Safe Browsing)

    NÃO executa port scan nem consulta NVD (muito lentos para demo online).
    """
    domain = validate_domain(domain)
    t0     = time.time()

    # ── Roda os módulos em sequência ─────────────────────────────────────────
    try:
        ip_mod    = get_ip_info(domain)
    except Exception:
        ip_mod    = {}

    try:
        ssl_mod   = check_ssl(domain)
    except Exception:
        ssl_mod   = {"certificate": {}, "risks": [], "risk_flags": []}

    try:
        dns_mod   = enumerate_dns(domain)
    except Exception:
        dns_mod   = {"spf": {"exists": False}, "dmarc": {"exists": False}, "subdomains": []}

    try:
        web_mod   = get_web_info(domain)
    except Exception:
        web_mod   = {"technologies": [], "security_headers": {"percentage": 0}}

    try:
        osint_mod = run_osint(domain)
    except Exception:
        osint_mod = {"hibp": {"count": 0, "breaches": []}, "virustotal": {}}

    # ── Score ─────────────────────────────────────────────────────────────────
    score, breakdown = calc_score(dns_mod, ssl_mod, web_mod, osint_mod)

    # ── Consolida risk_flags ──────────────────────────────────────────────────
    all_flags = []
    for mod in [ip_mod, dns_mod, ssl_mod, web_mod, osint_mod]:
        if isinstance(mod, dict):
            all_flags.extend(mod.get("risk_flags", []))

    # ── Monta resposta (apenas dados seguros para exposição pública) ──────────
    cert        = ssl_mod.get("certificate", {})
    geo         = ip_mod.get("geolocation", {})
    cdn_info    = ip_mod.get("cdn_info", {})
    sec_headers = web_mod.get("security_headers", {})
    ips         = ip_mod.get("ips", [])

    return {
        "domain":          domain,
        "elapsed_seconds": round(time.time() - t0, 2),

        # Score
        "score":          score,
        "score_breakdown": breakdown,

        # IP
        "primary_ip":     ips[0] if ips else None,
        "location":       f"{geo.get('city','')}, {geo.get('country','')}".strip(', '),
        "cdn_detected":   cdn_info.get("is_cdn", False),
        "cdn_name":       cdn_info.get("cdn_name"),

        # SSL
        "ssl_valid":      cert.get("valid", False),
        "ssl_days_left":  cert.get("days_left"),
        "ssl_expired":    cert.get("expired", False),
        "tls_version":    cert.get("tls_version"),
        "ssl_issuer":     cert.get("issuer_org"),

        # Email
        "spf_ok":         dns_mod.get("spf",  {}).get("exists", False),
        "dmarc_ok":       dns_mod.get("dmarc",{}).get("exists", False),
        "spf_record":     dns_mod.get("spf",  {}).get("record"),
        "dmarc_record":   dns_mod.get("dmarc",{}).get("record"),

        # Headers
        "headers_pct":    sec_headers.get("percentage", 0),
        "headers_score":  sec_headers.get("score", 0),
        "headers_max":    sec_headers.get("max_score", 7),

        # OSINT
        "breach_count":   osint_mod.get("hibp", {}).get("count", 0),
        "vt_malicious":   osint_mod.get("virustotal", {}).get("malicious", 0),
        "safe_browsing":  osint_mod.get("google_safebrow", {}).get("safe"),

        # Subdomínios (só count na demo, não a lista)
        "subdomain_count": dns_mod.get("subdomain_count", 0),

        # Flags (limitadas a 8 na demo)
        "risk_flags":      all_flags[:8],
        "total_flags":     len(all_flags),
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "Cyber Primer Scanner API"}
