"""
Módulo: OSINT — Exposição Pública
APIs: HaveIBeenPwned (domínio), Shodan InternetDB, URLScan.io, VirusTotal free

CORREÇÕES:
  - Bug 2 (CRÍTICO): domain extraction usava parts[-2:] → "com.br" para qualquer
    domínio .com.br. HIBP verificava "com.br" em vez do domínio real,
    retornando "0 breaches" mesmo que o domínio real fosse afetado.
    Fix: usa _extract_base_domain() com suporte a TLDs compostos.

  - Bug 6 (importação frágil): mantida a correção anterior de fallback
    tri-nível para check_shodan_basic.
"""

import json
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional


# ── Extração de domínio base (compartilhada com dns_enum) ────────────────────
_BR_SLD = {
    "com", "net", "org", "edu", "gov", "mil", "adv", "agr", "arq",
    "art", "ato", "bio", "cng", "cnt", "coop", "ecn", "eco", "eng",
    "esp", "etc", "eti", "far", "fnd", "fot", "fst", "ind", "inf",
    "jor", "jus", "leg", "lel", "mat", "med", "mus", "not", "ntr",
    "odo", "pro", "psc", "rec", "srv", "trd", "tur", "tv", "vet",
}
_CC_SLD = {
    ("co", "uk"), ("org", "uk"), ("me", "uk"), ("net", "uk"),
    ("com", "au"), ("net", "au"), ("org", "au"), ("edu", "au"),
    ("co", "nz"), ("org", "nz"), ("co", "jp"), ("or", "jp"),
    ("com", "mx"), ("org", "mx"), ("com", "ar"), ("org", "ar"),
    ("com", "co"), ("org", "co"),
}


def _extract_base_domain(target: str) -> str:
    """FIX Bug 2: extração correta de domínio para TLDs compostos."""
    parts = target.split(".")
    n = len(parts)
    if n < 2:
        return target
    if n >= 3 and parts[-1] == "br" and parts[-2] in _BR_SLD:
        return ".".join(parts[-(min(n, 3)):])
    if n >= 3 and (parts[-2], parts[-1]) in _CC_SLD:
        return ".".join(parts[-(min(n, 3)):])
    return ".".join(parts[-2:])


# ── Importação robusta de check_shodan_basic ─────────────────────────────────
def _check_shodan_basic_inline(ip: str) -> dict:
    try:
        req = urllib.request.Request(
            f"https://internetdb.shodan.io/{ip}",
            headers={"User-Agent": "SecurityReport/1.0"}
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode())
        if data and "error" not in data:
            return {
                "open_ports": data.get("ports", []),
                "hostnames":  data.get("hostnames", []),
                "tags":       data.get("tags", []),
                "cves":       data.get("vulns", []),
            }
    except Exception:
        pass
    return {}

try:
    from .ip_info import check_shodan_basic as _check_shodan_basic
except ImportError:
    try:
        from modules.ip_info import check_shodan_basic as _check_shodan_basic
    except ImportError:
        _check_shodan_basic = _check_shodan_basic_inline
# ─────────────────────────────────────────────────────────────────────────────


def _get(url: str, timeout: int = 12, headers: dict = None) -> Optional[dict]:
    default_headers = {"User-Agent": "SecurityReport/1.0 (ethical scan)"}
    if headers:
        default_headers.update(headers)
    try:
        req = urllib.request.Request(url, headers=default_headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"not_found": True}
        return {"error": e.code}
    except Exception as e:
        return {"error": str(e)}


def check_hibp_domain(domain: str) -> dict:
    """Verifica breaches via HIBP."""
    url  = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
    data = _get(url, headers={"hibp-api-version": "3"})

    if isinstance(data, list):
        breaches = []
        for b in data:
            breaches.append({
                "name":         b.get("Name"),
                "date":         b.get("BreachDate"),
                "pwn_count":    b.get("PwnCount"),
                "data_classes": b.get("DataClasses", []),
                "is_sensitive": b.get("IsSensitive", False),
                "is_verified":  b.get("IsVerified", False),
            })
        return {"breaches": breaches, "count": len(breaches)}
    return {"breaches": [], "count": 0, "note": "HIBP não retornou breaches ou requer chave"}


def check_urlscan(target: str) -> dict:
    """Busca histórico de scans no urlscan.io."""
    url  = f"https://urlscan.io/api/v1/search/?q=domain:{target}&size=5"
    data = _get(url)
    if not data or "results" not in data:
        return {"scans": [], "count": 0}

    scans = []
    for r in data["results"][:5]:
        page = r.get("page", {})
        scans.append({
            "url":        page.get("url"),
            "country":    page.get("country"),
            "server":     page.get("server"),
            "ip":         page.get("ip"),
            "scan_date":  r.get("task", {}).get("time"),
            "screenshot": r.get("screenshot"),
            "report":     r.get("result"),
        })

    return {"scans": scans, "count": data.get("total", 0)}


def check_virustotal_domain(domain: str) -> dict:
    """Consulta VirusTotal."""
    url  = f"https://www.virustotal.com/api/v3/domains/{domain}"
    data = _get(url)
    if data and isinstance(data, dict) and "error" in data:
        code = data.get("error")
        if code == 401:
            return {"available": False, "note": "VirusTotal requer chave API (gratuita em virustotal.com)"}
        return {"available": False, "note": str(data)}

    if data and "data" in data:
        attrs = data["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "available":     True,
            "malicious":     stats.get("malicious", 0),
            "suspicious":    stats.get("suspicious", 0),
            "harmless":      stats.get("harmless", 0),
            "categories":    attrs.get("categories", {}),
            "reputation":    attrs.get("reputation"),
            "creation_date": attrs.get("creation_date"),
        }
    return {"available": False}


def check_google_safebrowsing(domain: str) -> dict:
    """Checa Google Transparency Report."""
    try:
        encoded = urllib.parse.quote(f"http://{domain}", safe="")
        url = f"https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site={encoded}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            raw   = r.read().decode()
            clean = raw.lstrip(")]}'\n")
            data  = json.loads(clean)
            safe  = True
            if isinstance(data, list) and len(data) > 1:
                statuses = data[1] if isinstance(data[1], list) else []
                for s in statuses:
                    if isinstance(s, list) and len(s) > 1 and s[0] != 0:
                        safe = False
            return {"safe": safe, "raw": data}
    except Exception as e:
        return {"safe": None, "error": str(e)}


def check_shodan_internetdb(ip: str) -> dict:
    return _check_shodan_basic(ip)


def run_osint(target: str) -> dict:
    """Ponto de entrada principal do módulo."""
    # FIX Bug 2: extração correta do domínio base
    domain = _extract_base_domain(target)

    hibp       = check_hibp_domain(domain)
    urlscan    = check_urlscan(target)
    vt         = check_virustotal_domain(domain)
    safebrowse = check_google_safebrowsing(domain)

    risk_flags = []
    if hibp.get("count", 0) > 0:
        risk_flags.append(f"Domínio encontrado em {hibp['count']} breach(es) — HaveIBeenPwned")
    if vt.get("malicious", 0) > 0:
        risk_flags.append(f"VirusTotal: {vt['malicious']} engine(s) marcam como malicioso")
    if safebrowse.get("safe") is False:
        risk_flags.append("Google Safe Browsing detectou conteúdo perigoso")
    if urlscan.get("count", 0) > 0:
        risk_flags.append(f"URLScan.io possui {urlscan['count']} scan(s) histórico(s)")

    return {
        "domain":          domain,
        "hibp":            hibp,
        "urlscan":         urlscan,
        "virustotal":      vt,
        "google_safebrow": safebrowse,
        "risk_flags":      risk_flags,
    }
