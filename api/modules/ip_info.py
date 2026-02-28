"""
Módulo: Informações de IP e Geolocalização
Fontes: ip-api.com (HTTP — plano gratuito NÃO suporta HTTPS), ipinfo.io fallback

CORREÇÕES:
  - Bug 4: socket.gethostbyaddr(ip) não tinha timeout — em IPs sem registro
            PTR ou com servidor DNS lento pode travar por 30-120 s por IP,
            bloqueando toda a execução do scanner.
            Fix: executa gethostbyaddr em thread separada com join(timeout=5).
"""

import socket
import json
import urllib.request
import urllib.error
import threading
from typing import Optional

# ASNs de CDNs conhecidos — explica IP variável sem VPN
CDN_ASN_MAP = {
    "13335":  "Cloudflare",
    "54113":  "Fastly",
    "20940":  "Akamai",
    "16509":  "Amazon CloudFront",
    "15169":  "Google Cloud / GCP",
    "8075":   "Microsoft Azure CDN",
    "14618":  "Amazon AWS",
    "396982": "Google Cloud",
    "209242": "Cloudflare",
    "132892": "Cloudflare",
}

# Prefixos de IP conhecidos de Cloudflare
CLOUDFLARE_RANGES = [
    "103.21.244.", "103.22.200.", "103.31.4.", "104.16.", "104.17.",
    "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "108.162.",
    "131.0.72.", "141.101.64.", "141.101.65.", "162.158.", "172.64.",
    "172.65.", "172.66.", "172.67.", "172.68.", "172.69.", "172.70.",
    "172.71.", "185.93.228.", "188.114.96.", "188.114.97.", "190.93.240.",
    "197.234.240.", "198.41.128.", "198.41.129.",
]


def _http_get(url: str, timeout: int = 8) -> Optional[dict]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityReport/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def _reverse_dns_with_timeout(ip: str, timeout: float = 5.0) -> Optional[str]:
    """
    CORREÇÃO Bug 4: executa gethostbyaddr em thread separada com timeout.

    socket.gethostbyaddr() delega a resolução ao sistema operacional e não
    respeita socket.setdefaulttimeout(). Em redes lentas ou IPs sem PTR pode
    bloquear por até 120 s por entrada. Como resolve_target itera sobre
    até 3 IPs, o travamento total poderia ser de até 6 minutos.

    Fix: dispara gethostbyaddr em daemon thread e aguarda no máximo `timeout`
    segundos; se não concluir, retorna None (sem crash, sem bloqueio).
    """
    result_box: list = []

    def _worker():
        try:
            result_box.append(socket.gethostbyaddr(ip)[0])
        except socket.herror:
            result_box.append(None)
        except Exception:
            result_box.append(None)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout)
    return result_box[0] if result_box else None  # None se timeout


def resolve_target(target: str) -> dict:
    """Resolve hostname para IP(s) e faz lookup reverso."""
    result = {"target": target, "ips": [], "reverse_dns": [], "is_ip": False}

    try:
        socket.inet_aton(target)
        result["is_ip"] = True
        result["ips"] = [target]
    except OSError:
        pass

    if not result["is_ip"]:
        try:
            infos = socket.getaddrinfo(target, None)
            result["ips"] = list({i[4][0] for i in infos})
        except socket.gaierror as e:
            result["resolve_error"] = str(e)
            return result

    # CORREÇÃO Bug 4: usa _reverse_dns_with_timeout em vez de gethostbyaddr direto
    for ip in result["ips"][:3]:
        host = _reverse_dns_with_timeout(ip, timeout=5.0)
        result["reverse_dns"].append({"ip": ip, "host": host})

    return result


def detect_cdn(ip: str, asn_str: str = "", org: str = "") -> dict:
    """Detecta se o IP pertence a um CDN — explica geolocalização variável."""
    cdn_name = None

    if asn_str:
        for asn_id, name in CDN_ASN_MAP.items():
            if asn_id in asn_str:
                cdn_name = name
                break

    if not cdn_name:
        combined = (org or "").lower()
        for name in ["cloudflare", "fastly", "akamai", "cloudfront", "incapsula"]:
            if name in combined:
                cdn_name = name.title()
                break

    if not cdn_name:
        for prefix in CLOUDFLARE_RANGES:
            if ip.startswith(prefix):
                cdn_name = "Cloudflare"
                break

    if cdn_name:
        return {
            "is_cdn":   True,
            "cdn_name": cdn_name,
            "note": (
                f"⚠️ IP pertence à {cdn_name} (CDN). A localização exibida é do "
                f"ponto de presença (PoP) do CDN, não do servidor de origem. "
                f"Isso explica variações de localização (São Francisco, Toronto, etc.) "
                f"sem uso de VPN — é comportamento normal de CDNs."
            ),
        }
    return {"is_cdn": False, "cdn_name": None, "note": None}


def get_geolocation(ip: str) -> dict:
    """
    Obtém geolocalização via ip-api.com.
    IMPORTANTE: ip-api.com gratuito SÓ funciona via HTTP (não HTTPS).
    HTTPS é funcionalidade paga. Não alterar para https://.
    """
    data = _http_get(
        f"http://ip-api.com/json/{ip}"
        f"?fields=status,country,countryCode,regionName,city,isp,org,as,query"
    )
    if data and data.get("status") == "success":
        return {
            "ip":           data.get("query"),
            "country":      data.get("country"),
            "country_code": data.get("countryCode"),
            "region":       data.get("regionName"),
            "city":         data.get("city"),
            "isp":          data.get("isp"),
            "org":          data.get("org"),
            "asn":          data.get("as"),
        }
    # Fallback: ipinfo.io
    data2 = _http_get(f"https://ipinfo.io/{ip}/json")
    if data2:
        return {
            "ip":      data2.get("ip"),
            "country": data2.get("country"),
            "region":  data2.get("region"),
            "city":    data2.get("city"),
            "org":     data2.get("org"),
            "asn":     data2.get("org"),
        }
    return {"ip": ip, "error": "geolocation unavailable"}


def get_asn_info(ip: str) -> dict:
    """Consulta informação ASN via bgpview.io."""
    data = _http_get(f"https://api.bgpview.io/ip/{ip}")
    if not data or data.get("status") != "ok":
        return {}
    prefixes = data.get("data", {}).get("prefixes", [])
    if prefixes:
        p = prefixes[0]
        return {
            "asn":         p.get("asn", {}).get("asn"),
            "asn_name":    p.get("asn", {}).get("name"),
            "prefix":      p.get("prefix"),
            "description": p.get("description"),
        }
    return {}


def check_tor_exit(ip: str) -> bool:
    """Verifica se o IP é um nó de saída Tor via torproject.org."""
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        socket.gethostbyname(f"{reversed_ip}.dnsel.torproject.org")
        return True
    except socket.gaierror:
        return False


def check_shodan_basic(ip: str) -> dict:
    """Consulta InternetDB (Shodan, sem chave) para portas e CVEs."""
    data = _http_get(f"https://internetdb.shodan.io/{ip}")
    if data and "error" not in data:
        return {
            "open_ports": data.get("ports", []),
            "hostnames":  data.get("hostnames", []),
            "tags":       data.get("tags", []),
            "cves":       data.get("vulns", []),
        }
    return {}


def get_ip_info(target: str) -> dict:
    """Ponto de entrada principal do módulo."""
    result = resolve_target(target)

    if "resolve_error" in result:
        return result

    primary_ip = result["ips"][0] if result["ips"] else target

    geo = get_geolocation(primary_ip)
    result["geolocation"]  = geo
    result["asn"]          = get_asn_info(primary_ip)
    result["is_tor_exit"]  = check_tor_exit(primary_ip)
    result["shodan_quick"] = check_shodan_basic(primary_ip)

    asn_str = geo.get("asn", "") or ""
    org_str = geo.get("org", "") or geo.get("isp", "") or ""
    result["cdn_info"] = detect_cdn(primary_ip, asn_str, org_str)

    result["risk_flags"] = []
    if result["is_tor_exit"]:
        result["risk_flags"].append("IP é nó de saída Tor")
    if result["shodan_quick"].get("cves"):
        result["risk_flags"].append(
            f"Shodan reporta {len(result['shodan_quick']['cves'])} CVE(s) para este IP"
        )
    if result["cdn_info"]["is_cdn"]:
        result["risk_flags"].append(
            f"IP pertence ao CDN {result['cdn_info']['cdn_name']} — "
            f"geolocalização exibida é do PoP do CDN, não do servidor real"
        )

    return result
