"""
Módulo: Enumeração DNS e Subdomínios
Analisa: registros A, AAAA, MX, TXT, NS, CNAME, SPF, DMARC
Tenta: enumeração de subdomínios via wordlist + crt.sh

CORREÇÕES:
  - Bug 1 (CRÍTICO): `domain = ".".join(parts[-2:])` não reconhece TLDs compostos.
    Para "animaiseciabrasil.com.br" extraía "com.br" em vez do domínio real.
    Resultado: crt.sh consultado para "%.com.br" → 6.050 subdomínios de toda a
    zona .com.br, execução de 648s, SPF/DMARC/MX/NS verificados em "com.br".
    Fix: _extract_base_domain() com lista de SLDs brasileiros e internacionais.

  - Bug 1b: crt.sh pode retornar milhares de entradas mesmo com domínio correto
    (domínios com wildcard certs). Adicionado cap de 500 resoluções para
    evitar travamentos em casos extremos.

  - Bug 1c: analyze_dmarc() recebe `domain` (que era "com.br"), portanto
    consultava `_dmarc.com.br` — sempre retornava "ausente" mesmo que o
    domínio real tivesse DMARC. Corrigido automaticamente com o fix do domínio.
"""

import socket
import json
import urllib.request
from typing import Optional


# ── TLDs compostos conhecidos ─────────────────────────────────────────────────
# Segundo nível do Brasil (.com.br, .net.br, etc.)
_BR_SLD = {
    "com", "net", "org", "edu", "gov", "mil", "adv", "agr", "arq",
    "art", "ato", "bio", "cng", "cnt", "coop", "ecn", "eco", "eng",
    "esp", "etc", "eti", "far", "fnd", "fot", "fst", "ind", "inf",
    "jor", "jus", "leg", "lel", "mat", "med", "mus", "not", "ntr",
    "odo", "pro", "psc", "rec", "srv", "trd", "tur", "tv", "vet",
}

# Outros ccTLDs comuns com SLD composto
_CC_SLD = {
    ("co", "uk"), ("org", "uk"), ("me", "uk"), ("net", "uk"), ("gov", "uk"),
    ("com", "au"), ("net", "au"), ("org", "au"), ("edu", "au"), ("gov", "au"),
    ("co", "nz"), ("org", "nz"), ("net", "nz"), ("govt", "nz"),
    ("co", "jp"), ("ne", "jp"), ("or", "jp"), ("ac", "jp"),
    ("com", "mx"), ("org", "mx"), ("net", "mx"), ("gob", "mx"),
    ("com", "ar"), ("org", "ar"), ("net", "ar"), ("gob", "ar"),
    ("com", "co"), ("org", "co"), ("net", "co"), ("gov", "co"),
}

# Quantos subdomínios do crt.sh resolver via socket (evita travar em domínios
# com milhares de certificados wildcard)
_MAX_CT_RESOLVE = 300


def _extract_base_domain(target: str) -> str:
    """
    FIX Bug 1: Extrai o domínio registrável corretamente para TLDs compostos.

    Exemplos:
      animaiseciabrasil.com.br  → animaiseciabrasil.com.br
      lp.bwcommerce.com.br      → bwcommerce.com.br
      hospital.animaiseciabrasil.com.br → animaiseciabrasil.com.br
      sub.example.com           → example.com
      example.co.uk             → example.co.uk
    """
    parts = target.split(".")
    n = len(parts)

    if n < 2:
        return target

    # Caso .com.br, .net.br, etc.
    if n >= 3 and parts[-1] == "br" and parts[-2] in _BR_SLD:
        # Domínio registrável = último label antes do SLD + SLD + "br"
        # ["lp","bwcommerce","com","br"] → parts[-3:] = ["bwcommerce","com","br"]
        # ["animaiseciabrasil","com","br"] → n==3 → return all
        return ".".join(parts[-(min(n, 3)):])

    # Outros ccTLDs compostos
    if n >= 3 and (parts[-2], parts[-1]) in _CC_SLD:
        return ".".join(parts[-(min(n, 3)):])

    # Caso padrão: pega os últimos 2 labels
    return ".".join(parts[-2:])


# Wordlist de subdomínios comuns
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "admin",
    "api", "dev", "staging", "test", "uat", "prod", "app", "mobile",
    "m", "static", "cdn", "assets", "media", "img", "images", "docs",
    "portal", "vpn", "remote", "intranet", "extranet", "git", "gitlab",
    "github", "jenkins", "ci", "jira", "confluence", "monitor", "metrics",
    "grafana", "kibana", "dashboard", "status", "health", "login", "auth",
    "sso", "oauth", "accounts", "shop", "store", "pay", "payment", "secure",
    "ns1", "ns2", "mx1", "mx2", "backup", "old", "legacy", "v2", "beta",
    "internal", "corp", "helpdesk", "support", "crm", "erp", "db", "mysql",
]


def resolve_record(hostname: str, timeout: int = 5) -> Optional[str]:
    """Tenta resolver um hostname."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def get_txt_records(domain: str) -> list:
    """Busca registros TXT via dig/nslookup."""
    import subprocess, shutil
    records = []

    if shutil.which("dig"):
        try:
            r = subprocess.run(
                ["dig", "+short", "TXT", domain],
                capture_output=True, text=True, timeout=10
            )
            records = [line.strip('"').strip() for line in r.stdout.splitlines() if line.strip()]
        except Exception:
            pass
    elif shutil.which("nslookup"):
        try:
            r = subprocess.run(
                ["nslookup", "-type=TXT", domain],
                capture_output=True, text=True, timeout=10
            )
            for line in r.stdout.splitlines():
                if "text =" in line:
                    records.append(line.split("text =")[-1].strip().strip('"'))
        except Exception:
            pass

    return records


def get_mx_records(domain: str) -> list:
    """Busca servidores MX."""
    import subprocess, shutil
    records = []
    if shutil.which("dig"):
        try:
            r = subprocess.run(
                ["dig", "+short", "MX", domain],
                capture_output=True, text=True, timeout=10
            )
            records = [line.strip() for line in r.stdout.splitlines() if line.strip()]
        except Exception:
            pass
    return records


def get_ns_records(domain: str) -> list:
    """Busca nameservers."""
    import subprocess, shutil
    records = []
    if shutil.which("dig"):
        try:
            r = subprocess.run(
                ["dig", "+short", "NS", domain],
                capture_output=True, text=True, timeout=10
            )
            records = [line.strip().rstrip(".") for line in r.stdout.splitlines() if line.strip()]
        except Exception:
            pass
    return records


def get_crtsh_subdomains(domain: str) -> list:
    """Busca subdomínios via crt.sh (Certificate Transparency Logs)."""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityReport/1.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read().decode())
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for line in name.splitlines():
                line = line.strip().lstrip("*.")
                if line.endswith(domain) and line != domain:
                    subdomains.add(line.lower())
        return sorted(subdomains)
    except Exception:
        return []


def brute_subdomains(domain: str, wordlist: list = COMMON_SUBDOMAINS) -> list:
    """Tenta resolver subdomínios comuns."""
    found = []
    for sub in wordlist:
        fqdn = f"{sub}.{domain}"
        ip = resolve_record(fqdn, timeout=2)
        if ip:
            found.append({"subdomain": fqdn, "ip": ip})
    return found


def analyze_spf(txt_records: list) -> dict:
    """Analisa política SPF."""
    for rec in txt_records:
        if rec.startswith("v=spf1"):
            soft_fail = "~all" in rec
            fail      = "-all" in rec
            return {
                "record":  rec,
                "exists":  True,
                "policy":  "-all" if fail else "~all" if soft_fail else "+all",
                "risk":    "low" if fail else "medium" if soft_fail else "high",
            }
    return {"exists": False, "risk": "high", "note": "SPF ausente — risco de spoofing de email"}


def analyze_dmarc(domain: str, txt_records: list) -> dict:
    """
    Verifica política DMARC.
    FIX Bug 1c: domain agora é o domínio registrável correto, não "com.br".
    """
    dmarc_records = get_txt_records(f"_dmarc.{domain}")
    for rec in dmarc_records:
        if rec.startswith("v=DMARC1"):
            policy = "none"
            if "p=reject"     in rec: policy = "reject"
            elif "p=quarantine" in rec: policy = "quarantine"
            return {
                "record": rec,
                "exists": True,
                "policy": policy,
                "risk":   "low" if policy == "reject" else "medium" if policy == "quarantine" else "high",
            }
    return {"exists": False, "risk": "high", "note": "DMARC ausente — domínio pode ser usado para phishing"}


def enumerate_dns(target: str) -> dict:
    """Ponto de entrada principal do módulo."""
    # FIX Bug 1: usa extração correta de domínio base
    domain = _extract_base_domain(target)

    txt_records = get_txt_records(target)
    # Para MX/NS, usa o domínio base registrável (não subdomínio)
    mx_records  = get_mx_records(domain)
    ns_records  = get_ns_records(domain)

    # Subdomínios via Certificate Transparency
    ct_subs = get_crtsh_subdomains(domain)

    # Brute force com wordlist
    brute_subs = brute_subdomains(domain)
    brute_set  = {s["subdomain"] for s in brute_subs}

    # Merge: adiciona CT subs não encontrados no brute
    # FIX Bug 1b: cap de _MAX_CT_RESOLVE para evitar travar com wildcards
    all_subdomains = list(brute_subs)
    ct_to_resolve  = [s for s in ct_subs if s not in brute_set][:_MAX_CT_RESOLVE]
    for sub in ct_to_resolve:
        ip = resolve_record(sub, timeout=2)
        all_subdomains.append({"subdomain": sub, "ip": ip, "source": "crt.sh"})

    spf   = analyze_spf(txt_records)
    dmarc = analyze_dmarc(domain, txt_records)

    risk_flags = []
    if not spf["exists"]:
        risk_flags.append(spf.get("note", "SPF ausente"))
    if spf.get("risk") == "high" and spf["exists"]:
        risk_flags.append(f"Política SPF permissiva: {spf.get('record', '')}")
    if not dmarc["exists"]:
        risk_flags.append(dmarc.get("note", "DMARC ausente"))
    if dmarc.get("risk") == "high" and dmarc["exists"]:
        risk_flags.append("DMARC com política 'none' — phishing possível")

    return {
        "domain":          domain,
        "target":          target,
        "txt_records":     txt_records,
        "mx_records":      mx_records,
        "ns_records":      ns_records,
        "spf":             spf,
        "dmarc":           dmarc,
        "subdomains":      all_subdomains,
        "subdomain_count": len(all_subdomains),
        "ct_log_count":    len(ct_subs),
        "risk_flags":      risk_flags,
    }
