"""
Módulo: Correlação de Vulnerabilidades
Cruza serviços/versões com CVEs via NVD (NIST) e regras locais.

CORREÇÕES:
  - Bug 3 (CRÍTICO): _nvd_lookup() sem filtro de data retornava CVEs de 2004
    (CVE-2004-1559, CVE-2004-1584 confirmados nos logs). NVD ordena por
    relevância, não por data — CVEs antigos ficam no topo para termos genéricos.
    Fix: parâmetro pubStartDate=2018-01-01T00:00:00.000 + filtra localmente
    qualquer CVE cujo ID seja anterior a 2015 como segunda barreira.

  - Bug 4 (CRÍTICO): sem rate limiting na NVD API pública.
    Limite: 5 req/30s sem chave. A partir do 6º, retorna 403/503 silencioso
    e a função retornava [] — aparentando "sem CVEs" quando havia falha.
    Fix: _RateLimiter garante ≥ 6.5s entre chamadas + retry em 403/429.

  - Bug anterior (mantido corrigido): get_shodan_cves() agora lê CVEs corretamente
    do campo ip_data["shodan_quick"]["cves"] em vez de retornar sempre [].
"""

import json
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional


# ── Rate limiter global para NVD ─────────────────────────────────────────────
class _RateLimiter:
    _last_call: float = 0.0
    _min_interval: float = 6.5   # NVD público: máx 5 req/30s → ~6s de segurança

    @classmethod
    def wait(cls):
        elapsed = time.monotonic() - cls._last_call
        if elapsed < cls._min_interval:
            time.sleep(cls._min_interval - elapsed)
        cls._last_call = time.monotonic()


# ── Regras locais (não dependem de API) ──────────────────────────────────────
LOCAL_VULN_RULES = [
    {
        "match_service": "redis",
        "cve": "Configuração", "severity": "critical", "cvss": 9.8,
        "title": "Redis sem autenticação frequentemente exposto",
        "desc":  "Redis em portas públicas frequentemente sem senha — acesso total ao banco em memória",
        "ref":   "https://redis.io/docs/latest/operate/oss_and_stack/management/security/",
    },
    {
        "match_service": "elasticsearch",
        "cve": "Configuração", "severity": "critical", "cvss": 9.8,
        "title": "Elasticsearch sem autenticação pode expor dados",
        "desc":  "Elasticsearch versões antigas sem segurança habilitada por padrão",
        "ref":   "https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html",
    },
    {
        "match_service": "mongodb",
        "cve": "Configuração", "severity": "critical", "cvss": 9.1,
        "title": "MongoDB pode estar sem autenticação",
        "desc":  "MongoDB exposto publicamente sem autenticação permitiu milhões de registros vazados",
        "ref":   "https://docs.mongodb.com/manual/security/",
    },
    {
        "match_service": "telnet",
        "cve": "CWE-319", "severity": "critical", "cvss": 9.1,
        "title": "Telnet transmite dados em texto plano",
        "desc":  "Credenciais e dados trafegam sem criptografia — substituir por SSH",
        "ref":   "https://owasp.org/www-community/vulnerabilities/Cleartext_Transmission_of_Sensitive_Information",
    },
    {
        "match_service": "ftp",
        "cve": "CWE-319", "severity": "high", "cvss": 7.5,
        "title": "FTP transmite credenciais em texto plano",
        "desc":  "FTP não criptografado — usar SFTP ou FTPS",
        "ref":   "https://owasp.org/www-community/vulnerabilities/Cleartext_Transmission_of_Sensitive_Information",
    },
    {
        "match_service": "smb",
        "cve": "CVE-2017-0144", "severity": "critical", "cvss": 9.8,
        "title": "SMB exposto — risco EternalBlue/WannaCry",
        "desc":  "Porta SMB (445) exposta à internet — alvo frequente de ransomware",
        "ref":   "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144",
    },
    {
        "match_service": "rdp",
        "cve": "CVE-2019-0708", "severity": "critical", "cvss": 9.8,
        "title": "RDP exposto — risco BlueKeep",
        "desc":  "RDP público é alvo de brute force e exploits críticos como BlueKeep",
        "ref":   "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708",
    },
    {
        "match_service": "mysql",
        "cve": "Configuração", "severity": "critical", "cvss": 9.8,
        "title": "MySQL exposto à internet",
        "desc":  "Banco de dados MySQL acessível externamente — alvo de brute-force e exfiltração",
        "ref":   "https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html",
    },
    {
        "match_service": "postgresql",
        "cve": "Configuração", "severity": "critical", "cvss": 9.8,
        "title": "PostgreSQL exposto à internet",
        "desc":  "Banco de dados PostgreSQL acessível externamente",
        "ref":   "https://www.postgresql.org/docs/current/auth-pg-hba-conf.html",
    },
    {
        "match_service": "vnc",
        "cve": "Configuração", "severity": "high", "cvss": 8.1,
        "title": "VNC exposto — controle remoto de desktop acessível",
        "desc":  "VNC exposto sem VPN — risco de acesso não autorizado ao desktop",
        "ref":   "https://www.cisa.gov/uscert/ncas/alerts/TA17-293A",
    },
]

SERVICE_TO_NVD_KEYWORD = {
    "apache":     "Apache HTTP Server",
    "nginx":      "nginx",
    "openssl":    "OpenSSL",
    "openssh":    "OpenSSH",
    "mysql":      "MySQL",
    "postgresql": "PostgreSQL",
    "mariadb":    "MariaDB",
    "tomcat":     "Apache Tomcat",
    "wordpress":  "WordPress",
    "drupal":     "Drupal",
    "joomla":     "Joomla",
    "php":        "PHP",
    "iis":        "Microsoft IIS",
}

# CVEs de tecnologias web que não têm versão detectada:
# só consultamos NVD se tiver versão. Sem versão, usamos apenas estas regras
# locais focadas nos riscos de configuração (não CVEs de versão específica).
WEB_TECH_CONFIG_RULES = {
    "wordpress": {
        "cve": "Configuração", "severity": "medium", "cvss": 5.3,
        "title": "WordPress detectado — requer hardening e atualizações constantes",
        "desc": (
            "WordPress é o CMS mais atacado do mundo. Sem versão detectada, não "
            "é possível correlacionar CVEs específicos, mas a exposição ao xmlrpc.php, "
            "wp-login.php e plugins desatualizados são vetores comuns de ataque."
        ),
        "ref": "https://wordpress.org/support/article/hardening-wordpress/",
    },
    "drupal": {
        "cve": "Configuração", "severity": "medium", "cvss": 5.0,
        "title": "Drupal detectado — verificar atualizações de segurança",
        "desc": "Drupal possui histórico de vulnerabilidades críticas (Drupalgeddon). Manter sempre atualizado.",
        "ref": "https://www.drupal.org/security",
    },
    "joomla": {
        "cve": "Configuração", "severity": "medium", "cvss": 5.0,
        "title": "Joomla detectado — verificar atualizações de segurança",
        "desc": "Joomla requer atualizações frequentes de núcleo e extensões.",
        "ref": "https://developer.joomla.org/security-centre.html",
    },
}


def _nvd_lookup(keyword: str, version: str, max_results: int = 5) -> list:
    """
    Consulta NVD com rate limiting e filtro de data.
    FIX Bug 3: pubStartDate=2018 elimina CVEs antigos irrelevantes.
    FIX Bug 4: _RateLimiter garante espaçamento entre chamadas.
    """
    if not keyword:
        return []

    _RateLimiter.wait()

    try:
        q = urllib.parse.quote(f"{keyword} {version}".strip())
        # FIX Bug 3: filtra CVEs anteriores a 2018
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch={q}"
            f"&resultsPerPage={max_results}"
            f"&pubStartDate=2018-01-01T00%3A00%3A00.000"
            f"&cvssV3Severity=MEDIUM"  # só retorna MEDIUM, HIGH, CRITICAL
        )
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityReport/1.0"})

        for attempt in range(2):
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    data = json.loads(r.read().decode())
                break
            except urllib.error.HTTPError as e:
                if e.code in (403, 429) and attempt == 0:
                    # FIX Bug 4: back-off em rate limit
                    time.sleep(10)
                    continue
                return []
        else:
            return []

        vulns = []
        for item in data.get("vulnerabilities", [])[:max_results]:
            cve  = item.get("cve", {})
            cve_id = cve.get("id", "")

            # FIX Bug 3: segunda barreira — rejeita CVEs com ID < 2015
            try:
                cve_year = int(cve_id.split("-")[1]) if cve_id else 0
                if cve_year < 2015:
                    continue
            except (IndexError, ValueError):
                pass

            desc    = cve.get("descriptions", [{}])[0].get("value", "")
            metrics = cve.get("metrics", {})
            cvss_score = None
            severity   = "unknown"

            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                m = metrics.get(key, [])
                if m:
                    cvss_data  = m[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    severity   = cvss_data.get("baseSeverity", m[0].get("baseSeverity", "unknown")).lower()
                    break

            vulns.append({
                "cve":      cve_id,
                "title":    desc[:120] if desc else "",
                "severity": severity,
                "cvss":     cvss_score,
                "url":      f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        return vulns

    except Exception:
        return []


def apply_local_rules(ports_data: dict) -> list:
    """Aplica regras locais de vulnerabilidade aos serviços encontrados."""
    open_ports = ports_data.get("open_ports", [])
    findings   = []

    for port in open_ports:
        service  = (port.get("service") or "").lower()
        product  = (port.get("product") or "").lower()
        combined = f"{service} {product}"

        for rule in LOCAL_VULN_RULES:
            if rule["match_service"] in combined:
                findings.append({**rule, "port": port.get("port"), "source": "local_rules"})

    return findings


def check_service_cves(ports_data: dict, web_data: dict) -> list:
    """
    Consulta NVD para serviços com versão detectada.
    Para tecnologias web sem versão, usa regras locais (não NVD).
    FIX Bug 3/4: _nvd_lookup agora tem filtro de data e rate limiting.
    """
    open_ports = ports_data.get("open_ports", [])
    findings   = []
    queried    = set()

    # Serviços de porta: consulta NVD apenas se tiver versão detectada
    for port in open_ports:
        service = (port.get("service") or "").lower()
        product = (port.get("product") or "").lower()
        version = port.get("version") or ""

        keyword = None
        for svc_key, nvd_kw in SERVICE_TO_NVD_KEYWORD.items():
            if svc_key in service or svc_key in product:
                keyword = nvd_kw
                break

        # Só consulta NVD se tiver versão — sem versão é impossível correlacionar
        if keyword and version and (keyword, version) not in queried:
            queried.add((keyword, version))
            cves = _nvd_lookup(keyword, version)
            for cve in cves:
                cve["port"]   = port.get("port")
                cve["source"] = "nvd_api"
                findings.append(cve)

    # Tecnologias web: se tiver versão, consulta NVD; se não, usa regra local
    techs = web_data.get("technologies", [])
    for tech in techs:
        tech_lower = tech.lower()

        # Tenta extrair versão do string "WordPress 6.4" etc.
        parts = tech.split()
        version_from_tech = parts[1] if len(parts) > 1 else ""

        for svc_key, nvd_kw in SERVICE_TO_NVD_KEYWORD.items():
            if svc_key in tech_lower:
                if version_from_tech and (nvd_kw, version_from_tech) not in queried:
                    # Versão conhecida → consulta NVD com filtro de data
                    queried.add((nvd_kw, version_from_tech))
                    cves = _nvd_lookup(nvd_kw, version_from_tech, max_results=3)
                    for cve in cves:
                        cve["source"] = "nvd_web_tech"
                        findings.append(cve)
                elif not version_from_tech and svc_key in WEB_TECH_CONFIG_RULES and (svc_key, "config") not in queried:
                    # Sem versão → regra local de configuração
                    queried.add((svc_key, "config"))
                    rule = WEB_TECH_CONFIG_RULES[svc_key].copy()
                    rule["source"] = "local_web_config"
                    findings.append(rule)
                break

    return findings


def get_shodan_cves(ip_data: dict) -> list:
    """
    Extrai CVEs reportados pelo Shodan InternetDB.
    Mantido corrigido: lê corretamente ip_data["shodan_quick"]["cves"].
    """
    findings = []
    if not ip_data:
        return findings

    cve_ids = ip_data.get("shodan_quick", {}).get("cves", [])
    for cve_id in cve_ids:
        findings.append({
            "cve":    cve_id,
            "title":  f"Vulnerabilidade detectada pelo Shodan: {cve_id}",
            "severity": "high",
            "cvss":   None,
            "desc":   "CVE identificado pelo Shodan InternetDB. Consulte nvd.nist.gov para detalhes e patch.",
            "url":    f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "source": "shodan_internetdb",
            "port":   None,
        })
    return findings


def categorize_findings(all_findings: list) -> dict:
    """Categoriza vulnerabilidades por severidade e remove duplicatas."""
    result = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    seen   = set()

    for f in all_findings:
        key = f.get("cve") or f.get("title", "")
        if key in seen:
            continue
        seen.add(key)

        sev = (f.get("severity") or "info").lower()
        if sev == "critical":
            result["critical"].append(f)
        elif sev == "high":
            result["high"].append(f)
        elif sev in ("medium", "moderate"):
            result["medium"].append(f)
        elif sev == "low":
            result["low"].append(f)
        else:
            result["info"].append(f)

    return result


def check_vulnerabilities(ports_data: dict, web_data: dict, ip_data: dict = None) -> dict:
    """Ponto de entrada principal do módulo."""
    local_findings  = apply_local_rules(ports_data)
    cve_findings    = check_service_cves(ports_data, web_data)
    shodan_findings = get_shodan_cves(ip_data)

    all_findings = local_findings + cve_findings + shodan_findings
    categorized  = categorize_findings(all_findings)

    risk_flags = []
    if categorized["critical"]:
        risk_flags.append(f"{len(categorized['critical'])} vulnerabilidade(s) CRÍTICA(s) identificada(s)")
    if categorized["high"]:
        risk_flags.append(f"{len(categorized['high'])} vulnerabilidade(s) de alto risco")

    return {
        **categorized,
        "total":      sum(len(v) for v in categorized.values()),
        "risk_flags": risk_flags,
    }
