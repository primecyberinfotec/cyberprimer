"""
Módulo: Fingerprint Web e Análise de Cabeçalhos HTTP
Analisa: tecnologias, cabeçalhos de segurança, cookies, redirect chain

CORREÇÕES:
  - Bug 3: dict(resp.headers) descartar headers duplicados fazia com que
            apenas o último Set-Cookie fosse analisado (respostas comuns
            com 3-10 cookies deixavam os demais invisíveis).
            Fix: usar resp.headers.get_all() / items() para coletar todos
            os valores de Set-Cookie antes de converter para dict.
"""

import urllib.request
import urllib.error
import urllib.parse
import ssl
import re
from typing import Optional


# Cabeçalhos de segurança esperados e seus riscos se ausentes
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "risk": "high",
        "description": "HSTS — força HTTPS, previne downgrade",
        "recommendation": "Adicionar: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "risk": "high",
        "description": "CSP — previne XSS e injeção de conteúdo",
        "recommendation": "Definir política CSP restritiva"
    },
    "X-Frame-Options": {
        "risk": "medium",
        "description": "Previne clickjacking",
        "recommendation": "Adicionar: X-Frame-Options: DENY ou SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "risk": "medium",
        "description": "Previne MIME sniffing",
        "recommendation": "Adicionar: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "risk": "low",
        "description": "Controla informações de referência",
        "recommendation": "Adicionar: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "risk": "low",
        "description": "Controla APIs do navegador (câmera, mic, etc.)",
        "recommendation": "Definir Permissions-Policy restritiva"
    },
    "X-XSS-Protection": {
        "risk": "low",
        "description": "Proteção XSS legada (browsers antigos)",
        "recommendation": "Adicionar: X-XSS-Protection: 1; mode=block"
    },
}

# Assinaturas de tecnologias nos cabeçalhos / conteúdo
TECH_SIGNATURES = {
    "WordPress":       [r"wp-content", r"wp-includes", r"WordPress"],
    "Drupal":          [r"Drupal", r"sites/default/files"],
    "Joomla":          [r"Joomla!", r"/components/com_"],
    "Laravel":         [r"laravel_session", r"XSRF-TOKEN"],
    "Django":          [r"csrfmiddlewaretoken", r"Django"],
    "Ruby on Rails":   [r"_rails", r"X-Request-Id"],
    "Express.js":      [r"X-Powered-By: Express"],
    "Next.js":         [r"__NEXT_DATA__", r"/_next/"],
    "React":           [r"__react", r"data-reactroot"],
    "Vue.js":          [r"data-v-", r"__vue__"],
    "jQuery":          [r"jquery"],
    "Bootstrap":       [r"bootstrap"],
    "Apache":          [r"Server: Apache"],
    "Nginx":           [r"Server: nginx"],
    "IIS":             [r"Server: Microsoft-IIS"],
    "Cloudflare":      [r"cf-ray", r"cloudflare"],
    "AWS CloudFront":  [r"X-Amz-Cf-Id", r"CloudFront"],
    "Fastly":          [r"Fastly-Restarts", r"X-Served-By.*cache"],
    "Varnish":         [r"X-Varnish", r"Age:"],
    "PHP":             [r"X-Powered-By: PHP", r"PHPSESSID"],
    "ASP.NET":         [r"X-Powered-By: ASP.NET", r"ASP.NET_SessionId"],
    "Tomcat":          [r"JSESSIONID", r"Apache Tomcat"],
    "Elasticsearch":   [r"\"cluster_name\""],
    "GraphQL":         [r"\"__schema\"", r"/graphql"],
}


def _collect_set_cookie_headers(resp) -> list:
    """
    CORREÇÃO Bug 3: coleta TODOS os valores de Set-Cookie da resposta.

    http.client.HTTPResponse.headers é um email.message.Message que suporta
    múltiplos valores para o mesmo campo via get_all(). Converter diretamente
    para dict() perde todos os duplicados, mantendo apenas o último.

    Fix: usar .get_all("set-cookie") para obter a lista completa.
    """
    try:
        # http.client expõe get_all()
        values = resp.headers.get_all("set-cookie") or []
        return values
    except AttributeError:
        # Fallback para implementações alternativas
        cookies = []
        for k, v in resp.headers.items():
            if k.lower() == "set-cookie":
                cookies.append(v)
        return cookies


def _http_request(url: str, timeout: int = 10) -> Optional[tuple]:
    """
    Faz requisição HTTP e retorna (headers_dict, all_set_cookies, body_snippet, final_url, status).
    Retorna tupla de 5 elementos (incompatível com o original de 4 — ver get_web_info).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPRedirectHandler()
    )
    opener.addheaders = [
        ("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)"),
        ("Accept", "text/html,application/xhtml+xml,*/*"),
    ]

    try:
        with opener.open(url, timeout=timeout) as resp:
            # CORREÇÃO: captura todos os Set-Cookie antes de converter para dict
            all_cookies = _collect_set_cookie_headers(resp)
            headers     = dict(resp.headers)
            body        = resp.read(8192).decode(errors="ignore")
            final_url   = resp.url
            status      = resp.status
            return headers, all_cookies, body, final_url, status
    except urllib.error.HTTPError as e:
        headers = dict(e.headers) if e.headers else {}
        all_cookies = []
        try:
            all_cookies = e.headers.get_all("set-cookie") or [] if e.headers else []
        except AttributeError:
            pass
        return headers, all_cookies, "", url, e.code
    except Exception:
        return None


def check_security_headers(headers: dict) -> dict:
    """Avalia presença e configuração dos cabeçalhos de segurança."""
    result = {"present": {}, "missing": {}, "score": 0, "max_score": 0}

    for header, meta in SECURITY_HEADERS.items():
        result["max_score"] += 1
        value = next((v for k, v in headers.items() if k.lower() == header.lower()), None)
        if value:
            result["present"][header] = {"value": value, **meta}
            result["score"] += 1
        else:
            result["missing"][header] = meta

    result["percentage"] = round((result["score"] / result["max_score"]) * 100) if result["max_score"] else 0
    return result


def detect_technologies(headers: dict, body: str) -> list:
    """Detecta tecnologias via assinaturas em headers e body."""
    detected = []
    combined = str(headers) + body

    for tech, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                detected.append(tech)
                break

    return list(set(detected))


def check_cookies(all_set_cookies: list) -> list:
    """
    CORREÇÃO Bug 3: analisa flags de segurança em TODOS os cookies da resposta.

    Antes: buscava apenas o primeiro Set-Cookie via next() no dict de headers,
    deixando todos os outros cookies sem análise — um site com session + csrf
    + tracking cookies teria apenas o primeiro verificado.

    Fix: recebe a lista completa de valores Set-Cookie e analisa cada um.
    """
    issues = []

    if not all_set_cookies:
        return issues

    for cookie_header in all_set_cookies:
        # Extrai nome do cookie para contexto no log
        cookie_name = cookie_header.split("=")[0].strip() if "=" in cookie_header else "?"

        if "HttpOnly" not in cookie_header:
            issues.append({
                "risk": "medium",
                "msg":  f"Cookie '{cookie_name}' sem flag HttpOnly — acessível via JavaScript",
            })
        if "Secure" not in cookie_header:
            issues.append({
                "risk": "medium",
                "msg":  f"Cookie '{cookie_name}' sem flag Secure — pode ser enviado em HTTP",
            })
        if "SameSite" not in cookie_header:
            issues.append({
                "risk": "low",
                "msg":  f"Cookie '{cookie_name}' sem SameSite — risco de CSRF",
            })

    # Deduplica mensagens idênticas (vários cookies com mesmo problema)
    seen = set()
    deduped = []
    for issue in issues:
        key = issue["msg"]
        if key not in seen:
            seen.add(key)
            deduped.append(issue)

    return deduped


def get_redirect_chain(target: str, timeout: int = 10) -> list:
    """Mapeia a cadeia de redirecionamentos."""
    chain  = []
    seen   = set()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            chain.append({"url": req.full_url, "status": code, "location": newurl})
            if newurl in seen or len(chain) > 10:
                return None
            seen.add(newurl)
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    start_url = f"http://{target}"
    try:
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
        opener.addheaders = [("User-Agent", "Mozilla/5.0")]
        with opener.open(start_url, timeout=timeout) as r:
            chain.append({"url": r.url, "status": r.status, "location": None})
    except Exception:
        pass

    return chain


def get_web_info(target: str, timeout: int = 10) -> dict:
    """Ponto de entrada principal do módulo."""
    result = {
        "target":          target,
        "urls_checked":    [],
        "headers":         {},
        "technologies":    [],
        "security_headers":{},
        "cookie_issues":   [],
        "all_cookies":     [],   # novo: lista raw de Set-Cookie coletados
        "redirect_chain":  [],
        "server":          None,
        "powered_by":      None,
        "risk_flags":      [],
    }

    # Tenta HTTPS primeiro, depois HTTP
    for scheme in ["https", "http"]:
        url  = f"{scheme}://{target}"
        resp = _http_request(url, timeout)
        if resp:
            headers, all_cookies, body, final_url, status = resp
            result["urls_checked"].append({"url": url, "final": final_url, "status": status})
            result["headers"]      = {k: v for k, v in headers.items()}
            result["all_cookies"]  = all_cookies          # CORREÇÃO: preserva lista completa
            result["technologies"] = detect_technologies(headers, body)

            result["server"]     = headers.get("Server") or headers.get("server")
            result["powered_by"] = headers.get("X-Powered-By") or headers.get("x-powered-by")
            break

    result["security_headers"] = check_security_headers(result["headers"])
    result["cookie_issues"]    = check_cookies(result["all_cookies"])  # CORREÇÃO: passa lista
    result["redirect_chain"]   = get_redirect_chain(target, timeout)

    # Risk flags
    sec = result["security_headers"]
    if sec["percentage"] < 50:
        result["risk_flags"].append(f"Score de cabeçalhos de segurança baixo: {sec['percentage']}%")

    missing_critical = [h for h, m in sec["missing"].items() if m["risk"] == "high"]
    if missing_critical:
        result["risk_flags"].append(f"Cabeçalhos críticos ausentes: {', '.join(missing_critical)}")

    if result["server"] and any(v in (result["server"] or "") for v in ["Apache/2.2", "Apache/2.0", "nginx/1.0", "nginx/1.2"]):
        result["risk_flags"].append(f"Versão de servidor desatualizada exposta: {result['server']}")

    if result["powered_by"]:
        result["risk_flags"].append(f"X-Powered-By expõe tecnologia: {result['powered_by']}")

    for issue in result["cookie_issues"]:
        if issue["risk"] == "medium":
            result["risk_flags"].append(issue["msg"])

    return result
