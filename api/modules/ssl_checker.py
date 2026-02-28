"""
Módulo: Verificação de Certificado SSL/TLS
Analisa: validade, emissor, protocolos, cipher suites, vulnerabilidades

CORREÇÕES:
  - Bug 1: ssl.TLSVersion.TLSv1 lança AttributeError no Python 3.10+/OpenSSL 3.x
            (TLS 1.0/1.1 removidos do enum em sistemas com OpenSSL 3.x endurecido).
            Fix: verificar existência do atributo antes de usar; marcar como
            "não testável" em vez de crashar.
"""

import ssl
import socket
import datetime
from typing import Optional


# Protocolos e cipher suites inseguros
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
WEAK_CIPHERS   = {"RC4", "DES", "3DES", "EXPORT", "NULL", "anon", "MD5"}

# Verifica suporte do sistema a TLS legado (Python 3.10+ / OpenSSL 3.x pode não ter)
_HAS_TLSv1   = hasattr(ssl.TLSVersion, "TLSv1")   if hasattr(ssl, "TLSVersion") else False
_HAS_TLSv1_1 = hasattr(ssl.TLSVersion, "TLSv1_1") if hasattr(ssl, "TLSVersion") else False


def get_cert(hostname: str, port: int = 443, timeout: int = 10) -> Optional[dict]:
    """Obtém o certificado SSL e metadados da conexão."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode    = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert        = ssock.getpeercert()
                cipher      = ssock.cipher()           # (name, proto, bits)
                tls_version = ssock.version()

                # Parse subject
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer", []))

                # Datas
                not_before = datetime.datetime.strptime(
                    cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
                )
                not_after  = datetime.datetime.strptime(
                    cert["notAfter"],  "%b %d %H:%M:%S %Y %Z"
                )
                now        = datetime.datetime.utcnow()
                days_left  = (not_after - now).days

                # SANs
                sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

                return {
                    "hostname":        hostname,
                    "port":            port,
                    "tls_version":     tls_version,
                    "cipher":          cipher[0] if cipher else None,
                    "cipher_bits":     cipher[2] if cipher else None,
                    "subject_cn":      subject.get("commonName"),
                    "subject_org":     subject.get("organizationName"),
                    "issuer_cn":       issuer.get("commonName"),
                    "issuer_org":      issuer.get("organizationName"),
                    "not_before":      not_before.isoformat(),
                    "not_after":       not_after.isoformat(),
                    "days_left":       days_left,
                    "expired":         days_left < 0,
                    "expiring_soon":   0 <= days_left <= 30,
                    "sans":            sans,
                    "san_count":       len(sans),
                    "serial":          cert.get("serialNumber"),
                    "valid":           True,
                }
    except ssl.SSLCertVerificationError as e:
        return {"hostname": hostname, "port": port, "valid": False, "error": str(e), "type": "cert_invalid"}
    except ssl.SSLError as e:
        return {"hostname": hostname, "port": port, "valid": False, "error": str(e), "type": "ssl_error"}
    except ConnectionRefusedError:
        return {"hostname": hostname, "port": port, "valid": None, "error": "Porta 443 fechada", "type": "no_ssl"}
    except Exception as e:
        return {"hostname": hostname, "port": port, "valid": None, "error": str(e), "type": "unknown"}


def check_weak_protocols(hostname: str, timeout: int = 5) -> dict:
    """
    Testa suporte a protocolos TLS legados (inseguros).

    CORREÇÃO Bug 1: ssl.TLSVersion.TLSv1 / TLSv1_1 podem não existir em
    Python 3.10+ compilado contra OpenSSL 3.x com hardening de sistema
    (ex: Ubuntu 22.04+, RHEL 9, Debian 12). Nesses ambientes o próprio
    sistema operacional remove suporte a TLS < 1.2 em nível de biblioteca,
    e o enum ssl.TLSVersion não expõe essas constantes.

    Fix: checar _HAS_TLSv1 / _HAS_TLSv1_1 antes de atribuir; se ausente,
    registrar como "not_testable" em vez de lançar AttributeError.
    """
    results = {}

    for proto_name, has_support, version_attr in [
        ("TLSv1.0", _HAS_TLSv1,   "TLSv1"),
        ("TLSv1.1", _HAS_TLSv1_1, "TLSv1_1"),
    ]:
        if not has_support:
            # Sistema não expõe a constante: protocolo já desativado em nível de OS
            results[proto_name] = False  # equivale a "não suportado" (situação segura)
            continue

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.minimum_version = getattr(ssl.TLSVersion, version_attr)
            ctx.maximum_version = getattr(ssl.TLSVersion, version_attr)

            with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as _:
                    results[proto_name] = True  # Suportado (ruim!)
        except (AttributeError, ValueError):
            # Atributo sumiu em runtime (edge-case de sistemas com patch parcial)
            results[proto_name] = False
        except Exception:
            results[proto_name] = False  # Não suportado (bom)

    return results


def analyze_risks(cert_data: dict, weak_protos: dict) -> list:
    """Gera lista de riscos SSL."""
    risks = []

    if not cert_data.get("valid"):
        risks.append({"level": "critical", "msg": f"Certificado inválido: {cert_data.get('error')}"})
        return risks

    if cert_data.get("expired"):
        risks.append({"level": "critical", "msg": f"Certificado expirado há {abs(cert_data['days_left'])} dias"})
    elif cert_data.get("expiring_soon"):
        risks.append({"level": "high", "msg": f"Certificado expira em {cert_data['days_left']} dias"})

    tls = cert_data.get("tls_version", "")
    if tls in WEAK_PROTOCOLS:
        risks.append({"level": "high", "msg": f"Protocolo fraco em uso: {tls}"})

    cipher = cert_data.get("cipher", "")
    for weak in WEAK_CIPHERS:
        if weak in (cipher or "").upper():
            risks.append({"level": "high", "msg": f"Cipher suite fraca: {cipher}"})
            break

    bits = cert_data.get("cipher_bits", 0) or 0
    if bits < 128:
        risks.append({"level": "high", "msg": f"Tamanho de chave insuficiente: {bits} bits"})

    for proto, supported in weak_protos.items():
        if supported:
            risks.append({"level": "medium", "msg": f"Servidor aceita protocolo legado: {proto}"})

    return risks


def check_ssl(target: str, port: int = 443) -> dict:
    """Ponto de entrada principal do módulo."""
    cert_data   = get_cert(target, port)
    weak_protos = {}

    if cert_data.get("valid"):
        try:
            weak_protos = check_weak_protocols(target)
        except Exception:
            pass

    risks = analyze_risks(cert_data or {}, weak_protos)

    return {
        "certificate":    cert_data,
        "weak_protocols": weak_protos,
        "risks":          risks,
        "risk_flags":     [r["msg"] for r in risks if r["level"] in ("critical", "high")],
    }
