"""
Módulo: Scan de Portas e Serviços
Usa: nmap (python-nmap wrapper) com fallback para socket

CORREÇÕES:
  - Bug 2: port_spec="all" no fallback socket produzia lista vazia pois
            "all".split(",") → ["all"] que não passa em isdigit().
            Fix: mapear "all" e "top1000" para PORT_GROUPS["top100"] no fallback,
            já que varredura de 65535 portas via socket puro é inviável.
"""

import subprocess
import shutil
import socket
import json
from typing import Optional

# Mapeamento de portas comuns para contexto
COMMON_PORTS_CONTEXT = {
    21:   {"service": "FTP",          "risk": "high",   "note": "FTP não criptografado"},
    22:   {"service": "SSH",          "risk": "low",    "note": "Acesso remoto seguro"},
    23:   {"service": "Telnet",       "risk": "critical","note": "Telnet não criptografado — crítico"},
    25:   {"service": "SMTP",         "risk": "medium", "note": "Servidor de email"},
    53:   {"service": "DNS",          "risk": "medium", "note": "Servidor DNS exposto"},
    80:   {"service": "HTTP",         "risk": "info",   "note": "Web não criptografada"},
    110:  {"service": "POP3",         "risk": "medium", "note": "Email não criptografado"},
    143:  {"service": "IMAP",         "risk": "medium", "note": "Email não criptografado"},
    443:  {"service": "HTTPS",        "risk": "info",   "note": "Web criptografada"},
    445:  {"service": "SMB",          "risk": "critical","note": "Compartilhamento Windows — não expor"},
    1433: {"service": "MSSQL",        "risk": "critical","note": "Banco de dados exposto"},
    1521: {"service": "Oracle DB",    "risk": "critical","note": "Banco de dados exposto"},
    2222: {"service": "SSH alt",      "risk": "medium", "note": "SSH em porta alternativa"},
    3306: {"service": "MySQL",        "risk": "critical","note": "Banco de dados exposto"},
    3389: {"service": "RDP",          "risk": "high",   "note": "Área de trabalho remota Windows"},
    5432: {"service": "PostgreSQL",   "risk": "critical","note": "Banco de dados exposto"},
    5900: {"service": "VNC",          "risk": "high",   "note": "Controle remoto de desktop"},
    6379: {"service": "Redis",        "risk": "critical","note": "Cache sem auth frequentemente"},
    8080: {"service": "HTTP-alt",     "risk": "medium", "note": "Web alternativa — comum em dev"},
    8443: {"service": "HTTPS-alt",    "risk": "low",    "note": "HTTPS alternativo"},
    8888: {"service": "HTTP-dev",     "risk": "medium", "note": "Jupyter / serviços dev"},
    9200: {"service": "Elasticsearch","risk": "critical","note": "Banco NoSQL — frequentemente aberto"},
    27017:{"service": "MongoDB",      "risk": "critical","note": "Banco NoSQL exposto"},
}

PORT_GROUPS = {
    "top100":  [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
                1723,3306,3389,5900,8080,8443,8888,9200,27017,6379,
                1433,1521,5432,2049,2121,3000,3001,4000,4443,4848,
                5000,5001,5005,5050,5555,6000,6001,7000,7001,7002,
                7070,7443,7777,8000,8001,8008,8009,8010,8081,8082,
                8083,8085,8088,8090,8091,8161,8180,8181,8222,8333,
                8334,8400,8444,8480,8500,8585,8600,8787,8800,8880,
                8983,9000,9001,9043,9060,9080,9090,9091,9100,9200,
                9300,9443,9800,9981,10000,10243,49152,49153],
    "top1000": None,  # Deixa nmap decidir com --top-ports 1000
}


def _parse_nmap_xml(xml_output: str) -> list:
    """Parse simples de XML do nmap."""
    import xml.etree.ElementTree as ET
    ports = []
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            for port_elem in host.findall(".//port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue
                port_id = int(port_elem.get("portid", 0))
                service_elem = port_elem.find("service")
                service_name    = service_elem.get("name", "") if service_elem is not None else ""
                service_product = service_elem.get("product", "") if service_elem is not None else ""
                service_version = service_elem.get("version", "") if service_elem is not None else ""
                service_extra   = service_elem.get("extrainfo", "") if service_elem is not None else ""

                ctx = COMMON_PORTS_CONTEXT.get(port_id, {})
                ports.append({
                    "port":     port_id,
                    "protocol": port_elem.get("protocol", "tcp"),
                    "state":    "open",
                    "service":  service_name or ctx.get("service", "unknown"),
                    "product":  service_product,
                    "version":  service_version,
                    "extra":    service_extra,
                    "risk":     ctx.get("risk", "info"),
                    "note":     ctx.get("note", ""),
                })
    except ET.ParseError:
        pass
    return ports


def nmap_scan(target: str, port_spec: str, timeout: int = 30) -> Optional[list]:
    """Executa nmap e retorna lista de portas abertas."""
    if not shutil.which("nmap"):
        return None

    # Monta argumentos
    cmd = ["nmap", "-sV", "--version-intensity", "5", "-oX", "-"]

    if port_spec == "top100":
        ports_list = PORT_GROUPS["top100"]
        cmd += ["-p", ",".join(map(str, ports_list))]
    elif port_spec == "top1000":
        cmd += ["--top-ports", "1000"]
    elif port_spec == "all":
        cmd += ["-p-"]
    else:
        cmd += ["-p", port_spec]

    cmd += ["--open", "-T4", "--host-timeout", f"{timeout}s", target]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
        if proc.returncode == 0:
            return _parse_nmap_xml(proc.stdout)
        return None
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def socket_scan(target: str, ports: list, timeout: int = 2) -> list:
    """Fallback: scan básico via socket quando nmap não está disponível."""
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                ctx = COMMON_PORTS_CONTEXT.get(port, {})
                # Tenta banner grab apenas em portas HTTP-like
                banner = ""
                try:
                    if port in (80, 8080, 8000, 8008, 8081, 8888):
                        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s.recv(256).decode(errors="ignore").strip()[:100]
                except Exception:
                    pass
                open_ports.append({
                    "port":    port,
                    "protocol":"tcp",
                    "state":   "open",
                    "service": ctx.get("service", "unknown"),
                    "product": "",
                    "version": "",
                    "banner":  banner,
                    "risk":    ctx.get("risk", "info"),
                    "note":    ctx.get("note", ""),
                })
            s.close()
        except Exception:
            pass
    return open_ports


def _resolve_ports_for_socket_fallback(port_spec: str) -> list:
    """
    CORREÇÃO Bug 2: resolve a lista de portas para o fallback socket.

    Antes: port_spec="all" ou "top1000" sem nmap caía no else e tentava
    fazer "all".split(",") → ["all"] → isdigit() False → lista vazia,
    causando scan silenciosamente vazio.

    Fix: mapear "all" e "top1000" para top100 no fallback (varredura de
    65535 portas via socket puro levaria horas e não é viável). Emite
    aviso no resultado sobre a limitação.
    """
    if port_spec in ("top100", "top1000", "all"):
        return PORT_GROUPS["top100"]
    # Lista manual: "80,443,8080"
    return [int(p) for p in port_spec.split(",") if p.strip().isdigit()]


def scan_ports(target: str, port_spec: str = "top100", timeout: int = 30) -> dict:
    """Ponto de entrada principal do módulo."""
    result = {
        "target":    target,
        "port_spec": port_spec,
        "method":    None,
        "open_ports":[],
        "summary":   {},
        "risk_flags":[],
    }

    # Tenta nmap primeiro
    nmap_result = nmap_scan(target, port_spec, timeout)

    if nmap_result is not None:
        result["method"]     = "nmap"
        result["open_ports"] = nmap_result
    else:
        # Fallback socket — CORRIGIDO: resolve portas corretamente para qualquer port_spec
        ports_to_scan = _resolve_ports_for_socket_fallback(port_spec)
        result["method"] = "socket (nmap não encontrado)"
        if port_spec in ("top1000", "all"):
            result["method"] += f" — limitado a top100 (nmap ausente, port_spec={port_spec} inviável via socket)"
        result["open_ports"] = socket_scan(target, ports_to_scan, timeout=2)

    # Sumário por risco
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for p in result["open_ports"]:
        risk_counts[p.get("risk", "info")] = risk_counts.get(p.get("risk", "info"), 0) + 1

    result["summary"] = {
        "total_open":  len(result["open_ports"]),
        "risk_counts": risk_counts,
    }

    # Risk flags
    critical_ports = [p for p in result["open_ports"] if p.get("risk") == "critical"]
    if critical_ports:
        names = [f"{p['port']}/{p['service']}" for p in critical_ports]
        result["risk_flags"].append(f"Portas críticas expostas: {', '.join(names)}")

    return result
