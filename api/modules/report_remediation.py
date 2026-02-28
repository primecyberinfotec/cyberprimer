"""
Gerador de Relatório de REMEDIAÇÃO (pós-contrato)
Passo a passo técnico de como corrigir cada problema encontrado
"""

from datetime import datetime
from pathlib import Path


# Base de conhecimento de remediações por categoria
REMEDIATION_KB = {
    "redis": {
        "title": "Proteger Redis contra acesso não autorizado",
        "effort": "Baixo — 30 min",
        "steps": [
            ("Habilitar autenticação", "Edite <code>/etc/redis/redis.conf</code> e adicione: <code>requirepass SUA_SENHA_FORTE_AQUI</code>"),
            ("Bloquear acesso externo", "No mesmo arquivo: <code>bind 127.0.0.1</code> — isso faz o Redis aceitar apenas conexões locais"),
            ("Firewall", "Bloqueie a porta 6379 externamente: <code>ufw deny 6379</code> ou configure no painel do provedor"),
            ("Reiniciar o serviço", "<code>sudo systemctl restart redis</code>"),
            ("Validar", "Tente conectar externamente: <code>redis-cli -h SEU_IP ping</code> — deve retornar erro"),
        ]
    },
    "mongodb": {
        "title": "Proteger MongoDB contra acesso não autorizado",
        "effort": "Baixo — 45 min",
        "steps": [
            ("Habilitar autenticação", "Edite <code>/etc/mongod.conf</code> e adicione em security: <code>authorization: enabled</code>"),
            ("Criar usuário admin", "No mongo shell: <code>db.createUser({{user:'admin', pwd:'SENHA_FORTE', roles:['root']}})</code>"),
            ("Bind address", "No mongod.conf: <code>bindIp: 127.0.0.1</code>"),
            ("Firewall", "Bloqueie porta 27017: <code>ufw deny 27017</code>"),
            ("Reiniciar", "<code>sudo systemctl restart mongod</code>"),
        ]
    },
    "elasticsearch": {
        "title": "Proteger Elasticsearch contra acesso público",
        "effort": "Médio — 1h",
        "steps": [
            ("Habilitar segurança", "Em <code>elasticsearch.yml</code>: <code>xpack.security.enabled: true</code>"),
            ("Configurar TLS", "Gere certificados e configure <code>xpack.security.transport.ssl.enabled: true</code>"),
            ("Bind local", "<code>network.host: 127.0.0.1</code> em elasticsearch.yml"),
            ("Firewall", "Bloqueie portas 9200 e 9300 externamente"),
            ("Criar senhas", "Execute: <code>bin/elasticsearch-setup-passwords auto</code>"),
        ]
    },
    "mysql": {
        "title": "Remover acesso externo ao MySQL",
        "effort": "Baixo — 20 min",
        "steps": [
            ("Remover usuários remotos", "No MySQL: <code>DELETE FROM mysql.user WHERE Host != 'localhost';</code> depois <code>FLUSH PRIVILEGES;</code>"),
            ("Bind local", "Em <code>/etc/mysql/mysql.conf.d/mysqld.cnf</code>: <code>bind-address = 127.0.0.1</code>"),
            ("Firewall", "Bloqueie porta 3306: <code>ufw deny 3306</code>"),
            ("Reiniciar", "<code>sudo systemctl restart mysql</code>"),
        ]
    },
    "ftp": {
        "title": "Substituir FTP por SFTP (SSH)",
        "effort": "Médio — 2h",
        "steps": [
            ("Instalar SFTP", "O SFTP vem com o OpenSSH — verifique: <code>which sftp-server</code>"),
            ("Configurar chroot", "Em <code>/etc/ssh/sshd_config</code> adicione Subsystem sftp com ChrootDirectory"),
            ("Criar usuário SFTP", "Crie usuário sem shell: <code>useradd -s /sbin/nologin sftp_user</code>"),
            ("Desabilitar FTP", "<code>sudo systemctl disable vsftpd && systemctl stop vsftpd</code>"),
            ("Fechar porta 21", "<code>ufw deny 21</code>"),
        ]
    },
    "telnet": {
        "title": "Desabilitar Telnet e habilitar SSH",
        "effort": "Baixo — 15 min",
        "steps": [
            ("Desabilitar Telnet", "<code>sudo systemctl disable telnet && systemctl stop telnet</code>"),
            ("Garantir SSH ativo", "<code>sudo systemctl enable ssh && systemctl start ssh</code>"),
            ("Fechar porta 23", "<code>ufw deny 23</code>"),
            ("Testar SSH", "Conecte via <code>ssh usuario@servidor</code> antes de fechar a sessão Telnet"),
        ]
    },
    "smb": {
        "title": "Isolar SMB da internet pública",
        "effort": "Baixo — 20 min",
        "steps": [
            ("Bloquear no firewall", "<code>ufw deny 445 && ufw deny 139</code>"),
            ("Usar VPN para acesso remoto", "Configure WireGuard ou OpenVPN para acessar compartilhamentos SMB internamente"),
            ("Atualizar Windows", "Aplique todos os patches de segurança — especialmente MS17-010 (EternalBlue)"),
            ("Desabilitar SMBv1", "No PowerShell: <code>Set-SmbServerConfiguration -EnableSMB1Protocol $false</code>"),
        ]
    },
    "rdp": {
        "title": "Proteger acesso RDP",
        "effort": "Médio — 1h",
        "steps": [
            ("Mover para porta alternativa", "Altere a porta RDP no registro: <code>HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\PortNumber</code>"),
            ("Habilitar NLA", "Exija autenticação de nível de rede (Network Level Authentication) nas configurações de Área de Trabalho Remota"),
            ("Usar VPN", "Bloqueie a porta RDP na internet e acesse apenas via VPN"),
            ("Habilitar MFA", "Configure autenticação de dois fatores com Windows Hello ou solução de MFA"),
            ("Limitar IPs", "No firewall, permita RDP apenas de IPs conhecidos"),
        ]
    },
    "hsts": {
        "title": "Adicionar cabeçalho HSTS (força HTTPS)",
        "effort": "Baixíssimo — 5 min",
        "nginx": "Adicione no bloco server do nginx:<br><code>add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;</code>",
        "apache": "Adicione no VirtualHost:<br><code>Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"</code>",
        "steps": [
            ("Nginx", "Adicione <code>add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;</code> no bloco server"),
            ("Apache", "Habilite mod_headers: <code>a2enmod headers</code> e adicione o Header no VirtualHost"),
            ("Reiniciar servidor web", "<code>sudo systemctl reload nginx</code> ou <code>sudo systemctl reload apache2</code>"),
            ("Validar", "Use: <code>curl -I https://seusite.com | grep Strict</code>"),
        ]
    },
    "csp": {
        "title": "Implementar Content Security Policy (CSP)",
        "effort": "Médio — 2-4h",
        "steps": [
            ("Política inicial permissiva", "Comece com: <code>Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline';</code>"),
            ("Testar com report-only", "Use <code>Content-Security-Policy-Report-Only</code> primeiro para não quebrar o site"),
            ("Eliminar inline scripts", "Mova scripts inline para arquivos .js externos"),
            ("Apertar a política", "Remova 'unsafe-inline' e use nonces ou hashes para scripts necessários"),
            ("Validar", "Use https://csp-evaluator.withgoogle.com para revisar a política"),
        ]
    },
    "spf": {
        "title": "Configurar SPF para prevenir spoofing de email",
        "effort": "Baixíssimo — 10 min",
        "steps": [
            ("Identificar servidores de envio", "Liste todos os servidores que enviam email pelo seu domínio (hosting, marketing, suporte)"),
            ("Criar registro TXT", "No DNS, crie um registro TXT para o domínio raiz:<br><code>v=spf1 include:_spf.seuservidor.com ~all</code>"),
            ("Política -all", "Prefira <code>-all</code> (rejeitar) ao invés de <code>~all</code> (softfail) para máxima proteção"),
            ("Validar", "Use: <code>dig TXT seudominio.com</code> ou https://mxtoolbox.com/spf.aspx"),
        ]
    },
    "dmarc": {
        "title": "Configurar DMARC para proteção anti-phishing",
        "effort": "Baixo — 30 min",
        "steps": [
            ("Criar registro DMARC", "No DNS, crie um TXT para <code>_dmarc.seudominio.com</code>:<br><code>v=DMARC1; p=none; rua=mailto:dmarc@seudominio.com</code>"),
            ("Monitorar relatórios", "Com p=none você recebe relatórios sem bloquear nada — analise por 2 semanas"),
            ("Aumentar para quarantine", "Após validar: <code>p=quarantine; pct=25</code> (25% dos emails suspeitos vão para spam)"),
            ("Chegar em reject", "Meta final: <code>p=reject</code> — rejeita 100% dos emails não autorizados"),
            ("Validar", "Use https://mxtoolbox.com/dmarc.aspx"),
        ]
    },
    "ssl_expiry": {
        "title": "Renovar / monitorar certificado SSL",
        "effort": "Baixíssimo — 15 min",
        "steps": [
            ("Let's Encrypt (gratuito)", "Instale Certbot: <code>apt install certbot python3-certbot-nginx</code>"),
            ("Obter certificado", "<code>certbot --nginx -d seudominio.com -d www.seudominio.com</code>"),
            ("Renovação automática", "Certbot adiciona automaticamente cron. Verifique: <code>certbot renew --dry-run</code>"),
            ("Monitorar expiração", "Configure alerta em https://uptimerobot.com ou similar para SSL expiry"),
        ]
    },
}


def severity_color(sev):
    return {"critical": "#e74c3c", "high": "#f39c12", "medium": "#d4ac0d", "low": "#27ae60"}.get(sev, "#6b7280")

def severity_bg(sev):
    return {"critical": "#fdf2f2", "high": "#fef9ec", "medium": "#fefce8", "low": "#f0fdf4"}.get(sev, "#f9fafb")

def severity_label(sev):
    return {"critical": "🔴 CRÍTICO", "high": "🟠 ALTO", "medium": "🟡 MÉDIO", "low": "🟢 BAIXO"}.get(sev, sev.upper())


def build_remediation_items(vuln_mod, web_mod, dns_mod, ssl_mod):
    """Monta lista de remediações baseadas nos dados do scan."""
    items = []

    # Portas críticas / vulnerabilidades
    for vuln in vuln_mod.get("critical", []) + vuln_mod.get("high", []):
        title = vuln.get("title", "")
        svc   = vuln.get("cve", "")
        port  = vuln.get("port")
        sev   = vuln.get("severity", "high")

        kb_key = None
        title_lower = title.lower()
        for k in REMEDIATION_KB:
            if k in title_lower or (port and str(port) in title_lower):
                kb_key = k
                break

        if kb_key and kb_key in REMEDIATION_KB:
            kb = REMEDIATION_KB[kb_key]
            items.append({"severity": sev, "port": port, "cve": svc, "title": kb["title"], "effort": kb.get("effort", "Variável"), "steps": kb["steps"]})
        else:
            items.append({"severity": sev, "port": port, "cve": svc, "title": title, "effort": "Consulte documentação", "steps": [("Investigar", vuln.get("desc", "Verifique o CVE informado e aplique o patch do fabricante")), ("Atualizar software", "Verifique a versão atual e atualize para a mais recente"), ("Validar", "Após atualização, verifique se a vulnerabilidade foi corrigida")]})

    # Cabeçalhos HTTP faltando
    missing_headers = web_mod.get("security_headers", {}).get("missing", {})
    for header, info in missing_headers.items():
        risk = info.get("risk", "low")
        kb_key = "hsts" if "Strict" in header else "csp" if "Content-Security" in header else None
        if kb_key and kb_key in REMEDIATION_KB:
            kb = REMEDIATION_KB[kb_key]
            items.append({"severity": risk, "port": 80, "cve": "Config", "title": kb["title"], "effort": kb.get("effort", "Baixo"), "steps": kb["steps"]})
        else:
            items.append({"severity": risk, "port": 80, "cve": "Config", "title": f"Adicionar cabeçalho: {header}", "effort": "Baixíssimo — 5 min", "steps": [("Adicionar ao servidor web", f"{info.get('recommendation','Consulte a documentação do servidor web')}"),(  "Reiniciar servidor", "<code>sudo systemctl reload nginx</code> ou <code>sudo systemctl reload apache2</code>"), ("Validar", f"<code>curl -I https://seusite.com | grep {header.split('-')[0]}</code>")]})

    # SPF/DMARC
    if not dns_mod.get("spf", {}).get("exists"):
        kb = REMEDIATION_KB["spf"]
        items.append({"severity": "high", "port": None, "cve": "DNS", "title": kb["title"], "effort": kb["effort"], "steps": kb["steps"]})
    if not dns_mod.get("dmarc", {}).get("exists"):
        kb = REMEDIATION_KB["dmarc"]
        items.append({"severity": "high", "port": None, "cve": "DNS", "title": kb["title"], "effort": kb["effort"], "steps": kb["steps"]})

    # SSL expirando
    cert = ssl_mod.get("certificate", {})
    if cert.get("expired") or cert.get("expiring_soon"):
        kb = REMEDIATION_KB["ssl_expiry"]
        items.append({"severity": "high", "port": 443, "cve": "SSL", "title": kb["title"], "effort": kb["effort"], "steps": kb["steps"]})

    # Ordena por severidade
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    items.sort(key=lambda x: order.get(x["severity"], 4))
    return items


def remediation_card(item, idx):
    sev   = item["severity"]
    color = severity_color(sev)
    bg    = severity_bg(sev)
    steps_html = "".join(f"""
        <div class="step">
          <div class="step-num">{i+1}</div>
          <div class="step-body">
            <div class="step-title">{title}</div>
            <div class="step-desc">{desc}</div>
          </div>
        </div>""" for i, (title, desc) in enumerate(item["steps"]))

    port_badge = f'<span class="port-badge">:{item["port"]}</span>' if item.get("port") else ""
    cve_badge  = f'<span class="cve-badge">{item["cve"]}</span>' if item.get("cve") and item["cve"] != "Config" and item["cve"] != "DNS" and item["cve"] != "SSL" else ""

    return f"""
    <div class="rem-card" style="border-left:4px solid {color};background:{bg};">
      <div class="rem-header">
        <div class="rem-num" style="background:{color}">{idx}</div>
        <div class="rem-info">
          <div class="rem-sev" style="color:{color}">{severity_label(sev)}</div>
          <div class="rem-title">{item['title']} {port_badge} {cve_badge}</div>
        </div>
        <div class="rem-effort">⏱️ {item['effort']}</div>
      </div>
      <div class="rem-steps">{steps_html}</div>
    </div>"""


def generate_remediation_report(data: dict, output_path: str,
                                 company_name: str = "Cyber Primer Infortech",
                                 analyst_name: str = "Wilker Santana Damazio — CEO",
                                 client_name: str = "Cliente"):
    target    = data.get("target", "")
    scan_date = data.get("scan_date", "")
    mods      = data.get("modules", {})

    dns_mod  = mods.get("dns_enum", {})
    ssl_mod  = mods.get("ssl", {})
    web_mod  = mods.get("web_info", {})
    vuln_mod = mods.get("vulnerabilities", {})

    n_crit = len(vuln_mod.get("critical", []))
    n_high = len(vuln_mod.get("high", []))
    n_med  = len(vuln_mod.get("medium", []))
    n_low  = len(vuln_mod.get("low", []))

    items    = build_remediation_items(vuln_mod, web_mod, dns_mod, ssl_mod)
    date_fmt = datetime.fromisoformat(scan_date).strftime('%d/%m/%Y') if scan_date else datetime.now().strftime('%d/%m/%Y')

    n_items_crit = len([i for i in items if i["severity"]=="critical"])
    n_items_high = len([i for i in items if i["severity"]=="high"])
    n_items_med  = len([i for i in items if i["severity"]=="medium"])
    n_items_low  = len([i for i in items if i["severity"]=="low"])

    cards_html = "".join(remediation_card(item, idx+1) for idx, item in enumerate(items))
    if not cards_html:
        cards_html = '<div style="text-align:center;padding:40px;color:#6b7280;">✅ Nenhuma remediação crítica identificada neste scan.</div>'

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Plano de Remediação — {target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Inter',sans-serif;background:#f5f6fa;color:#1a1a2e;line-height:1.6}}
  code{{background:#e8eaf0;padding:2px 6px;border-radius:4px;font-family:'SF Mono','Cascadia Code',monospace;font-size:12px;color:#c0392b}}
  .page{{max-width:900px;margin:0 auto;background:white;box-shadow:0 4px 40px rgba(0,0,0,.1)}}

  /* HEADER */
  .header{{background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460);color:white;padding:48px;position:relative;overflow:hidden}}
  .header::before{{content:'';position:absolute;top:-40px;right:-40px;width:250px;height:250px;background:rgba(99,102,241,.12);border-radius:50%}}
  .badge{{display:inline-flex;align-items:center;gap:6px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2);border-radius:20px;padding:4px 14px;font-size:11px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;margin-bottom:24px}}
  .header h1{{font-size:11px;text-transform:uppercase;letter-spacing:2px;color:rgba(255,255,255,.5);margin-bottom:8px}}
  .header h2{{font-size:28px;font-weight:800;margin-bottom:6px}}
  .header .target{{font-size:14px;color:rgba(255,255,255,.6);font-family:monospace;margin-bottom:24px}}
  .header-meta{{display:flex;gap:24px;flex-wrap:wrap}}
  .meta-item{{font-size:12px;color:rgba(255,255,255,.5)}}
  .meta-item strong{{color:white;display:block;font-size:13px;margin-top:2px}}
  .confidential{{position:absolute;top:20px;right:48px;background:rgba(231,76,60,.2);border:1px solid rgba(231,76,60,.4);color:#ff8a80;font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;padding:4px 12px;border-radius:4px}}

  /* SUMMARY */
  .summary{{background:#1a1a2e;color:white;padding:28px 48px;display:flex;gap:32px;flex-wrap:wrap;align-items:center}}
  .sum-title{{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,.45);margin-bottom:12px;width:100%}}
  .sum-stat{{text-align:center}}
  .sum-stat .n{{font-size:32px;font-weight:900;line-height:1}}
  .sum-stat .l{{font-size:11px;color:rgba(255,255,255,.45);margin-top:4px;text-transform:uppercase;letter-spacing:.5px}}

  /* INTRO BOX */
  .intro{{padding:32px 48px;background:#fafbfc;border-bottom:1px solid #e5e7eb}}
  .intro h3{{font-size:16px;font-weight:700;margin-bottom:10px}}
  .intro p{{font-size:14px;color:#4b5563;line-height:1.8}}
  .priority-guide{{display:flex;gap:12px;margin-top:20px;flex-wrap:wrap}}
  .pg-item{{flex:1;min-width:120px;border-radius:8px;padding:12px;text-align:center}}
  .pg-item .pg-n{{font-size:22px;font-weight:900}}
  .pg-item .pg-l{{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:2px}}
  .pg-item .pg-d{{font-size:11px;color:#6b7280;margin-top:4px}}

  /* REMEDIATION CARDS */
  .cards-section{{padding:32px 48px}}
  .section-title{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;color:#6b7280;margin-bottom:20px;display:flex;align-items:center;gap:8px}}
  .section-title::after{{content:'';flex:1;height:1px;background:#e5e7eb}}

  .rem-card{{border-radius:10px;margin-bottom:16px;overflow:hidden}}
  .rem-header{{display:flex;align-items:flex-start;gap:14px;padding:16px 20px;}}
  .rem-num{{width:28px;height:28px;border-radius:50%;color:white;font-size:12px;font-weight:800;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:2px}}
  .rem-info{{flex:1}}
  .rem-sev{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}}
  .rem-title{{font-size:15px;font-weight:700;color:#1a1a2e;display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
  .rem-effort{{font-size:12px;color:#6b7280;white-space:nowrap;padding-top:2px}}
  .port-badge{{background:#1a1a2e;color:white;font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;font-family:monospace}}
  .cve-badge{{background:#fff3cd;color:#856404;border:1px solid #ffc107;font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px}}

  .rem-steps{{padding:0 20px 16px 20px}}
  .step{{display:flex;gap:12px;margin-bottom:10px}}
  .step-num{{width:22px;height:22px;border-radius:50%;background:#e5e7eb;color:#6b7280;font-size:11px;font-weight:800;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:2px}}
  .step-body{{flex:1}}
  .step-title{{font-size:13px;font-weight:700;color:#374151;margin-bottom:3px}}
  .step-desc{{font-size:13px;color:#4b5563;line-height:1.6}}

  /* FOOTER -->*/
  .footer-section{{background:#1a1a2e;color:white;padding:36px 48px}}
  .footer-section h3{{font-size:16px;font-weight:700;margin-bottom:12px}}
  .footer-section p{{font-size:13px;color:rgba(255,255,255,.6);line-height:1.8;margin-bottom:8px}}
  .footer-bar{{background:#0d0d1a;color:rgba(255,255,255,.3);text-align:center;padding:16px;font-size:11px}}

  @media(max-width:600px){{.header,.cards-section,.intro,.footer-section{{padding:24px 20px}}.summary{{padding:20px}}.confidential{{display:none}}}}
</style>
</head>
<body><div class="page">

<!-- HEADER -->
<div class="header">
  <div class="confidential">CONFIDENCIAL</div>
  <div class="badge">🔧 {company_name}</div>
  <h1>Plano de Remediação de Segurança</h1>
  <h2>Correções Priorizadas por Risco</h2>
  <div class="target">🎯 <a href="https://{target}" target="_blank" rel="noopener" style="color:inherit;text-decoration:underline;text-decoration-color:rgba(255,255,255,.4);">{target} ↗</a></div>
  <div class="header-meta">
    <div class="meta-item">Data do Scan<strong>{date_fmt}</strong></div>
    <div class="meta-item">Responsável Técnico<strong>{analyst_name}</strong></div>
    <div class="meta-item">Cliente<strong>{client_name}</strong></div>
    <div class="meta-item">Total de Correções<strong>{len(items)} itens</strong></div>
  </div>
</div>

<!-- SUMMARY BAR -->
<div class="summary">
  <div class="sum-title">Vulnerabilidades por severidade</div>
  <div class="sum-stat"><div class="n" style="color:#e74c3c">{n_crit}</div><div class="l">Crítico</div></div>
  <div class="sum-stat"><div class="n" style="color:#f39c12">{n_high}</div><div class="l">Alto</div></div>
  <div class="sum-stat"><div class="n" style="color:#d4ac0d">{n_med}</div><div class="l">Médio</div></div>
  <div class="sum-stat"><div class="n" style="color:#27ae60">{n_low}</div><div class="l">Baixo</div></div>
  <div class="sum-stat" style="margin-left:auto"><div class="n" style="color:white">{len(items)}</div><div class="l">Correções</div></div>
</div>

<!-- INTRO -->
<div class="intro">
  <h3>📋 Como usar este plano</h3>
  <p>As correções estão ordenadas por <strong>prioridade de risco</strong>. Recomendamos iniciar pelas críticas e altas imediatamente. As médias e baixas podem ser planejadas para as próximas semanas. Cada item contém o passo a passo completo para a correção.</p>
  <div class="priority-guide">
    <div class="pg-item" style="background:#fdf2f2"><div class="pg-n" style="color:#e74c3c">{n_items_crit}</div><div class="pg-l" style="color:#e74c3c">Críticas</div><div class="pg-d">Corrigir hoje</div></div>
    <div class="pg-item" style="background:#fef9ec"><div class="pg-n" style="color:#f39c12">{n_items_high}</div><div class="pg-l" style="color:#f39c12">Altas</div><div class="pg-d">Esta semana</div></div>
    <div class="pg-item" style="background:#fefce8"><div class="pg-n" style="color:#d4ac0d">{n_items_med}</div><div class="pg-l" style="color:#d4ac0d">Médias</div><div class="pg-d">Este mês</div></div>
    <div class="pg-item" style="background:#f0fdf4"><div class="pg-n" style="color:#27ae60">{n_items_low}</div><div class="pg-l" style="color:#27ae60">Baixas</div><div class="pg-d">Próximo ciclo</div></div>
  </div>
</div>

<!-- CARDS -->
<div class="cards-section">
  <div class="section-title">🔧 Plano de Correção Detalhado</div>
  {cards_html}
</div>

<!-- FOOTER SECTION -->
<div class="footer-section">
  <h3>📞 Suporte na Implementação</h3>
  <p>Caso sua equipe precise de auxílio na execução de qualquer uma das correções listadas neste documento, nossa equipe técnica está disponível para suporte presencial ou remoto.</p>
  <p>Após a implementação, recomendamos um <strong>scan de verificação</strong> para confirmar que todas as correções foram aplicadas corretamente e nenhuma nova exposição foi introduzida.</p>
  <p style="margin-top:16px">📧 <strong>primecyberinfotec@gmail.com</strong> &nbsp;|&nbsp; 🌐 <strong>primecyberinfotec.github.io/cyberprimer</strong></p>
</div>

<div class="footer-bar">
  Cyber Primer Infortech · CNPJ 51.698.369/0001-50 · Barra do Garças — MT — Brasil · {date_fmt} · Documento confidencial · Uso exclusivo de {client_name}
</div>

</div></body></html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)