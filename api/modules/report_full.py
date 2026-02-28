"""
Gerador de Relatório COMPLETO
Inclui todos os detalhes técnicos + Guia de Correção passo a passo
"""

from datetime import datetime
from pathlib import Path


def _rc(level):
    return {"critical":"#FF3B30","high":"#FF9500","medium":"#FFCC00","low":"#34C759","info":"#636366"}.get(level,"#636366")

def _badge(level):
    labels = {"critical":"🔴 CRÍTICO","high":"🟠 ALTO","medium":"🟡 MÉDIO","low":"🟢 BAIXO","info":"🔵 INFO"}
    c = _rc(level)
    return f'<span style="background:{c}22;color:{c};border:1px solid {c}55;border-radius:6px;padding:2px 10px;font-size:11px;font-weight:700;">{labels.get(level,level.upper())}</span>'

def _score(vuln_mod, headers_pct, dns_mod=None, ssl_mod=None, osint_mod=None):
    """FIX Bug 6: score com penalidades completas, alinhado com report_preview.py."""
    n = {
        "critical": len(vuln_mod.get("critical", [])),
        "high":     len(vuln_mod.get("high",     [])),
        "medium":   len(vuln_mod.get("medium",   [])),
        "low":      len(vuln_mod.get("low",      [])),
    }
    penalty  = 0
    penalty += min(n["critical"] * 25, 50)
    penalty += min(n["high"]     * 10, 30)
    penalty += min(n["medium"]   *  5, 20)
    penalty += min(n["low"]      *  2, 10)
    if dns_mod:
        if not dns_mod.get("spf",   {}).get("exists", True): penalty += 8
        if not dns_mod.get("dmarc", {}).get("exists", True): penalty += 8
    if headers_pct < 50:   penalty += 10
    elif headers_pct < 70: penalty += 6
    elif headers_pct < 80: penalty += 3
    if ssl_mod:
        cert = ssl_mod.get("certificate", {})
        if cert.get("expired"):           penalty += 20
        elif cert.get("expiring_soon"):   penalty += 10
    if osint_mod:
        breach_cnt = osint_mod.get("hibp", {}).get("count", 0)
        penalty += min(breach_cnt * 10, 20)
    return max(0, min(100, round(100 - penalty))), n


# ── GUIAS DE CORREÇÃO ────────────────────────────────────────────────────────
REMEDIATION = {
    "DMARC ausente": {
        "title": "Configurar política DMARC",
        "risk":  "high",
        "why":   "Sem DMARC, qualquer pessoa pode enviar e-mails se passando pelo seu domínio (phishing).",
        "steps": [
            "Acesse o painel do seu provedor de DNS (ex: Cloudflare, Registro.br, GoDaddy).",
            "Crie um registro TXT para o subdomínio <code>_dmarc.seudominio.com.br</code>.",
            "Valor inicial (monitoramento): <code>v=DMARC1; p=none; rua=mailto:dmarc@seudominio.com.br</code>",
            "Após 2 semanas analisando os relatórios, mude para <code>p=quarantine</code>.",
            "Quando estiver seguro, use <code>p=reject</code> para máxima proteção.",
        ],
        "effort": "30 min", "cost": "Gratuito"
    },
    "SPF ausente": {
        "title": "Configurar registro SPF",
        "risk":  "high",
        "why":   "Sem SPF, servidores de e-mail não conseguem verificar se o remetente é legítimo.",
        "steps": [
            "Acesse o painel DNS do seu domínio.",
            "Crie um registro TXT na raiz do domínio (<code>@</code>).",
            "Valor: <code>v=spf1 include:_spf.google.com ~all</code> (ajuste para seu provedor de e-mail).",
            "Para Locaweb: <code>v=spf1 include:spf.locaweb.com.br ~all</code>",
            "Para Office 365: <code>v=spf1 include:spf.protection.outlook.com ~all</code>",
            "Troque <code>~all</code> por <code>-all</code> para política mais rígida após testar.",
        ],
        "effort": "15 min", "cost": "Gratuito"
    },
    "HSTS ausente": {
        "title": "Habilitar HSTS (Strict-Transport-Security)",
        "risk":  "high",
        "why":   "Sem HSTS, um atacante pode forçar o navegador a usar HTTP e interceptar dados.",
        "steps": [
            "<strong>Apache:</strong> Adicione no .htaccess ou httpd.conf:<br><code>Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"</code>",
            "<strong>Nginx:</strong> Adicione no bloco <code>server</code>:<br><code>add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;</code>",
            "<strong>Cloudflare:</strong> Vá em SSL/TLS → Edge Certificates → Enable HSTS.",
            "<strong>WordPress:</strong> Adicione ao functions.php ou via plugin de segurança (Wordfence, iThemes).",
            "Teste em: <a href='https://securityheaders.com' target='_blank'>securityheaders.com</a>",
        ],
        "effort": "20 min", "cost": "Gratuito"
    },
    "CSP ausente": {
        "title": "Implementar Content Security Policy (CSP)",
        "risk":  "high",
        "why":   "Sem CSP, ataques XSS podem injetar scripts maliciosos no seu site.",
        "steps": [
            "Comece com política permissiva para não quebrar o site:<br><code>Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';</code>",
            "Adicione como cabeçalho HTTP no servidor (mesmo procedimento do HSTS).",
            "Teste a política sem bloquear usando <code>Content-Security-Policy-Report-Only</code>.",
            "Use a ferramenta: <a href='https://csp-evaluator.withgoogle.com' target='_blank'>CSP Evaluator do Google</a>",
            "Vá tornando a política mais restritiva gradualmente.",
        ],
        "effort": "1-2h", "cost": "Gratuito"
    },
    "Redis exposto": {
        "title": "Proteger Redis exposto",
        "risk":  "critical",
        "why":   "Redis sem senha em porta pública permite acesso total ao cache — pode expor dados ou ser usado para RCE.",
        "steps": [
            "Bloqueie a porta 6379 no firewall imediatamente: <code>ufw deny 6379</code> (Linux) ou regra no painel do servidor.",
            "Adicione senha no redis.conf: <code>requirepass SUA_SENHA_FORTE_AQUI</code>",
            "Bind apenas para localhost: <code>bind 127.0.0.1</code> no redis.conf",
            "Reinicie o Redis: <code>systemctl restart redis</code>",
            "Se precisar acesso externo, use túnel SSH ou VPN — nunca exponha direto.",
        ],
        "effort": "30 min", "cost": "Gratuito"
    },
    "MySQL exposto": {
        "title": "Fechar acesso externo ao MySQL",
        "risk":  "critical",
        "why":   "MySQL acessível externamente é alvo de brute-force e pode expor todos os dados.",
        "steps": [
            "Bloqueie a porta 3306 no firewall: <code>ufw deny 3306</code>",
            "No MySQL, vincule ao localhost: edite <code>/etc/mysql/mysql.conf.d/mysqld.cnf</code> e adicione <code>bind-address = 127.0.0.1</code>",
            "Remova usuários com acesso externo: <code>SELECT user, host FROM mysql.user;</code> e delete os com host <code>%</code>.",
            "Se precisar de acesso remoto, use tunnel SSH: <code>ssh -L 3306:localhost:3306 usuario@servidor</code>",
            "Reinicie: <code>systemctl restart mysql</code>",
        ],
        "effort": "45 min", "cost": "Gratuito"
    },
    "RDP exposto": {
        "title": "Proteger acesso RDP",
        "risk":  "critical",
        "why":   "RDP exposto é alvo constante de brute-force e exploits como BlueKeep.",
        "steps": [
            "Bloqueie a porta 3389 no firewall para IPs não autorizados.",
            "Use VPN para acesso remoto — nunca exponha RDP diretamente.",
            "Habilite Network Level Authentication (NLA).",
            "Ative autenticação de dois fatores.",
            "Mantenha o Windows atualizado (patches de segurança).",
            "Considere mudar a porta padrão como medida adicional.",
        ],
        "effort": "1-2h", "cost": "Gratuito a R$200/mês (VPN)"
    },
    "SMB exposto": {
        "title": "Fechar porta SMB (445)",
        "risk":  "critical",
        "why":   "SMB exposto foi vetor do ataque WannaCry que paralisou empresas globalmente.",
        "steps": [
            "Bloqueie a porta 445 no firewall imediatamente.",
            "Se possível, desative SMBv1: <code>Set-SmbServerConfiguration -EnableSMB1Protocol $false</code> (PowerShell)",
            "Mantenha o Windows atualizado com todos os patches de segurança.",
            "Jamais exponha SMB à internet — use VPN para compartilhamento remoto.",
        ],
        "effort": "20 min", "cost": "Gratuito"
    },
    "X-Frame-Options ausente": {
        "title": "Adicionar proteção contra Clickjacking",
        "risk":  "medium",
        "why":   "Sem este cabeçalho, atacantes podem incorporar seu site em iframes para enganar usuários.",
        "steps": [
            "<strong>Nginx:</strong> <code>add_header X-Frame-Options \"SAMEORIGIN\" always;</code>",
            "<strong>Apache:</strong> <code>Header always set X-Frame-Options \"SAMEORIGIN\"</code>",
            "<strong>Cloudflare:</strong> Crie uma Page Rule ou use Transform Rules para adicionar o cabeçalho.",
        ],
        "effort": "10 min", "cost": "Gratuito"
    },
    "X-Content-Type-Options ausente": {
        "title": "Adicionar X-Content-Type-Options",
        "risk":  "medium",
        "why":   "Sem este cabeçalho, navegadores podem interpretar arquivos de forma incorreta (MIME sniffing).",
        "steps": [
            "<strong>Nginx:</strong> <code>add_header X-Content-Type-Options \"nosniff\" always;</code>",
            "<strong>Apache:</strong> <code>Header always set X-Content-Type-Options \"nosniff\"</code>",
        ],
        "effort": "5 min", "cost": "Gratuito"
    },
    "Certificado expirando": {
        "title": "Renovar certificado SSL",
        "risk":  "high",
        "why":   "Certificado expirado causa alertas no navegador e quebra a confiança dos usuários.",
        "steps": [
            "<strong>Let's Encrypt (Certbot):</strong> <code>sudo certbot renew</code>",
            "Configure renovação automática: <code>crontab -e</code> → <code>0 12 * * * certbot renew --quiet</code>",
            "<strong>Cloudflare:</strong> Se estiver usando SSL gerenciado, verifique as configurações em SSL/TLS.",
            "<strong>Painel de hospedagem:</strong> Procure a opção de renovar SSL/certificado.",
        ],
        "effort": "15 min", "cost": "Gratuito (Let's Encrypt)"
    },
}


def _remediation_section(all_flags, vuln_mod):
    """Gera a seção de guia de correção com base nos problemas encontrados."""
    rems = []

    # Match flags com guias
    for flag in all_flags:
        for key, guide in REMEDIATION.items():
            if any(kw.lower() in flag.lower() for kw in [key.lower(), guide["title"].lower()[:15]]):
                if guide not in rems:
                    rems.append(guide)

    # Match vulnerabilidades
    for sev in ["critical","high","medium"]:
        for v in vuln_mod.get(sev, []):
            title = (v.get("title") or "").lower()
            for key, guide in REMEDIATION.items():
                if any(kw in title for kw in key.lower().split()):
                    if guide not in rems:
                        rems.append(guide)

    if not rems:
        return "<p style='color:#8e8e93;'>Nenhuma correção prioritária identificada automaticamente.</p>"

    html = ""
    for i, r in enumerate(rems, 1):
        c = _rc(r["risk"])
        steps_html = "".join(f'<li style="margin-bottom:10px;line-height:1.6;">{s}</li>' for s in r["steps"])
        html += f"""
        <div style="border:1px solid #e5e5ea;border-radius:14px;padding:24px;margin-bottom:16px;border-left:4px solid {c};">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap;">
            <span style="background:{c}22;color:{c};border-radius:20px;padding:3px 12px;font-size:12px;font-weight:700;">#{i} PRIORIDADE</span>
            {_badge(r["risk"])}
            <span style="font-size:12px;color:#8e8e93;">⏱ {r["effort"]} · 💰 {r["cost"]}</span>
          </div>
          <h4 style="font-size:16px;font-weight:700;margin-bottom:6px;">{r["title"]}</h4>
          <p style="color:#6e6e73;font-size:13px;margin-bottom:16px;background:#f5f5f7;padding:10px 14px;border-radius:8px;">⚠️ <strong>Por que corrigir:</strong> {r["why"]}</p>
          <ol style="padding-left:20px;color:#1d1d1f;font-size:14px;">
            {steps_html}
          </ol>
        </div>"""
    return html




def _full_scorecard(score, counts, dns_mod, headers_pct, ssl_cert, breach_count, ip_mod, osint_mod):
    """Scorecard completo para report_full: todos os fatores avaliados."""
    n_crit = counts.get("critical", 0); n_high = counts.get("high", 0)
    n_med  = counts.get("medium",  0); n_low  = counts.get("low",  0)
    spf_ok   = dns_mod.get("spf",   {}).get("exists", True)
    dmarc_ok = dns_mod.get("dmarc", {}).get("exists", True)

    def row(category, pts, detail=""):
        if pts < 0:
            badge = '<span style="color:#FF3B30;font-weight:700;">−' + str(abs(pts)) + 'pts</span>'
            bg    = 'background:rgba(255,59,48,.05);'
        else:
            badge = '<span style="color:#34C759;font-weight:700;">✓ OK</span>'
            bg    = ''
        det = (' <span style="color:#6e6e73;font-size:11px;">(' + detail + ')</span>') if detail else ''
        return (
            '<div style="display:flex;justify-content:space-between;align-items:center;'
            'padding:8px 0;border-bottom:1px solid #1d1d1f;">'
            '<span style="font-size:13px;color:#f0f0f5;">' + category + det + '</span>'
            + badge + '</div>'
        )

    cve_pts = -(min(n_crit*25,50)+min(n_high*10,30)+min(n_med*5,20)+min(n_low*2,10))
    cve_det = (str(n_crit)+"C/"+str(n_high)+"A/"+str(n_med)+"M/"+str(n_low)+"B") if cve_pts<0 else "nenhum"

    h_pts = (-10 if headers_pct<50 else -6 if headers_pct<70 else -3 if headers_pct<80 else 0)

    if ssl_cert.get("expired"):         ssl_pts=-20; ssl_det="expirado"
    elif ssl_cert.get("expiring_soon"): ssl_pts=-10; ssl_det=str(ssl_cert.get("days_left","?"))+" dias"
    else:                               ssl_pts=0;   ssl_det=str(ssl_cert.get("days_left","?"))+" dias restantes"

    breach_pts = -min(breach_count*10,20) if breach_count else 0
    tor        = ip_mod.get("is_tor_exit", False)
    vt_mal     = osint_mod.get("virustotal", {}).get("malicious", 0)

    rows = [
        row("🛡️ Vulnerabilidades (CVEs)", cve_pts, cve_det),
        row("📧 SPF (anti-spoofing)",     -8 if not spf_ok   else 0, "" if spf_ok   else "ausente"),
        row("📧 DMARC (anti-phishing)",   -8 if not dmarc_ok else 0, "" if dmarc_ok else "ausente"),
        row("🔒 Cabeçalhos HTTP",          h_pts, str(headers_pct)+"%"),
        row("🔐 Certificado SSL/TLS",      ssl_pts, ssl_det),
        row("💾 Vazamentos (HIBP)",        breach_pts, str(breach_count)+" breach(es)" if breach_count else "nenhum"),
        row("🦠 VirusTotal",              -10 if vt_mal else 0, str(vt_mal)+" engine(s)" if vt_mal else "limpo"),
        row("🧅 Nó Tor",                 -15 if tor else 0),
    ]

    total_pen = (abs(cve_pts)+(8 if not spf_ok else 0)+(8 if not dmarc_ok else 0)
                 +abs(h_pts)+abs(ssl_pts)+abs(breach_pts)+(10 if vt_mal else 0)+(15 if tor else 0))

    return (
        '<h4 style="font-size:13px;margin:16px 0 8px;color:#aeaeb2;text-transform:uppercase;letter-spacing:.8px;">'
        '📊 Composição do Score — 100 − ' + str(total_pen) + 'pts = ' + str(score) + '/100'
        '</h4>'
        '<div style="background:#1c1c1e;border:1px solid #2d2d2d;border-radius:8px;padding:0 12px;">'
        + ''.join(rows) + '</div>'
    )


def generate_full_report(data: dict, output_path: str, empresa: str = "", consultor: str = "", contato: str = ""):
    target    = data.get("target", "")
    scan_date = data.get("scan_date", "")
    mods      = data.get("modules", {})

    ip_mod    = mods.get("ip_info", {})
    dns_mod   = mods.get("dns_enum", {})
    ports_mod = mods.get("ports", {})
    ssl_mod   = mods.get("ssl", {})
    web_mod   = mods.get("web_info", {})
    osint_mod = mods.get("osint", {})
    vuln_mod  = mods.get("vulnerabilities", {})

    sec_headers = web_mod.get("security_headers", {})
    score, counts = _score(vuln_mod, sec_headers.get("percentage", 0), dns_mod=dns_mod, ssl_mod=ssl_mod, osint_mod=osint_mod)
    score_color = "#FF3B30" if score < 40 else "#FF9500" if score < 70 else "#34C759"
    total_vulns = sum(counts.values())

    open_ports = ports_mod.get("open_ports", [])
    subdomains = dns_mod.get("subdomains", [])
    cert       = ssl_mod.get("certificate", {})
    breaches   = osint_mod.get("hibp", {}).get("breaches", [])
    techs      = web_mod.get("technologies", [])
    primary_ip = ip_mod.get("ips", ["?"])[0] if ip_mod.get("ips") else "?"
    geo        = ip_mod.get("geolocation", {})
    scan_fmt   = datetime.fromisoformat(scan_date).strftime("%d/%m/%Y às %H:%M") if scan_date else ""

    # Consolida todos os risk_flags
    all_flags = []
    for mod in mods.values():
        if isinstance(mod, dict):
            all_flags.extend(mod.get("risk_flags", []))

    # Portas HTML
    def port_rows():
        if not open_ports:
            return "<tr><td colspan='5' style='color:#8e8e93;text-align:center;padding:20px;'>Nenhuma porta encontrada ou scan pulado.</td></tr>"
        rows = ""
        for p in open_ports:
            c = _rc(p.get("risk","info"))
            ver = (p.get("version") or p.get("product") or "—")
            rows += f"""<tr style="border-bottom:1px solid #f2f2f7;">
              <td style="padding:10px 12px;font-family:monospace;font-weight:600;">{p.get('port')}/{p.get('protocol','tcp')}</td>
              <td style="padding:10px 12px;">{p.get('service','')}</td>
              <td style="padding:10px 12px;font-family:monospace;font-size:12px;color:#6e6e73;">{ver}</td>
              <td style="padding:10px 12px;">{_badge(p.get('risk','info'))}</td>
              <td style="padding:10px 12px;font-size:13px;color:#6e6e73;">{p.get('note','')}</td>
            </tr>"""
        return rows

    # Vuln cards
    def vuln_cards():
        all_v = vuln_mod.get("critical",[]) + vuln_mod.get("high",[]) + vuln_mod.get("medium",[]) + vuln_mod.get("low",[])
        if not all_v:
            return "<p style='color:#8e8e93;'>Nenhuma vulnerabilidade identificada automaticamente.</p>"
        html = ""
        for v in all_v:
            c   = _rc(v.get("severity","info"))
            url = v.get("url") or v.get("ref") or ""
            cve = v.get("cve") or ""
            link = f'<a href="{url}" target="_blank" style="color:#0071e3;">{cve}</a>' if url else cve
            html += f"""
            <div style="border:1px solid {c}44;border-left:4px solid {c};border-radius:12px;padding:16px;margin-bottom:10px;background:{c}08;">
              <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap;">
                {_badge(v.get('severity','info'))}
                {f'<span style="background:#f2f2f7;border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700;">CVSS {v["cvss"]}</span>' if v.get("cvss") else ""}
                <span style="font-family:monospace;font-size:12px;color:#0071e3;">{link}</span>
                {f'<span style="font-size:12px;color:#8e8e93;">porta {v["port"]}</span>' if v.get("port") else ""}
              </div>
              <div style="font-weight:600;margin-bottom:4px;">{v.get('title','')}</div>
              <div style="font-size:13px;color:#6e6e73;">{v.get('desc','')}</div>
            </div>"""
        return html

    # Header check rows
    def header_rows():
        html = ""
        for name, info in sec_headers.get("present",{}).items():
            html += f"""<tr style="border-bottom:1px solid #f2f2f7;">
              <td style="padding:10px 12px;">✅ <strong>{name}</strong></td>
              <td style="padding:10px 12px;font-family:monospace;font-size:12px;color:#6e6e73;">{str(info.get('value',''))[:80]}</td>
              <td style="padding:10px 12px;">{_badge('info')}</td>
              <td style="padding:10px 12px;font-size:13px;color:#34C759;">Presente</td>
            </tr>"""
        for name, info in sec_headers.get("missing",{}).items():
            html += f"""<tr style="border-bottom:1px solid #f2f2f7;background:#fff9f9;">
              <td style="padding:10px 12px;">❌ <strong>{name}</strong></td>
              <td style="padding:10px 12px;font-size:13px;color:#FF3B30;font-style:italic;">Ausente</td>
              <td style="padding:10px 12px;">{_badge(info.get('risk','low'))}</td>
              <td style="padding:10px 12px;font-size:13px;color:#6e6e73;">{info.get('recommendation','')}</td>
            </tr>"""
        return html

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Relatório Completo de Segurança | {target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Inter',sans-serif;background:#f5f5f7;color:#1d1d1f;}}
  a{{color:#0071e3;text-decoration:none}} a:hover{{text-decoration:underline}}
  code{{background:#f2f2f7;padding:2px 7px;border-radius:5px;font-family:'SF Mono','Cascadia Code',monospace;font-size:12px;color:#c41a16;}}
  table{{width:100%;border-collapse:collapse;}}
  th{{text-align:left;padding:8px 12px;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#8e8e93;border-bottom:2px solid #e5e5ea;}}

  .cover{{background:linear-gradient(135deg,#1c1c1e,#2c2c2e);color:#fff;padding:60px 40px 48px;}}
  .cover .badge{{display:inline-block;background:rgba(52,199,89,.2);border:1px solid rgba(52,199,89,.4);color:#34C759;border-radius:20px;padding:4px 14px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-bottom:20px}}
  .cover h1{{font-size:34px;font-weight:800;margin-bottom:8px}}
  .cover .sub{{color:rgba(255,255,255,.5);font-size:15px;margin-bottom:32px}}
  .cover .meta-row{{display:flex;gap:24px;flex-wrap:wrap;margin-top:24px}}
  .cover .meta-item{{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);border-radius:10px;padding:12px 18px;}}
  .cover .meta-item .mk{{font-size:11px;color:rgba(255,255,255,.4);text-transform:uppercase;margin-bottom:4px}}
  .cover .meta-item .mv{{font-size:14px;font-weight:600}}

  .content{{max-width:900px;margin:0 auto;padding:40px 24px;}}
  .card{{background:#fff;border-radius:16px;padding:28px;margin-bottom:20px;box-shadow:0 2px 12px rgba(0,0,0,.05);}}
  .card h2{{font-size:19px;font-weight:700;margin-bottom:4px;display:flex;align-items:center;gap:10px;}}
  .card .sub{{color:#8e8e93;font-size:13px;margin-bottom:20px;}}

  .score-wrap{{display:flex;align-items:center;gap:40px;flex-wrap:wrap;padding:8px 0 16px;}}
  .score-num-big{{font-size:72px;font-weight:900;color:{score_color};line-height:1;}}
  .score-bar-wrap{{flex:1;min-width:200px;}}
  .score-bar{{height:12px;background:#f2f2f7;border-radius:6px;overflow:hidden;margin-bottom:8px;}}
  .score-bar-fill{{height:100%;width:{score}%;background:{score_color};border-radius:6px;}}

  .grid2{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px;}}
  .info-box{{background:#f5f5f7;border-radius:12px;padding:14px 18px;}}
  .info-box .k{{font-size:11px;text-transform:uppercase;color:#8e8e93;font-weight:600;margin-bottom:4px;}}
  .info-box .v{{font-size:15px;font-weight:600;}}

  .flag{{display:flex;gap:10px;padding:10px 14px;margin-bottom:8px;border-radius:8px;background:#fff9f0;border-left:3px solid #FF9500;font-size:13px;}}
  .flag.crit{{background:#fff0f0;border-color:#FF3B30;}}

  .rem-step{{background:#f0f8ff;border:1px solid #bee3f8;border-radius:10px;padding:16px;margin-top:16px;}}

  .tag{{display:inline-block;background:#f2f2f7;border-radius:6px;padding:3px 10px;font-size:12px;font-weight:500;margin:2px;}}

  .toc{{background:#fff;border-radius:16px;padding:24px 28px;margin-bottom:20px;box-shadow:0 2px 12px rgba(0,0,0,.05);}}
  .toc h3{{font-size:15px;font-weight:700;margin-bottom:14px;color:#8e8e93;text-transform:uppercase;letter-spacing:.5px;}}
  .toc a{{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid #f2f2f7;font-size:14px;font-weight:500;color:#1d1d1f;}}
  .toc a:last-child{{border-bottom:none}}
  .toc a:hover{{color:#0071e3;}}
  .toc .num{{width:24px;height:24px;background:#f2f2f7;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:#8e8e93;flex-shrink:0;}}

  .footer{{text-align:center;color:#8e8e93;font-size:12px;padding:20px 0 48px;margin-top:20px;border-top:1px solid #e5e5ea;}}

  @media(max-width:640px){{.grid2{{grid-template-columns:1fr}}.cover{{padding:40px 24px}}.score-num-big{{font-size:52px}}}}
</style>
</head>
<body>

<!-- CAPA -->
<div class="cover">
  <div style="max-width:900px;margin:0 auto;">
    <div class="badge">✅ Relatório Técnico Completo + Guia de Correção</div>
    <h1>Relatório de Segurança Digital</h1>
    <div class="sub">Análise Completa de Exposição Externa, Vulnerabilidades e Plano de Remediação</div>
    <div class="meta-row">
      <div class="meta-item"><div class="mk">Alvo</div><div class="mv"><a href="https://{target}" target="_blank" rel="noopener" style="color:inherit;text-decoration:underline;text-decoration-color:rgba(255,255,255,.3);">{target} ↗</a></div></div>
      <div class="meta-item"><div class="mk">IP Principal</div><div class="mv">{primary_ip}</div></div>
      <div class="meta-item"><div class="mk">Data da Análise</div><div class="mv">{scan_fmt}</div></div>
      <div class="meta-item"><div class="mk">Score de Segurança</div><div class="mv" style="color:{score_color}">{score}/100</div></div>
      {f'<div class="meta-item"><div class="mk">Consultor</div><div class="mv">{consultor}</div></div>' if consultor else ""}
    </div>
  </div>
</div>

<div class="content">

  <!-- ÍNDICE -->
  <div class="toc">
    <h3>Índice</h3>
    <a href="#score"><div class="num">1</div> Score e Sumário Executivo</a>
    <a href="#ip"><div class="num">2</div> Infraestrutura e IP</a>
    <a href="#ports"><div class="num">3</div> Portas e Serviços ({len(open_ports)} aberta(s))</a>
    <a href="#ssl"><div class="num">4</div> Certificado SSL/TLS</a>
    <a href="#dns"><div class="num">5</div> DNS, Subdomínios e E-mail</a>
    <a href="#web"><div class="num">6</div> Fingerprint Web e Cabeçalhos HTTP</a>
    <a href="#osint"><div class="num">7</div> OSINT e Exposição Pública</a>
    <a href="#vulns"><div class="num">8</div> Vulnerabilidades ({total_vulns} encontrada(s))</a>
    <a href="#remediation"><div class="num">9</div> 🔧 Guia de Correção — Passo a Passo</a>
  </div>

  <!-- 1. SCORE -->
  <div class="card" id="score">
    <h2>📊 Score e Sumário Executivo</h2>
    <div class="sub">Avaliação consolidada com base em todos os módulos de análise</div>
    <div class="score-wrap">
      <div class="score-num-big">{score}</div>
      <div class="score-bar-wrap">
        <div class="score-bar"><div class="score-bar-fill"></div></div>
        <p style="font-size:14px;color:#6e6e73;">{"⚠️ Nível CRÍTICO — ação imediata necessária" if score<40 else "⚠️ Nível MODERADO — melhorias necessárias" if score<70 else "✅ Nível BOM — algumas melhorias recomendadas"}</p>
        <div style="display:flex;gap:12px;margin-top:12px;flex-wrap:wrap;">
          <span style="background:#FF3B3022;color:#FF3B30;border-radius:6px;padding:4px 12px;font-size:13px;font-weight:700;">{counts["critical"]} Crítico</span>
          <span style="background:#FF950022;color:#FF9500;border-radius:6px;padding:4px 12px;font-size:13px;font-weight:700;">{counts["high"]} Alto</span>
          <span style="background:#FFCC0022;color:#CCAA00;border-radius:6px;padding:4px 12px;font-size:13px;font-weight:700;">{counts["medium"]} Médio</span>
          <span style="background:#34C75922;color:#34C759;border-radius:6px;padding:4px 12px;font-size:13px;font-weight:700;">{counts["low"]} Baixo</span>
        </div>
      </div>
    </div>
    {"" if not all_flags else "<h4 style='font-size:14px;margin-bottom:10px;'>⚠️ Alertas Principais</h4>" + "".join(f'<div class="flag {"crit" if any(w in f.lower() for w in ["crítica","crítico"]) else ""}">{f}</div>' for f in all_flags[:15])}
    {_full_scorecard(score, counts, dns_mod, sec_headers.get('percentage',0),
                           cert, len(breaches), ip_mod, osint_mod)}
  </div>

  <!-- 2. IP -->
  <div class="card" id="ip">
    <h2>🌍 Infraestrutura e IP</h2>
    <div class="sub">Geolocalização, ASN e verificações de reputação</div>
    <div class="grid2">
      <div class="info-box"><div class="k">IP Principal</div><div class="v">{primary_ip}</div></div>
      <div class="info-box"><div class="k">Localização</div><div class="v">{geo.get("city","")}, {geo.get("country","?")}</div></div>
      <div class="info-box"><div class="k">ISP / Organização</div><div class="v">{geo.get("org") or geo.get("isp","?")}</div></div>
      <div class="info-box"><div class="k">ASN</div><div class="v">{ip_mod.get("asn",{}).get("asn_name") or geo.get("asn","?")}</div></div>
      <div class="info-box"><div class="k">Nó de Saída Tor</div><div class="v" style="color:{'#FF3B30' if ip_mod.get('is_tor_exit') else '#34C759'}">{'⚠️ Sim' if ip_mod.get('is_tor_exit') else '✅ Não'}</div></div>
      <div class="info-box"><div class="k">CVEs via Shodan</div><div class="v">{len(ip_mod.get("shodan_quick",{}).get("cves",[]))} encontrado(s)</div></div>
    </div>
    {f'<p><strong>Portas Shodan:</strong> ' + " ".join(f'<span class="tag">{p}</span>' for p in ip_mod.get("shodan_quick",{}).get("open_ports",[])[:20]) + '</p>' if ip_mod.get("shodan_quick",{}).get("open_ports") else ""}
  </div>

  <!-- 3. PORTAS -->
  <div class="card" id="ports">
    <h2>🔌 Portas e Serviços</h2>
    <div class="sub">Método: {ports_mod.get("method","N/A")} · {len(open_ports)} porta(s) abertas encontradas</div>
    <div style="overflow-x:auto;">
      <table>
        <tr><th>Porta</th><th>Serviço</th><th>Versão</th><th>Risco</th><th>Observação</th></tr>
        {port_rows()}
      </table>
    </div>
  </div>

  <!-- 4. SSL -->
  <div class="card" id="ssl">
    <h2>🔒 Certificado SSL/TLS</h2>
    <div class="sub">Validade, protocolo, cipher suite e configurações</div>
    {"" if not cert or not cert.get("valid") else f'''
    <div class="grid2">
      <div class="info-box"><div class="k">Emissor</div><div class="v">{cert.get("issuer_cn","?")}</div></div>
      <div class="info-box"><div class="k">Organização Emissora</div><div class="v">{cert.get("issuer_org","?")}</div></div>
      <div class="info-box"><div class="k">Domínio (CN)</div><div class="v">{cert.get("subject_cn","?")}</div></div>
      <div class="info-box"><div class="k">Protocolo TLS</div><div class="v">{cert.get("tls_version","?")}</div></div>
      <div class="info-box"><div class="k">Cipher Suite</div><div class="v" style="font-size:13px;">{cert.get("cipher","?")} ({cert.get("cipher_bits","?")} bits)</div></div>
      <div class="info-box"><div class="k">Validade</div><div class="v" style="color:{'#FF3B30' if cert.get('expired') or cert.get('expiring_soon') else '#34C759'}">
        {'🔴 EXPIRADO' if cert.get('expired') else f'⚠️ Expira em {cert.get("days_left")} dias' if cert.get('expiring_soon') else f'✅ {cert.get("days_left","?")} dias restantes'}
      </div></div>
    </div>
    {f'<p style="margin-top:12px;"><strong>SANs:</strong> ' + " ".join(f'<span class="tag">{s}</span>' for s in cert.get("sans",[])[:10]) + '</p>' if cert.get("sans") else ""}
    ''' if cert and cert.get("valid") else f'<div class="flag crit">{cert.get("error","SSL não disponível") if cert else "SSL não verificado"}</div>'}
    {"".join(f'<div class="flag {"crit" if r["level"]=="critical" else ""}">{_badge(r["level"])} {r["msg"]}</div>' for r in ssl_mod.get("risks",[]))}
  </div>

  <!-- 5. DNS -->
  <div class="card" id="dns">
    <h2>🌐 DNS, Subdomínios e Segurança de E-mail</h2>
    <div class="sub">SPF, DMARC e mapeamento de subdomínios</div>
    <div class="grid2" style="margin-bottom:20px;">
      <div class="info-box">
        <div class="k">SPF {_badge(dns_mod.get('spf',{}).get('risk','info'))}</div>
        <div class="v" style="font-size:13px;font-family:monospace;word-break:break-all;">{dns_mod.get('spf',{}).get('record') or '❌ Ausente'}</div>
      </div>
      <div class="info-box">
        <div class="k">DMARC {_badge(dns_mod.get('dmarc',{}).get('risk','info'))}</div>
        <div class="v" style="font-size:13px;font-family:monospace;word-break:break-all;">{dns_mod.get('dmarc',{}).get('record') or '❌ Ausente'}</div>
      </div>
    </div>
    {f'<p style="margin-bottom:12px;"><strong>Servidores MX:</strong> ' + "  ".join(f'<span class="tag">{m}</span>' for m in dns_mod.get("mx_records",[])[:5]) + '</p>' if dns_mod.get("mx_records") else ""}
    {f'<p style="margin-bottom:12px;"><strong>Nameservers:</strong> ' + "  ".join(f'<span class="tag">{n}</span>' for n in dns_mod.get("ns_records",[])[:5]) + '</p>' if dns_mod.get("ns_records") else ""}
    {"" if not subdomains else f'''
    <h4 style="margin-bottom:10px;font-size:14px;">Subdomínios ({len(subdomains)} encontrados)</h4>
    <div style="display:flex;flex-wrap:wrap;gap:6px;">
      {"".join(f'<span class="tag">{s["subdomain"]} <small style=\'color:#8e8e93\'>{s.get("ip","")}</small></span>' for s in subdomains[:50])}
      {f'<span class="tag" style="color:#8e8e93;">+{len(subdomains)-50} mais</span>' if len(subdomains)>50 else ""}
    </div>'''}
  </div>

  <!-- 6. WEB -->
  <div class="card" id="web">
    <h2>🖥️ Fingerprint Web e Cabeçalhos HTTP</h2>
    <div class="sub">Score: {sec_headers.get('percentage',0)}% ({sec_headers.get('score',0)}/{sec_headers.get('max_score',7)} cabeçalhos presentes)</div>
    <div class="grid2" style="margin-bottom:20px;">
      <div class="info-box"><div class="k">Servidor</div><div class="v">{web_mod.get('server','N/A') or 'N/A'}</div></div>
      <div class="info-box"><div class="k">Tecnologias</div><div class="v" style="font-size:13px;">{", ".join(techs[:6]) or "N/A"}</div></div>
    </div>
    <div style="overflow-x:auto;">
      <table>
        <tr><th>Cabeçalho</th><th>Valor</th><th>Risco</th><th>Recomendação</th></tr>
        {header_rows()}
      </table>
    </div>
  </div>

  <!-- 7. OSINT -->
  <div class="card" id="osint">
    <h2>🕵️ OSINT e Exposição Pública</h2>
    <div class="sub">Verificação em bases públicas de inteligência de ameaças</div>
    <div class="grid2">
      <div class="info-box"><div class="k">HaveIBeenPwned</div><div class="v" style="color:{'#FF3B30' if breaches else '#34C759'}">{len(breaches)} breach(es) encontrado(s)</div></div>
      <div class="info-box"><div class="k">Google Safe Browsing</div><div class="v" style="color:{'#FF3B30' if osint_mod.get('google_safebrow',{}).get('safe')==False else '#34C759'}">{'⚠️ Inseguro' if osint_mod.get('google_safebrow',{}).get('safe')==False else '✅ Seguro'}</div></div>
      <div class="info-box"><div class="k">URLScan.io</div><div class="v">{osint_mod.get('urlscan',{}).get('count',0)} scan(s) histórico(s)</div></div>
      <div class="info-box"><div class="k">VirusTotal</div><div class="v">{osint_mod.get('virustotal',{}).get('note','') or str(osint_mod.get('virustotal',{}).get('malicious',0)) + ' engine(s) malicioso(s)'}</div></div>
    </div>
    {"" if not breaches else f'''
    <h4 style="margin:16px 0 10px;font-size:14px;">Breaches Encontrados</h4>
    {"".join(f'''<div style="border-left:3px solid #FF3B30;border-radius:0 10px 10px 0;padding:10px 14px;margin-bottom:8px;background:#fff0f0;">
      <strong>{b["name"]}</strong> · {b.get("date","?")} · {b.get("pwn_count","?")} registros<br>
      <span style="font-size:12px;color:#8e8e93;">Dados: {", ".join(b.get("data_classes",[])[:5])}</span>
    </div>''' for b in breaches[:10])}'''}
  </div>

  <!-- 8. VULNERABILIDADES -->
  <div class="card" id="vulns">
    <h2>🛡️ Vulnerabilidades Identificadas</h2>
    <div class="sub">{total_vulns} problema(s) encontrado(s) via regras locais e base NVD/NIST</div>
    {vuln_cards()}
  </div>

  <!-- 9. GUIA DE CORREÇÃO -->
  <div class="card" id="remediation" style="border-top:4px solid #0071e3;">
    <h2>🔧 Guia de Correção — Passo a Passo</h2>
    <div class="sub">Instruções técnicas priorizadas para corrigir os problemas encontrados</div>
    {_remediation_section(all_flags, vuln_mod)}
  </div>

  <!-- Consultor / Rodapé -->
  {"" if not consultor else f'''
  <div style="background:#fff;border-radius:16px;padding:24px;margin-bottom:20px;box-shadow:0 2px 12px rgba(0,0,0,.05);display:flex;align-items:center;gap:20px;">
    <div style="width:56px;height:56px;border-radius:14px;background:linear-gradient(135deg,#0071e3,#0040a0);display:flex;align-items:center;justify-content:center;font-size:24px;flex-shrink:0;">🔐</div>
    <div>
      <div style="font-size:15px;font-weight:700;">{consultor}</div>
      <div style="font-size:13px;color:#8e8e93;">Consultor de Segurança Digital</div>
      {"<div style='font-size:13px;color:#0071e3;margin-top:4px;'>📧 " + contato + "</div>" if contato else ""}
      {"<div style='font-size:13px;color:#6e6e73;margin-top:2px;'>🏢 " + empresa + "</div>" if empresa else ""}
    </div>
  </div>'''}

  <div class="footer">
    Relatório Completo de Segurança · {target} · {scan_fmt}<br>
    Análise baseada 100% em dados públicos — nenhuma invasão ou exploração realizada<br>
    {"© " + empresa + " · " if empresa else ""}{"Contato: " + contato if contato else ""}
  </div>

</div>
</body>
</html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)