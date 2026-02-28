"""
Módulo: Gerador de Relatório HTML e JSON
Produz um relatório visual completo e profissional
"""

import json
from datetime import datetime
from pathlib import Path


def risk_badge(level: str) -> str:
    colors = {
        "critical": ("🔴", "#FF3B30", "#fff1f0"),
        "high":     ("🟠", "#FF9500", "#fff7e6"),
        "medium":   ("🟡", "#FFCC00", "#fffbe6"),
        "low":      ("🟢", "#34C759", "#f6ffed"),
        "info":     ("🔵", "#007AFF", "#e6f4ff"),
    }
    icon, color, bg = colors.get(level, ("⚪", "#8c8c8c", "#fafafa"))
    return f'<span class="badge" style="background:{bg};color:{color};border:1px solid {color};">{icon} {level.upper()}</span>'


def port_risk_row(port: dict) -> str:
    risk  = port.get("risk", "info")
    badge = risk_badge(risk)
    ver   = port.get("version") or port.get("product") or ""
    note  = port.get("note") or ""
    return f"""
    <tr>
      <td><code>{port.get('port')}/{port.get('protocol','tcp')}</code></td>
      <td>{port.get('service','')}</td>
      <td><code>{ver}</code></td>
      <td>{badge}</td>
      <td class="note">{note}</td>
    </tr>"""


def vuln_card(v: dict) -> str:
    sev   = v.get("severity", "info")
    badge = risk_badge(sev)
    cvss  = v.get("cvss")
    cvss_str = f'<span class="cvss">CVSS {cvss}</span>' if cvss else ""
    cve_id = v.get("cve") or ""
    url    = v.get("url") or v.get("ref") or ""
    link   = f'<a href="{url}" target="_blank">{cve_id}</a>' if url else cve_id
    port_info = f' — porta {v["port"]}' if v.get("port") else ""
    return f"""
    <div class="vuln-card sev-{sev}">
      <div class="vuln-header">{badge} {cvss_str} {link}{port_info}</div>
      <div class="vuln-title">{v.get('title','')}</div>
      <div class="vuln-desc">{v.get('desc','')}</div>
    </div>"""


def header_row(name: str, info: dict, present: bool) -> str:
    if present:
        val = info.get("value", "")
        return f"""
        <tr class="header-ok">
          <td>✅ {name}</td>
          <td><code>{val[:80]}</code></td>
          <td>{risk_badge('info')}</td>
          <td>Presente</td>
        </tr>"""
    else:
        risk = info.get("risk", "low")
        rec  = info.get("recommendation", "")
        return f"""
        <tr class="header-miss">
          <td>❌ {name}</td>
          <td><em class="missing">Ausente</em></td>
          <td>{risk_badge(risk)}</td>
          <td>{rec}</td>
        </tr>"""




def _gen_scorecard(score, n_crit, n_high, n_med, n_low,
                   spf_ok, dmarc_ok, headers_pct, ssl_cert,
                   breach_count, ip_mod, osint_mod):
    """Scorecard completo: todos os fatores avaliados, passando (verde) e falhando (vermelho)."""

    def row(category, pts, detail=""):
        if pts < 0:
            badge = '<span style="color:#f85149;font-weight:700;">−' + str(abs(pts)) + 'pts</span>'
            bg    = 'background:rgba(248,81,73,.06);'
        else:
            badge = '<span style="color:#3fb950;font-weight:700;">✓ OK</span>'
            bg    = ''
        det = (' <span style="color:var(--text2);font-size:11px;">(' + detail + ')</span>') if detail else ''
        return (
            '<div style="display:flex;justify-content:space-between;align-items:center;'
            'padding:7px 12px;border-bottom:1px solid var(--border);' + bg + '">'
            '<span style="font-size:12px;">' + category + det + '</span>'
            + badge + '</div>'
        )

    cve_pts = -(min(n_crit*25,50) + min(n_high*10,30) + min(n_med*5,20) + min(n_low*2,10))
    cve_det = (str(n_crit) + "C/" + str(n_high) + "A/" + str(n_med) + "M/" + str(n_low) + "B") if cve_pts < 0 else "nenhum"

    h_pts = (-10 if headers_pct < 50 else -6 if headers_pct < 70 else -3 if headers_pct < 80 else 0)

    if ssl_cert.get("expired"):         ssl_pts = -20; ssl_det = "expirado"
    elif ssl_cert.get("expiring_soon"): ssl_pts = -10; ssl_det = str(ssl_cert.get("days_left","?")) + " dias"
    else:                               ssl_pts = 0;   ssl_det = str(ssl_cert.get("days_left","?")) + " dias restantes"

    breach_pts = -min(breach_count * 10, 20) if breach_count else 0
    tor        = ip_mod.get("is_tor_exit", False)
    vt_mal     = osint_mod.get("virustotal", {}).get("malicious", 0)

    rows = [
        row("🛡️ Vulnerabilidades (CVEs)", cve_pts, cve_det),
        row("📧 SPF (anti-spoofing)",     -8 if not spf_ok   else 0, "" if spf_ok   else "ausente"),
        row("📧 DMARC (anti-phishing)",   -8 if not dmarc_ok else 0, "" if dmarc_ok else "ausente"),
        row("🔒 Cabeçalhos HTTP",          h_pts,    str(headers_pct) + "%"),
        row("🔐 Certificado SSL/TLS",      ssl_pts,  ssl_det),
        row("💾 Vazamentos (HIBP)",        breach_pts, str(breach_count) + " breach(es)" if breach_count else "nenhum"),
        row("🦠 VirusTotal",              -10 if vt_mal else 0, str(vt_mal) + " engine(s)" if vt_mal else "limpo"),
        row("🧅 Nó Tor",                 -15 if tor  else 0),
    ]

    total_pen = (abs(cve_pts) + (8 if not spf_ok else 0) + (8 if not dmarc_ok else 0)
                 + abs(h_pts) + abs(ssl_pts) + abs(breach_pts)
                 + (10 if vt_mal else 0) + (15 if tor else 0))

    return (
        '<div style="background:var(--surface2);border:1px solid var(--border);'
        'border-radius:8px;margin-bottom:24px;overflow:hidden;">'
        '<div style="padding:10px 12px;border-bottom:1px solid var(--border);'
        'font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--text2);">'
        + '📊 Composição do Score — 100 − ' + str(total_pen) + 'pts = ' + str(score) + '/100'
        + '</div>' + ''.join(rows) + '</div>'
    )


def generate_html_report(data: dict, output_path: str):
    target    = data.get("target", "")
    scan_date = data.get("scan_date", "")
    mods      = data.get("modules", {})

    # Dados principais
    ip_mod   = mods.get("ip_info", {})
    dns_mod  = mods.get("dns_enum", {})
    ports_mod= mods.get("ports", {})
    ssl_mod  = mods.get("ssl", {})
    web_mod  = mods.get("web_info", {})
    osint_mod= mods.get("osint", {})
    vuln_mod = mods.get("vulnerabilities", {})

    # Contagem de riscos
    n_crit = len(vuln_mod.get("critical", []))
    n_high = len(vuln_mod.get("high", []))
    n_med  = len(vuln_mod.get("medium", []))
    n_low  = len(vuln_mod.get("low", []))
    total_vulns = n_crit + n_high + n_med + n_low

    # Portas abertas
    open_ports    = ports_mod.get("open_ports", [])
    total_ports   = len(open_ports)

    # Subdomínios
    subdomains    = dns_mod.get("subdomains", [])

    # SSL
    cert          = ssl_mod.get("certificate", {})
    ssl_risks     = ssl_mod.get("risks", [])

    # Cabeçalhos
    sec_headers   = web_mod.get("security_headers", {})
    headers_score = sec_headers.get("percentage", 0)

    # Score geral (0–100) — penalidades em todas as categorias de risco
    # FIX Bug 5: fórmula original usava `bonus = headers*0.3` (infla score);
    # agora penaliza headers baixos, SPF/DMARC ausentes, SSL e breaches,
    # alinhado com report_preview.py para consistência entre relatórios.
    spf_ok      = dns_mod.get("spf", {}).get("exists", False)
    dmarc_ok    = dns_mod.get("dmarc", {}).get("exists", False)
    ssl_cert_rg = ssl_mod.get("certificate", {})
    breach_cnt  = osint_mod.get("hibp", {}).get("count", 0)

    penalty  = 0
    penalty += min(n_crit * 25, 50)
    penalty += min(n_high * 10, 30)
    penalty += min(n_med  *  5, 20)
    penalty += min(n_low  *  2, 10)
    if not spf_ok:   penalty += 8
    if not dmarc_ok: penalty += 8
    if headers_score < 50:   penalty += 10
    elif headers_score < 70: penalty += 6
    elif headers_score < 80: penalty += 3
    if ssl_cert_rg.get("expired"):      penalty += 20
    elif ssl_cert_rg.get("expiring_soon"): penalty += 10
    penalty += min(breach_cnt * 10, 20)
    raw_score = max(0, min(100, 100 - penalty))
    score_color = "#FF3B30" if raw_score < 40 else "#FF9500" if raw_score < 70 else "#34C759"

    # Risk flags consolidadas
    all_flags = []
    for mod in mods.values():
        if isinstance(mod, dict):
            all_flags.extend(mod.get("risk_flags", []))

    # Gera HTML ─────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Relatório de Exposição — {target}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --surface2: #21262d;
    --border: #30363d; --text: #c9d1d9; --text2: #8b949e;
    --accent: #58a6ff; --green: #3fb950; --red: #f85149;
    --orange: #d29922; --yellow: #e3b341;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.6; }}
  a {{ color: var(--accent); text-decoration: none; }} a:hover {{ text-decoration: underline; }}
  code {{ background: var(--surface2); padding: 2px 6px; border-radius: 4px; font-family: 'SF Mono', 'Cascadia Code', monospace; font-size: 13px; color: #e6edf3; }}

  /* Layout */
  .container {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
  .header {{ background: linear-gradient(135deg, #0d1117 0%, #161b22 100%); border-bottom: 1px solid var(--border); padding: 32px 0 24px; margin-bottom: 32px; }}
  .header h1 {{ font-size: 28px; font-weight: 700; color: #e6edf3; margin-bottom: 4px; }}
  .header .meta {{ color: var(--text2); font-size: 13px; }}
  .header .target-chip {{ display: inline-flex; align-items: center; gap: 8px; background: var(--surface2); border: 1px solid var(--border); border-radius: 20px; padding: 6px 14px; margin-top: 12px; font-family: monospace; }}

  /* Score */
  .score-ring {{ text-align: center; margin: 32px 0; }}
  .score-ring svg {{ width: 160px; height: 160px; }}
  .score-num {{ font-size: 42px; font-weight: 800; fill: {score_color}; }}
  .score-label {{ font-size: 12px; fill: var(--text2); }}

  /* Summary cards */
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 32px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px; text-align: center; }}
  .card .num {{ font-size: 32px; font-weight: 800; line-height: 1; margin-bottom: 4px; }}
  .card .lbl {{ font-size: 12px; color: var(--text2); text-transform: uppercase; letter-spacing: .5px; }}
  .card.red .num   {{ color: #f85149; }}
  .card.orange .num{{ color: #d29922; }}
  .card.yellow .num{{ color: #e3b341; }}
  .card.blue .num  {{ color: var(--accent); }}
  .card.green .num {{ color: var(--green); }}

  /* Sections */
  .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 20px; overflow: hidden; }}
  .section-header {{ display: flex; align-items: center; gap: 12px; padding: 14px 20px; border-bottom: 1px solid var(--border); background: var(--surface2); cursor: pointer; }}
  .section-header h2 {{ font-size: 16px; font-weight: 600; flex: 1; }}
  .section-body {{ padding: 20px; }}

  /* Risk flags */
  .risk-flags {{ margin-bottom: 24px; }}
  .flag {{ display: flex; align-items: flex-start; gap: 10px; padding: 10px 14px; margin-bottom: 8px; border-radius: 8px; background: #1c1008; border-left: 3px solid #d29922; }}
  .flag.critical {{ background: #1c0807; border-color: #f85149; }}

  /* Tables */
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; padding: 8px 12px; color: var(--text2); font-size: 12px; text-transform: uppercase; letter-spacing: .5px; border-bottom: 1px solid var(--border); }}
  td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: var(--surface2); }}
  .note {{ color: var(--text2); font-size: 13px; }}

  /* Badges */
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; white-space: nowrap; }}

  /* Vuln cards */
  .vuln-card {{ border: 1px solid var(--border); border-radius: 8px; padding: 14px; margin-bottom: 10px; }}
  .vuln-card.sev-critical {{ border-color: #f85149; background: #160b0a; }}
  .vuln-card.sev-high     {{ border-color: #d29922; background: #16110a; }}
  .vuln-card.sev-medium   {{ border-color: #e3b341; background: #161408; }}
  .vuln-card.sev-low      {{ border-color: #3fb950; background: #0a160c; }}
  .vuln-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }}
  .vuln-title  {{ font-weight: 600; margin-bottom: 4px; color: #e6edf3; }}
  .vuln-desc   {{ color: var(--text2); font-size: 13px; }}
  .cvss        {{ background: var(--surface2); border: 1px solid var(--border); border-radius: 4px; padding: 1px 6px; font-size: 11px; font-weight: 700; color: #e6edf3; }}

  /* SSL */
  .ssl-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }}
  .ssl-item {{ background: var(--surface2); border-radius: 8px; padding: 12px 16px; }}
  .ssl-item .key {{ font-size: 11px; text-transform: uppercase; color: var(--text2); margin-bottom: 4px; }}
  .ssl-item .val {{ font-weight: 600; }}

  /* Header table */
  .header-ok td {{ color: var(--text); }}
  .header-miss td {{ color: var(--text2); }}
  .missing {{ color: #f85149; }}

  /* Subdomains */
  .sub-list {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .sub-chip {{ background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 4px 10px; font-family: monospace; font-size: 12px; }}

  /* SPF/DMARC */
  .email-sec {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  .email-card {{ background: var(--surface2); border-radius: 8px; padding: 14px; }}
  .email-card h4 {{ margin-bottom: 8px; font-size: 13px; }}
  .email-card pre {{ background: var(--bg); border-radius: 4px; padding: 8px; font-size: 11px; color: var(--text2); white-space: pre-wrap; word-break: break-all; overflow: auto; max-height: 80px; }}

  /* OSINT */
  .breach-list {{ display: flex; flex-direction: column; gap: 8px; }}
  .breach-item {{ background: var(--surface2); border-left: 3px solid #f85149; border-radius: 0 8px 8px 0; padding: 10px 14px; }}
  .breach-name {{ font-weight: 600; margin-bottom: 4px; }}
  .breach-meta {{ font-size: 12px; color: var(--text2); }}

  /* Footer */
  .footer {{ text-align: center; color: var(--text2); font-size: 12px; margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); }}

  @media (max-width: 700px) {{
    .ssl-grid, .email-sec {{ grid-template-columns: 1fr; }}
    .cards {{ grid-template-columns: repeat(2, 1fr); }}
  }}
</style>
</head>
<body>

<div class="header">
  <div class="container">
    <h1>🔍 Relatório de Exposição Digital</h1>
    <div class="meta">Gerado em {datetime.fromisoformat(scan_date).strftime('%d/%m/%Y às %H:%M:%S') if scan_date else ''}</div>
    <div class="target-chip">
      <span>🎯</span>
      <a href="https://{target}" target="_blank" rel="noopener" style="color:inherit;text-decoration:none;font-weight:700;">{target} ↗</a>
      {f'<span style="color:var(--text2)">→ {ip_mod.get("ips", ["?"])[0]}</span>' if ip_mod.get("ips") else ""}
    </div>
  </div>
</div>

<div class="container">

  <!-- Score + Sumário -->
  <div style="display:flex;gap:32px;align-items:center;flex-wrap:wrap;margin-bottom:24px;">
    <div class="score-ring">
      <svg viewBox="0 0 160 160">
        <circle cx="80" cy="80" r="68" fill="none" stroke="#21262d" stroke-width="12"/>
        <circle cx="80" cy="80" r="68" fill="none" stroke="{score_color}" stroke-width="12"
          stroke-dasharray="{round(raw_score * 4.27)} 427"
          stroke-dashoffset="107" stroke-linecap="round" transform="rotate(-90 80 80)"/>
        <text x="80" y="76" text-anchor="middle" class="score-num">{round(raw_score)}</text>
        <text x="80" y="98" text-anchor="middle" class="score-label">SECURITY SCORE</text>
      </svg>
    </div>
    <div class="cards" style="flex:1;">
      <div class="card red">   <div class="num">{n_crit}</div>  <div class="lbl">Críticos</div></div>
      <div class="card orange"><div class="num">{n_high}</div>  <div class="lbl">Alto</div></div>
      <div class="card yellow"><div class="num">{n_med}</div>   <div class="lbl">Médio</div></div>
      <div class="card green"> <div class="num">{n_low}</div>   <div class="lbl">Baixo</div></div>
      <div class="card blue">  <div class="num">{total_ports}</div><div class="lbl">Portas Abertas</div></div>
      <div class="card blue">  <div class="num">{len(subdomains)}</div><div class="lbl">Subdomínios</div></div>
    </div>
  </div>

  <!-- Scorecard acumulado -->
  {_gen_scorecard(raw_score, n_crit, n_high, n_med, n_low,
                  spf_ok, dmarc_ok, headers_score, ssl_cert_rg,
                  breach_cnt, ip_mod, osint_mod)}

  <!-- Risk Flags -->
  {"" if not all_flags else f'''
  <div class="risk-flags">
    <h3 style="margin-bottom:12px;font-size:14px;text-transform:uppercase;color:var(--text2);letter-spacing:.5px;">⚠️ Alertas Principais</h3>
    {"".join(f'<div class="flag {"critical" if any(w in f.lower() for w in ["crítica","crítico","críticas"]) else ""}">{f}</div>' for f in all_flags[:12])}
  </div>'''}

  <!-- 1. IP e Geolocalização -->
  <div class="section">
    <div class="section-header">
      <span>🌍</span><h2>Informações de IP e Geolocalização</h2>
    </div>
    <div class="section-body">
      <div class="ssl-grid">
        <div class="ssl-item"><div class="key">IP Principal</div><div class="val">{ip_mod.get("ips", ["?"])[0] if ip_mod.get("ips") else "N/A"}</div></div>
        <div class="ssl-item"><div class="key">Localização</div><div class="val">{ip_mod.get("geolocation", {}).get("city","")}, {ip_mod.get("geolocation", {}).get("country","N/A")}</div></div>
        <div class="ssl-item"><div class="key">ISP / Org</div><div class="val">{ip_mod.get("geolocation", {}).get("org") or ip_mod.get("geolocation", {}).get("isp","N/A")}</div></div>
        <div class="ssl-item"><div class="key">ASN</div><div class="val">{ip_mod.get("asn", {}).get("asn_name") or ip_mod.get("geolocation", {}).get("asn","N/A")}</div></div>
        <div class="ssl-item"><div class="key">Nó Tor?</div><div class="val" style="color:{'#f85149' if ip_mod.get('is_tor_exit') else '#3fb950'}">{'⚠️ Sim' if ip_mod.get('is_tor_exit') else '✅ Não'}</div></div>
        <div class="ssl-item"><div class="key">CVEs (Shodan)</div><div class="val">{len(ip_mod.get("shodan_quick", {}).get("cves", []))} encontrado(s)</div></div>
      </div>
      {f'<div style="margin-top:12px;"><strong>Portas via Shodan:</strong> <code>{", ".join(str(p) for p in ip_mod.get("shodan_quick",{}).get("open_ports",[])[:20])}</code></div>' if ip_mod.get("shodan_quick",{}).get("open_ports") else ""}
    </div>
  </div>

  <!-- 2. Scan de Portas -->
  <div class="section">
    <div class="section-header">
      <span>🔌</span><h2>Portas e Serviços ({total_ports} aberta(s))</h2>
      <span style="color:var(--text2);font-size:12px;">método: {ports_mod.get("method","N/A")}</span>
    </div>
    <div class="section-body">
      {"<p style='color:var(--text2)'>Scan pulado ou sem resultados.</p>" if not open_ports else f'''
      <table>
        <tr><th>Porta</th><th>Serviço</th><th>Versão</th><th>Risco</th><th>Observação</th></tr>
        {"".join(port_risk_row(p) for p in open_ports)}
      </table>'''}
    </div>
  </div>

  <!-- 3. SSL/TLS -->
  <div class="section">
    <div class="section-header"><span>🔒</span><h2>Certificado SSL/TLS</h2></div>
    <div class="section-body">
      {f'''
      <div class="ssl-grid">
        <div class="ssl-item"><div class="key">Emissor</div><div class="val">{cert.get("issuer_cn","N/A")}</div></div>
        <div class="ssl-item"><div class="key">Organização</div><div class="val">{cert.get("issuer_org","N/A")}</div></div>
        <div class="ssl-item"><div class="key">CN / Domínio</div><div class="val">{cert.get("subject_cn","N/A")}</div></div>
        <div class="ssl-item"><div class="key">Protocolo</div><div class="val">{cert.get("tls_version","N/A")}</div></div>
        <div class="ssl-item"><div class="key">Cipher Suite</div><div class="val">{cert.get("cipher","N/A")} ({cert.get("cipher_bits","?")} bits)</div></div>
        <div class="ssl-item"><div class="key">Validade</div><div class="val" style="color:{'#f85149' if cert.get('expired') or cert.get('expiring_soon') else '#3fb950'}">
          {'🔴 EXPIRADO' if cert.get('expired') else f'⚠️ Expira em {cert.get("days_left")} dias' if cert.get('expiring_soon') else f'✅ {cert.get("days_left","?")} dias restantes'}
        </div></div>
      </div>
      {"" if not ssl_risks else "<h4 style='margin:12px 0 8px;'>Problemas SSL</h4>" + "".join(f'<div class="flag">{risk_badge(r["level"])} {r["msg"]}</div>' for r in ssl_risks)}
      ''' if cert and cert.get("valid") else f'<p style="color:var(--text2);">{cert.get("error","SSL não disponível") if cert else "SSL não verificado"}</p>'}
    </div>
  </div>

  <!-- 4. DNS / Subdomínios -->
  <div class="section">
    <div class="section-header"><span>🌐</span><h2>DNS e Subdomínios</h2></div>
    <div class="section-body">
      <div class="email-sec" style="margin-bottom:20px;">
        <div class="email-card">
          <h4>SPF {risk_badge(dns_mod.get('spf',{}).get('risk','info'))}</h4>
          <pre>{dns_mod.get('spf',{}).get('record') or dns_mod.get('spf',{}).get('note','Não encontrado')}</pre>
        </div>
        <div class="email-card">
          <h4>DMARC {risk_badge(dns_mod.get('dmarc',{}).get('risk','info'))}</h4>
          <pre>{dns_mod.get('dmarc',{}).get('record') or dns_mod.get('dmarc',{}).get('note','Não encontrado')}</pre>
        </div>
      </div>
      {"" if not dns_mod.get("mx_records") else f'<p style="margin-bottom:12px;"><strong>Servidores MX:</strong> <code>{"  |  ".join(dns_mod.get("mx_records",[]))}</code></p>'}
      {"" if not subdomains else f'''
      <h4 style="margin-bottom:10px;">Subdomínios Descobertos ({len(subdomains)})</h4>
      <div class="sub-list">
        {"".join(f'<span class="sub-chip">{s["subdomain"]}<small style="color:var(--text2);"> {s.get("ip","")}</small></span>' for s in subdomains[:40])}
        {f'<span style="color:var(--text2);">... e mais {len(subdomains)-40}</span>' if len(subdomains)>40 else ""}
      </div>'''}
    </div>
  </div>

  <!-- 5. Web Fingerprint -->
  <div class="section">
    <div class="section-header"><span>🖥️</span><h2>Fingerprint Web e Cabeçalhos HTTP</h2></div>
    <div class="section-body">
      <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px;">
        <div class="ssl-item" style="flex:1;min-width:200px;">
          <div class="key">Score Cabeçalhos Segurança</div>
          <div class="val" style="color:{'#f85149' if headers_score<50 else '#d29922' if headers_score<80 else '#3fb950'}">{headers_score}% ({sec_headers.get('score',0)}/{sec_headers.get('max_score',0)})</div>
        </div>
        <div class="ssl-item" style="flex:1;min-width:200px;">
          <div class="key">Servidor</div>
          <div class="val">{web_mod.get('server','N/A') or 'N/A'}</div>
        </div>
        <div class="ssl-item" style="flex:1;min-width:200px;">
          <div class="key">Tecnologias</div>
          <div class="val">{", ".join(web_mod.get('technologies',[])[:8]) or "N/A"}</div>
        </div>
      </div>
      <table>
        <tr><th>Cabeçalho</th><th>Valor</th><th>Risco se ausente</th><th>Recomendação</th></tr>
        {"".join(header_row(name, info, True) for name, info in sec_headers.get("present",{}).items())}
        {"".join(header_row(name, info, False) for name, info in sec_headers.get("missing",{}).items())}
      </table>
    </div>
  </div>

  <!-- 6. OSINT -->
  <div class="section">
    <div class="section-header"><span>🕵️</span><h2>OSINT — Exposição Pública</h2></div>
    <div class="section-body">
      <div class="ssl-grid" style="margin-bottom:16px;">
        <div class="ssl-item"><div class="key">HaveIBeenPwned</div><div class="val" style="color:{'#f85149' if osint_mod.get('hibp',{}).get('count',0)>0 else '#3fb950'}">{osint_mod.get('hibp',{}).get('count',0)} breach(es)</div></div>
        <div class="ssl-item"><div class="key">URLScan.io</div><div class="val">{osint_mod.get('urlscan',{}).get('count',0)} scan(s) histórico(s)</div></div>
        <div class="ssl-item"><div class="key">Google Safe Browsing</div><div class="val" style="color:{'#f85149' if osint_mod.get('google_safebrow',{}).get('safe')==False else '#3fb950'}">{'⚠️ Inseguro' if osint_mod.get('google_safebrow',{}).get('safe')==False else '✅ Seguro' if osint_mod.get('google_safebrow',{}).get('safe') else 'Indefinido'}</div></div>
        <div class="ssl-item"><div class="key">VirusTotal</div><div class="val">{osint_mod.get('virustotal',{}).get('note','') or f"{osint_mod.get('virustotal',{}).get('malicious',0)} engine(s) malicioso(s)"}</div></div>
      </div>
      {"" if not osint_mod.get('hibp',{}).get('breaches') else f'''
      <h4 style="margin-bottom:10px;">Breaches Encontrados</h4>
      <div class="breach-list">
        {"".join(f'<div class="breach-item"><div class="breach-name">{b["name"]}</div><div class="breach-meta">Data: {b.get("date","?")} | Registros: {b.get("pwn_count","?")} | Dados: {", ".join(b.get("data_classes",[])[:5])}</div></div>' for b in osint_mod["hibp"]["breaches"][:10])}
      </div>'''}
    </div>
  </div>

  <!-- 7. Vulnerabilidades -->
  <div class="section">
    <div class="section-header"><span>🛡️</span><h2>Vulnerabilidades Correlacionadas ({total_vulns})</h2></div>
    <div class="section-body">
      {"<p style='color:var(--text2)'>Nenhuma vulnerabilidade identificada automaticamente.</p>" if not total_vulns else ""}
      {"".join(vuln_card(v) for v in vuln_mod.get("critical",[])+vuln_mod.get("high",[])+vuln_mod.get("medium",[])+vuln_mod.get("low",[]))}
    </div>
  </div>

  <!-- Disclaimer -->
  <div class="section">
    <div class="section-body" style="color:var(--text2);font-size:13px;">
      <strong>⚠️ Aviso Legal:</strong> Este relatório foi gerado com base em informações publicamente disponíveis.
      Nenhuma invasão, exploração de vulnerabilidade ou acesso não autorizado foi realizado.
      As informações são para fins de diagnóstico e melhoria de segurança. Somente analise sistemas com autorização explícita.
    </div>
  </div>

  <div class="footer">
    Wilker Santana Damazio — CEO · {datetime.fromisoformat(scan_date).strftime('%d/%m/%Y %H:%M') if scan_date else 'N/A'} · Somente dados públicos (OSINT)
  </div>

</div>
</body>
</html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


def generate_json_report(data: dict, output_path: str):
    """Gera relatório em formato JSON."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)