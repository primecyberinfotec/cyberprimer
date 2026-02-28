"""
Gerador de Relatório PREVIEW (Prévia para Cliente)
Mostra o suficiente para gerar interesse — detalhes bloqueados

CORREÇÕES:
  - Fix 1: Score agora penaliza SPF ausente, DMARC ausente, headers HTTP,
            breaches HIBP, portas críticas abertas, SSL expirando/expirado,
            IPs Tor e flags VirusTotal — antes só penalizava CVEs.
  - Fix 2: Alertas bloqueados exibem badge de severidade estimada (🔴/🟠/🟡)
            mesmo sem revelar conteúdo — aumenta impacto comercial.
  - Fix 3: Alertas visíveis são os 3 mais severos, não os 3 primeiros da lista.
  - Fix 4: Texto descritivo do score condicionado ao contexto real (SPF/DMARC
            ausentes geram texto de atenção mesmo com score alto).
  - Fix 5: Localização exibe aviso "(PoP CDN)" quando CDN detectado.
  - Fix 6: flag_row bloqueada usa tamanho real do alerta no blur.
  - Fix 7: Seção Tecnologias mostra mensagem correta para 1-3 detecções.
"""

from datetime import datetime
from pathlib import Path


# ── Peso de cada problema no score ───────────────────────────────────────────
_PENALTY = {
    "spf_missing":        8,
    "dmarc_missing":      8,
    "headers_lt50":      10,
    "headers_lt70":       6,
    "headers_lt80":       3,
    "ssl_expired":       20,
    "ssl_expiring":      10,
    "breach_per":        10,
    "port_critical":     15,
    "tor_exit":          15,
    "vt_malicious":      10,
    "cve_critical":      25,
    "cve_high":          10,
    "cve_medium":         5,
    "cve_low":            2,
}

# ── Severidade estimada de cada tipo de flag ─────────────────────────────────
_FLAG_SEVERITY = {
    "CVE":         ("🔴", "Crítico"),
    "crítica":     ("🔴", "Crítico"),
    "crítico":     ("🔴", "Crítico"),
    "expirado":    ("🔴", "Crítico"),
    "EternalBlue": ("🔴", "Crítico"),
    "BlueKeep":    ("🔴", "Crítico"),
    "WannaCry":    ("🔴", "Crítico"),
    "Tor":         ("🔴", "Crítico"),
    "alto":        ("🟠", "Alto"),
    "high":        ("🟠", "Alto"),
    "expira em":   ("🟠", "Alto"),
    "VirusTotal":  ("🟠", "Alto"),
    "malicioso":   ("🟠", "Alto"),
    "breach":      ("🟠", "Alto"),
    "SPF":         ("🟡", "Médio"),
    "DMARC":       ("🟡", "Médio"),
    "cabeçalho":   ("🟡", "Médio"),
    "Header":      ("🟡", "Médio"),
    "cookie":      ("🟡", "Médio"),
    "Cookie":      ("🟡", "Médio"),
    "X-Powered-By":("🟡", "Médio"),
    "versão":      ("🟡", "Médio"),
    "URLScan":     ("🟢", "Baixo"),
    "CDN":         ("🔵", "Info"),
    "PoP":         ("🔵", "Info"),
}


def _estimate_flag_severity(flag_text: str) -> tuple:
    for keyword, sev in _FLAG_SEVERITY.items():
        if keyword.lower() in flag_text.lower():
            return sev
    return ("🟡", "Médio")


def _sort_flags_by_severity(flags: list) -> list:
    """FIX 3: Ordena flags pela severidade estimada (crítico primeiro)."""
    order = {"🔴": 0, "🟠": 1, "🟡": 2, "🟢": 3, "🔵": 4}
    return sorted(flags, key=lambda f: order.get(_estimate_flag_severity(f)[0], 5))


def _calc_score(n_crit, n_high, n_med, n_low,
                spf_ok, dmarc_ok, headers_pct,
                ssl_cert, breach_count,
                ports_mod, osint_mod, ip_mod) -> int:
    """FIX 1: Score com penalidades de todos os módulos."""
    penalty = 0

    penalty += min(n_crit * _PENALTY["cve_critical"], 50)
    penalty += min(n_high * _PENALTY["cve_high"],     30)
    penalty += min(n_med  * _PENALTY["cve_medium"],   20)
    penalty += min(n_low  * _PENALTY["cve_low"],      10)

    if not spf_ok:
        penalty += _PENALTY["spf_missing"]
    if not dmarc_ok:
        penalty += _PENALTY["dmarc_missing"]

    if headers_pct < 50:
        penalty += _PENALTY["headers_lt50"]
    elif headers_pct < 70:
        penalty += _PENALTY["headers_lt70"]
    elif headers_pct < 80:
        penalty += _PENALTY["headers_lt80"]

    if ssl_cert:
        if ssl_cert.get("expired"):
            penalty += _PENALTY["ssl_expired"]
        elif ssl_cert.get("expiring_soon"):
            penalty += _PENALTY["ssl_expiring"]

    penalty += min(breach_count * _PENALTY["breach_per"], 20)

    critical_ports = [p for p in ports_mod.get("open_ports", []) if p.get("risk") == "critical"]
    penalty += min(len(critical_ports) * _PENALTY["port_critical"], 30)

    if ip_mod.get("is_tor_exit"):
        penalty += _PENALTY["tor_exit"]

    if osint_mod.get("virustotal", {}).get("malicious", 0) > 0:
        penalty += _PENALTY["vt_malicious"]

    return max(0, min(100, 100 - penalty))


def generate_preview_report(data: dict, output_path: str,
                            company_name: str = "Cyber Primer Infortech",
                            analyst_name: str = "Wilker Santana Damazio — CEO"):
    target    = data.get("target", "")
    scan_date = data.get("scan_date", "")
    mods      = data.get("modules", {})

    ip_mod    = mods.get("ip_info",        {})
    dns_mod   = mods.get("dns_enum",       {})
    ports_mod = mods.get("ports",          {})
    ssl_mod   = mods.get("ssl",            {})
    web_mod   = mods.get("web_info",       {})
    osint_mod = mods.get("osint",          {})
    vuln_mod  = mods.get("vulnerabilities", {})

    n_crit = len(vuln_mod.get("critical", []))
    n_high = len(vuln_mod.get("high",     []))
    n_med  = len(vuln_mod.get("medium",   []))
    n_low  = len(vuln_mod.get("low",      []))

    total_ports  = len(ports_mod.get("open_ports", []))
    total_subs   = dns_mod.get("subdomain_count", 0)
    breach_count = osint_mod.get("hibp", {}).get("count", 0)

    ssl_cert    = ssl_mod.get("certificate", {})
    spf_ok      = dns_mod.get("spf",  {}).get("exists", False)
    dmarc_ok    = dns_mod.get("dmarc",{}).get("exists", False)
    headers_pct = web_mod.get("security_headers", {}).get("percentage", 0)
    techs       = web_mod.get("technologies", [])
    geo         = ip_mod.get("geolocation", {})
    cdn_info    = ip_mod.get("cdn_info", {})
    primary_ip  = (ip_mod.get("ips") or ["N/A"])[0]
    ssl_ok      = ssl_cert.get("valid", False)
    days_left   = ssl_cert.get("days_left", "?")
    date_fmt    = datetime.fromisoformat(scan_date).strftime('%d/%m/%Y') if scan_date else datetime.now().strftime('%d/%m/%Y')

    # FIX 1
    sec_score   = _calc_score(n_crit, n_high, n_med, n_low,
                              spf_ok, dmarc_ok, headers_pct,
                              ssl_cert, breach_count,
                              ports_mod, osint_mod, ip_mod)

    score_color = "#e74c3c" if sec_score < 40 else "#f39c12" if sec_score < 70 else "#27ae60"
    score_label = "CRÍTICO" if sec_score < 40 else "REQUER ATENÇÃO" if sec_score < 70 else "BOM"

    # FIX 4
    has_email_issues  = not spf_ok or not dmarc_ok
    has_header_issues = headers_pct < 80
    if sec_score < 40:
        score_title = "Situação crítica identificada"
        score_text  = "Nossa análise identificou exposições graves que podem comprometer dados de clientes, causar prejuízos financeiros e danos à reputação. Ação imediata é recomendada."
    elif sec_score < 70:
        score_title = "Vulnerabilidades importantes encontradas"
        score_text  = "Foram identificados pontos de atenção que precisam de correção para garantir a segurança do ambiente digital da empresa."
    elif has_email_issues:
        score_title = "Infraestrutura com brechas de email"
        score_text  = "A postura geral é positiva, mas o domínio está vulnerável a spoofing e phishing por ausência de SPF/DMARC. Qualquer pessoa pode enviar e-mails falsificando este domínio."
    elif has_header_issues:
        score_title = "Boa postura, cabeçalhos HTTP incompletos"
        score_text  = "A infraestrutura está bem configurada, mas cabeçalhos HTTP incompletos deixam brechas para ataques XSS e clickjacking."
    else:
        score_title = "Boa postura de segurança"
        score_text  = "A análise encontrou pontos de melhoria que, quando corrigidos, elevarão ainda mais o nível de proteção."

    # FIX 3: ordena por severidade
    all_flags = []
    for mod in mods.values():
        if isinstance(mod, dict):
            all_flags.extend(mod.get("risk_flags", []))
    all_flags = list(dict.fromkeys(all_flags))
    all_flags = _sort_flags_by_severity(all_flags)

    visible_flags = all_flags[:3]
    hidden_flags  = all_flags[3:]
    hidden_count  = len(hidden_flags)

    # FIX 5: localização indica CDN
    if cdn_info.get("is_cdn"):
        location_str = f"{geo.get('city','?')}, {geo.get('country','?')} <span style='font-size:11px;opacity:.6;'>(PoP {cdn_info['cdn_name']})</span>"
    else:
        location_str = f"{geo.get('city','?')}, {geo.get('country','?')}"

    def flag_row(text: str, locked: bool = False) -> str:
        """FIX 2 + FIX 6."""
        if locked:
            blur_len  = min(max(len(text), 20), 60)
            blur_text = "█" * blur_len
            icon, sev_name = _estimate_flag_severity(text)
            sev_html = f'<span style="font-size:10px;font-weight:700;color:#6b7280;margin-right:4px">{icon} {sev_name}</span>'
            return (
                f'<div class="flag-item locked">'
                f'<span class="flag-icon">⚠️</span>'
                f'{sev_html}'
                f'<span class="blur-text">{blur_text}</span>'
                f'<span class="lock-badge">🔒 RELATÓRIO COMPLETO</span>'
                f'</div>'
            )
        icon, _ = _estimate_flag_severity(text)
        return f'<div class="flag-item"><span class="flag-icon">{icon}</span><span class="flag-text">{text}</span></div>'

    visible_rows = "".join(flag_row(f) for f in visible_flags)
    locked_rows  = "".join(flag_row(f, locked=True) for f in hidden_flags[:5])
    more_note    = (f'<div class="more-locked">🔒 {hidden_count} alertas adicionais disponíveis no relatório completo</div>'
                    if hidden_count else "")

    # FIX 7: Tecnologias
    techs_visible = techs[:3]
    techs_locked  = techs[3:]
    tech_pills    = "".join(f'<span class="tech-pill">{t}</span>' for t in techs_visible)
    if techs_locked:
        tech_pills += "".join('<span class="tech-pill tech-locked">████████</span>' for _ in range(min(len(techs_locked), 4)))
        tech_pills += '<span class="tech-pill" style="color:#9ca3af;background:#f9fafb">🔒 +detalhes no completo</span>'
    if not techs:
        tech_pills = '<span class="tech-pill" style="color:#9ca3af">Detecção via CDN limitada — disponível no relatório completo</span>'

    infra_str = (geo.get("org") or geo.get("isp", "N/A"))[:32]
    if cdn_info.get("is_cdn"):
        infra_str = f'{cdn_info["cdn_name"]} CDN'

    # ── Score breakdown — scorecard completo de todos os fatores avaliados ──────
    # Mostra TODOS os itens (passando = verde, falhando = vermelho)
    # para deixar claro como o score acumula de cada categoria.
    def _pill(label: str, pts: int) -> str:
        """Gera pill colorida: vermelha se penalidade, verde se OK."""
        if pts < 0:
            return f'<span class="score-item penalty">−{abs(pts)}pts {label}</span>'
        return f'<span class="score-item ok">✓ {label}</span>'

    # Calcula cada penalidade individualmente para exibição
    _p_spf     = -_PENALTY["spf_missing"]  if not spf_ok   else 0
    _p_dmarc   = -_PENALTY["dmarc_missing"] if not dmarc_ok else 0
    if headers_pct < 50:   _p_hdrs = -_PENALTY["headers_lt50"]
    elif headers_pct < 70: _p_hdrs = -_PENALTY["headers_lt70"]
    elif headers_pct < 80: _p_hdrs = -_PENALTY["headers_lt80"]
    else:                  _p_hdrs = 0
    _p_ssl  = (-_PENALTY["ssl_expired"] if ssl_cert.get("expired")
               else -_PENALTY["ssl_expiring"] if ssl_cert.get("expiring_soon") else 0)
    _p_vuln_c = -min(n_crit * _PENALTY["cve_critical"], 50) if n_crit else 0
    _p_vuln_h = -min(n_high * _PENALTY["cve_high"],     30) if n_high else 0
    _p_vuln_m = -min(n_med  * _PENALTY["cve_medium"],   20) if n_med  else 0
    _p_vuln_l = -min(n_low  * _PENALTY["cve_low"],      10) if n_low  else 0
    _p_breach = -min(breach_count * _PENALTY["breach_per"], 20) if breach_count else 0
    _p_tor    = -_PENALTY["tor_exit"]   if ip_mod.get("is_tor_exit")                         else 0
    _p_vt     = -_PENALTY["vt_malicious"] if osint_mod.get("virustotal", {}).get("malicious", 0) > 0 else 0

    breakdown_pills = "".join([
        _pill("SPF",                  _p_spf),
        _pill("DMARC",                _p_dmarc),
        _pill(f"Cabeçalhos HTTP ({headers_pct}%)", _p_hdrs),
        _pill("SSL/TLS",              _p_ssl),
        _pill("Vulnerabilidades (CVEs)", _p_vuln_c or _p_vuln_h or _p_vuln_m or _p_vuln_l),
        _pill("Breaches Públicos",    _p_breach),
        _pill("VirusTotal",           _p_vt),
        _pill("Tor Exit Node",        _p_tor),
    ])

    # Score total acumulado (soma de todas as penalidades)
    _total_penalty = abs(_p_spf + _p_dmarc + _p_hdrs + _p_ssl +
                         _p_vuln_c + _p_vuln_h + _p_vuln_m + _p_vuln_l +
                         _p_breach + _p_tor + _p_vt)
    breakdown_summary = (
        f'<div class="score-total">'
        f'Score: 100 − {_total_penalty}pts de penalidades = <strong>{sec_score}</strong>/100'
        f'</div>'
    )

    # SSL status
    if ssl_cert.get("expired"):
        ssl_status_cls  = "s-bad"
        ssl_status_text = "❌ Expirado"
    elif ssl_cert.get("expiring_soon"):
        ssl_status_cls  = "s-warn"
        ssl_status_text = f"⚠️ Expira em {days_left} dias"
    elif ssl_ok and days_left != "?":
        ssl_status_cls  = "s-ok"
        ssl_status_text = f"✅ Válido — {days_left} dias"
    elif ssl_ok:
        ssl_status_cls  = "s-ok"
        ssl_status_text = "✅ Válido"
    else:
        ssl_status_cls  = "s-bad"
        ssl_status_text = "❌ Inválido"

    headers_cls = "s-ok" if headers_pct >= 80 else "s-warn" if headers_pct >= 50 else "s-bad"
    headers_ico = "✅" if headers_pct >= 80 else "⚠️" if headers_pct >= 50 else "❌"
    breach_cls  = "s-bad" if breach_count > 0 else "s-ok"
    breach_text = f"⚠️ {breach_count} breach(es) encontrado(s)" if breach_count else "✅ Nenhum breach encontrado"

    email_alert = ""
    if not spf_ok or not dmarc_ok:
        missing = []
        if not spf_ok:  missing.append("SPF")
        if not dmarc_ok: missing.append("DMARC")
        email_alert = f'''<div class="email-alert">
  <strong>⚠️ Risco de Spoofing e Phishing — {" e ".join(missing)} ausente(s)</strong>
  <span>Qualquer pessoa pode enviar e-mails se passando por <b>{target}</b> — risco direto de golpes contra clientes e parceiros da empresa.</span>
</div>'''

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Prévia de Segurança — {target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Inter',sans-serif;background:#f0f2f5;color:#1a1a2e;line-height:1.6}}
  .page{{max-width:860px;margin:0 auto;background:white;box-shadow:0 4px 40px rgba(0,0,0,.12)}}
  .header{{background:linear-gradient(135deg,#0d0d1a 0%,#1a1a2e 50%,#0f3460 100%);color:white;padding:52px 48px 44px;position:relative;overflow:hidden}}
  .header::before{{content:'';position:absolute;top:-60px;right:-60px;width:300px;height:300px;background:rgba(99,102,241,.15);border-radius:50%}}
  .header::after{{content:'';position:absolute;bottom:-80px;left:40%;width:200px;height:200px;background:rgba(16,185,129,.1);border-radius:50%}}
  .company-badge{{display:inline-flex;align-items:center;gap:8px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2);border-radius:20px;padding:5px 14px;font-size:11px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;margin-bottom:28px}}
  .header h1{{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:2px;color:rgba(255,255,255,.55);margin-bottom:10px}}
  .header h2{{font-size:30px;font-weight:800;margin-bottom:6px}}
  .header .target{{font-size:15px;color:rgba(255,255,255,.65);font-family:monospace;margin-bottom:28px}}
  .header-meta{{display:flex;gap:24px;flex-wrap:wrap}}
  .meta-item{{font-size:12px;color:rgba(255,255,255,.5)}}
  .meta-item strong{{color:rgba(255,255,255,.9);display:block;font-size:13px;margin-top:2px}}
  .confidential{{position:absolute;top:20px;right:48px;background:rgba(231,76,60,.2);border:1px solid rgba(231,76,60,.4);color:#ff8a80;font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;padding:4px 12px;border-radius:4px}}
  .score-hero{{background:linear-gradient(135deg,#1a1a2e,#0f3460);color:white;padding:40px 48px;display:flex;align-items:center;gap:48px;flex-wrap:wrap}}
  .score-ring-wrap{{text-align:center;flex-shrink:0}}
  .score-ring-wrap svg{{width:140px;height:140px}}
  .score-num{{font-size:38px;font-weight:900;fill:{score_color}}}
  .score-sub{{font-size:11px;fill:rgba(255,255,255,.45)}}
  .score-label{{font-size:15px;font-weight:800;color:{score_color};margin-top:8px;letter-spacing:1px}}
  .score-desc{{flex:1;min-width:200px}}
  .score-desc h3{{font-size:20px;font-weight:700;margin-bottom:10px}}
  .score-desc p{{font-size:14px;color:rgba(255,255,255,.65);line-height:1.7}}
  .score-breakdown{{margin-top:14px;display:flex;flex-wrap:wrap;gap:8px}}
  .score-item{{font-size:11px;color:rgba(255,255,255,.5);background:rgba(255,255,255,.07);border-radius:6px;padding:4px 10px}}
  .score-item.penalty{{color:#ff8a80;background:rgba(231,76,60,.15)}}
  .score-item.ok{{color:#6ee7b7;background:rgba(39,174,96,.12)}}
  .score-total{{margin-top:12px;font-size:12px;color:rgba(255,255,255,.45);letter-spacing:.3px}}
  .score-total strong{{color:rgba(255,255,255,.9)}}
  .counters{{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:1px;background:#e5e7eb;border-top:1px solid #e5e7eb;border-bottom:1px solid #e5e7eb}}
  .counter{{background:white;padding:20px 12px;text-align:center}}
  .counter .num{{font-size:34px;font-weight:900;line-height:1;margin-bottom:4px}}
  .counter .lbl{{font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.5px;font-weight:600}}
  .c-crit .num{{color:#e74c3c}}.c-high .num{{color:#f39c12}}.c-med .num{{color:#d4ac0d}}.c-low .num{{color:#27ae60}}.c-blue .num{{color:#3b82f6}}
  .section{{padding:32px 48px;border-bottom:1px solid #f0f2f5}}
  .section-title{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;color:#6b7280;margin-bottom:18px;display:flex;align-items:center;gap:8px}}
  .section-title::after{{content:'';flex:1;height:1px;background:#e5e7eb}}
  .flag-item{{display:flex;align-items:center;gap:10px;padding:11px 14px;background:#fffbf0;border:1px solid #fde68a;border-radius:8px;margin-bottom:8px}}
  .flag-item.locked{{background:#f9fafb;border-color:#e5e7eb}}
  .flag-icon{{font-size:15px;flex-shrink:0}}
  .flag-text{{font-size:13px;font-weight:500;flex:1}}
  .blur-text{{filter:blur(5px);user-select:none;color:#9ca3af;flex:1;letter-spacing:2px}}
  .lock-badge{{background:#1a1a2e;color:white;font-size:10px;font-weight:700;padding:3px 10px;border-radius:20px;white-space:nowrap;letter-spacing:.3px}}
  .more-locked{{text-align:center;padding:14px;color:#9ca3af;font-size:13px;margin-top:4px}}
  .email-alert{{background:#fff1f0;border:1px solid #ffccc7;border-radius:10px;padding:16px 20px;margin-bottom:16px}}
  .email-alert strong{{color:#e74c3c;display:block;margin-bottom:4px;font-size:13px}}
  .email-alert span{{font-size:12px;color:#595959;line-height:1.6}}
  .status-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:12px}}
  .status-card{{border:1px solid #e5e7eb;border-radius:10px;padding:14px 16px}}
  .status-card .s-label{{font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:.5px;font-weight:600;margin-bottom:6px}}
  .status-card .s-value{{font-size:13px;font-weight:700;line-height:1.4}}
  .s-ok{{color:#27ae60}}.s-warn{{color:#f39c12}}.s-bad{{color:#e74c3c}}.s-neu{{color:#3b82f6}}
  .tech-list{{display:flex;flex-wrap:wrap;gap:8px;margin-top:4px}}
  .tech-pill{{background:#f0f2f5;border:1px solid #e5e7eb;border-radius:20px;padding:5px 14px;font-size:12px;font-weight:600;color:#374151}}
  .tech-locked{{filter:blur(4px);user-select:none}}
  .cta-section{{background:linear-gradient(135deg,#0f3460,#1a1a2e);color:white;padding:52px 48px;text-align:center}}
  .cta-section h2{{font-size:26px;font-weight:800;margin-bottom:12px}}
  .cta-section p{{font-size:14px;color:rgba(255,255,255,.65);margin-bottom:32px;max-width:500px;margin-left:auto;margin-right:auto;line-height:1.8}}
  .cta-box{{display:inline-flex;flex-direction:column;gap:8px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.15);border-radius:12px;padding:24px 40px}}
  .cta-label{{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,.45)}}
  .cta-contact{{font-size:18px;font-weight:700;color:white}}
  .cta-includes{{display:flex;justify-content:center;gap:32px;margin-top:36px;flex-wrap:wrap}}
  .cta-item .ci-icon{{font-size:28px;margin-bottom:6px;text-align:center}}
  .cta-item .ci-text{{font-size:12px;color:rgba(255,255,255,.55);font-weight:500;text-align:center}}
  .footer{{background:#0d0d1a;color:rgba(255,255,255,.3);text-align:center;padding:18px;font-size:11px}}
  @media(max-width:600px){{.header,.score-hero,.section,.cta-section{{padding:28px 20px}}.header h2{{font-size:22px}}.confidential{{display:none}}}}
</style>
</head>
<body><div class="page">

<div class="header">
  <div class="confidential">CONFIDENCIAL</div>
  <div class="company-badge">🛡️ {company_name}</div>
  <h1>Relatório de Exposição Digital — Prévia</h1>
  <h2>Análise de Segurança Externa</h2>
  <div class="target">🎯 <a href="https://{target}" target="_blank" rel="noopener" style="color:rgba(255,255,255,.85);text-decoration:underline;text-decoration-color:rgba(255,255,255,.35);">{target} ↗</a></div>
  <div class="header-meta">
    <div class="meta-item">Data da Análise<strong>{date_fmt}</strong></div>
    <div class="meta-item">Responsável<strong>{analyst_name}</strong></div>
    <div class="meta-item">Servidor<strong>{location_str}</strong></div>
    <div class="meta-item">IP Principal<strong>{primary_ip}</strong></div>
  </div>
</div>

<div class="score-hero">
  <div class="score-ring-wrap">
    <svg viewBox="0 0 140 140">
      <circle cx="70" cy="70" r="58" fill="none" stroke="rgba(255,255,255,.1)" stroke-width="10"/>
      <circle cx="70" cy="70" r="58" fill="none" stroke="{score_color}" stroke-width="10"
        stroke-dasharray="{round(sec_score*3.64)} 364" stroke-dashoffset="91"
        stroke-linecap="round" transform="rotate(-90 70 70)"/>
      <text x="70" y="65" text-anchor="middle" class="score-num">{sec_score}</text>
      <text x="70" y="82" text-anchor="middle" class="score-sub">/ 100</text>
    </svg>
    <div class="score-label">{score_label}</div>
  </div>
  <div class="score-desc">
    <h3>{score_title}</h3>
    <p>{score_text}</p>
    <div class="score-breakdown">
      {breakdown_pills}
    </div>
    {breakdown_summary}
  </div>
</div>

<div class="counters">
  <div class="counter c-crit"><div class="num">{n_crit}</div><div class="lbl">🔴 Crítico</div></div>
  <div class="counter c-high"><div class="num">{n_high}</div><div class="lbl">🟠 Alto</div></div>
  <div class="counter c-med" ><div class="num">{n_med}</div><div class="lbl">🟡 Médio</div></div>
  <div class="counter c-low" ><div class="num">{n_low}</div><div class="lbl">🟢 Baixo</div></div>
  <div class="counter c-blue"><div class="num">{total_ports}</div><div class="lbl">🔌 Portas</div></div>
  <div class="counter c-blue"><div class="num">{total_subs}</div><div class="lbl">🌐 Subdomínios</div></div>
</div>

<div class="section">
  <div class="section-title">⚠️ Alertas Identificados</div>
  {visible_rows or '<p style="color:#9ca3af;font-size:13px;">Nenhum alerta crítico identificado nesta prévia.</p>'}
  {locked_rows}
  {more_note}
</div>

<div class="section">
  <div class="section-title">📋 Diagnóstico Rápido</div>
  {email_alert}
  <div class="status-grid">
    <div class="status-card"><div class="s-label">Certificado SSL</div>
      <div class="s-value {ssl_status_cls}">{ssl_status_text}</div></div>
    <div class="status-card"><div class="s-label">Anti-Spoofing (SPF)</div>
      <div class="s-value {'s-ok' if spf_ok else 's-bad'}">{'✅ Configurado' if spf_ok else '❌ Ausente — risco de spoofing'}</div></div>
    <div class="status-card"><div class="s-label">Anti-Phishing (DMARC)</div>
      <div class="s-value {'s-ok' if dmarc_ok else 's-bad'}">{'✅ Configurado' if dmarc_ok else '❌ Ausente — risco de phishing'}</div></div>
    <div class="status-card"><div class="s-label">Cabeçalhos HTTP</div>
      <div class="s-value {headers_cls}">{headers_pct}% configurados {headers_ico}</div></div>
    <div class="status-card"><div class="s-label">Vazamentos Públicos</div>
      <div class="s-value {breach_cls}">{breach_text}</div></div>
    <div class="status-card"><div class="s-label">Infraestrutura</div>
      <div class="s-value s-neu">{infra_str}</div></div>
  </div>
</div>

<div class="section">
  <div class="section-title">🖥️ Tecnologias Detectadas</div>
  <div class="tech-list">{tech_pills}</div>
</div>

<div class="section">
  <div class="section-title">📦 O Que Está no Relatório Completo</div>
  <div class="status-grid">
    <div class="status-card"><div class="s-label">🔌 Portas & Serviços</div><div class="s-value s-neu" style="font-size:12px">Mapeamento completo com versões e CVEs</div></div>
    <div class="status-card"><div class="s-label">🌐 Subdomínios</div><div class="s-value s-neu" style="font-size:12px">Todos os {total_subs} subdomínios descobertos</div></div>
    <div class="status-card"><div class="s-label">🔒 SSL/TLS</div><div class="s-value s-neu" style="font-size:12px">Análise de protocolos e cipher suites</div></div>
    <div class="status-card"><div class="s-label">🛡️ Vulnerabilidades</div><div class="s-value s-neu" style="font-size:12px">{n_crit+n_high+n_med+n_low} CVEs com detalhes técnicos</div></div>
    <div class="status-card"><div class="s-label">🕵️ OSINT</div><div class="s-value s-neu" style="font-size:12px">Exposição em bases públicas</div></div>
    <div class="status-card"><div class="s-label">🔧 Remediação</div><div class="s-value s-neu" style="font-size:12px">Passo a passo de correção priorizado</div></div>
  </div>
</div>

<div class="cta-section">
  <h2>Proteja sua empresa agora</h2>
  <p>Esta prévia mostra apenas uma fração do que identificamos. O relatório completo contém todos os detalhes técnicos, evidências de exposição e um plano de remediação com prioridades definidas.</p>
  <div class="cta-box">
    <span class="cta-label">Entre em contato para receber o relatório completo</span>
    <span class="cta-contact">📧 primecyberinfotec@gmail.com</span>
    <span class="cta-contact" style="font-size:13px;opacity:.8;">🌐 primecyberinfotec.github.io/cyberprimer</span>
  </div>
  <div class="cta-includes">
    <div class="cta-item"><div class="ci-icon">📋</div><div class="ci-text">Relatório Técnico<br>Completo</div></div>
    <div class="cta-item"><div class="ci-icon">🔧</div><div class="ci-text">Plano de<br>Remediação</div></div>
    <div class="cta-item"><div class="ci-icon">📞</div><div class="ci-text">Reunião de<br>Apresentação</div></div>
    <div class="cta-item"><div class="ci-icon">🛡️</div><div class="ci-text">Suporte na<br>Correção</div></div>
  </div>
</div>

<div class="footer">
  {company_name} · CNPJ 51.698.369/0001-50 · Barra do Garças — MT — Brasil · primecyberinfotec@gmail.com · {date_fmt} · Documento confidencial
</div>

</div></body></html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
