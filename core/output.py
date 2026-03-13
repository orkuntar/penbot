import json
import os
from datetime import datetime
from config import REPORTS_DIR


def save_scan(target: str, mode: str, aggressive: bool, results: dict) -> str:
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_")
    filename    = f"{safe_target}_{mode}_{timestamp}.json"
    filepath    = os.path.join(REPORTS_DIR, filename)
    data = {
        "meta": {
            "target":     target,
            "mode":       mode,
            "aggressive": aggressive,
            "timestamp":  datetime.now().isoformat(),
            "tool":       "GREYPHANTOM",
        },
        "results": results,
    }
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return filepath


def load_last_scan() -> dict | None:
    files = sorted(
        [f for f in os.listdir(REPORTS_DIR) if f.endswith(".json")],
        reverse=True,
    )
    if not files:
        return None
    with open(os.path.join(REPORTS_DIR, files[0])) as f:
        return json.load(f)


def _sev_order(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev.lower(), 9)


def format_for_claude(data: dict) -> str:
    meta    = data.get("meta", {})
    results = data.get("results", {})
    lines   = [
        "=" * 65,
        "GREYPHANTOM — CLAUDE ANALİZ ÖZET",
        "=" * 65,
        f"Hedef    : {meta.get('target')}",
        f"Mod      : {meta.get('mode')} | Agresif: {'EVET' if meta.get('aggressive') else 'HAYIR'}",
        f"Tarih    : {meta.get('timestamp', '')[:19]}",
        "",
    ]

    # ── Recon ────────────────────────────────────────────────────────────────
    subs  = results.get("subdomains", [])
    alive = results.get("alive_hosts", [])
    lines += [f"[RECON] Subdomain: {len(subs)} | Canlı: {len(alive)}"]
    for h in alive[:20]:
        lines.append(f"  {h}")
    lines.append("")

    # ── Portlar ───────────────────────────────────────────────────────────────
    naabu = results.get("naabu_ports", [])
    ports = results.get("open_ports", {})
    if naabu:
        lines.append(f"[NAABU] {len(naabu)} açık port:")
        for p in naabu[:20]:
            lines.append(f"  {p.get('host')}:{p.get('port')}")
        lines.append("")
    elif ports:
        lines.append("[NMAP] Açık portlar:")
        for host, pl in ports.items():
            lines.append(f"  {host}: {', '.join(str(p) for p in pl)}")
        lines.append("")

    # ── SSL/TLS ───────────────────────────────────────────────────────────────
    testssl = results.get("testssl", {})
    if testssl.get("findings"):
        lines.append("[TESTSSL] Bulgular:")
        for f in testssl["findings"][:10]:
            lines.append(f"  [{f['severity']}] {f['finding']}")
        lines.append("")

    # ── Teknolojiler ──────────────────────────────────────────────────────────
    techs = results.get("technologies", [])
    if techs:
        lines.append(f"[FİNGERPRİNT] {', '.join(techs[:15])}")
        lines.append("")

    # ── Sensitive Data ────────────────────────────────────────────────────────
    secrets = results.get("secret_findings", [])
    if secrets:
        lines.append(f"[🔴 SENSITIVE DATA] {len(secrets)} hassas veri tespit edildi:")
        for s in secrets[:15]:
            lines.append(f"  [{s['severity']}] {s['type']}: {s['value']} → {s['url']}")
        lines.append("")

    # ── HTTP Method Fuzzing ───────────────────────────────────────────────────
    methods = results.get("method_findings", [])
    unexpected = [m for m in methods if m.get('status') == 200 and m.get('method') not in ('GET', 'HEAD')]
    if unexpected:
        lines.append(f"[HTTP METHODS] {len(unexpected)} beklenmedik metod:")
        for m in unexpected[:15]:
            lines.append(f"  [{m['method']}] {m['url']} → {m['status']}")
        lines.append("")

    # ── IDOR ──────────────────────────────────────────────────────────────────
    idor = results.get("idor_findings", [])
    if idor:
        lines.append(f"[IDOR] {len(idor)} bulgu:")
        for i in idor[:10]:
            lines.append(f"  [HIGH] {i['url']} — {i.get('note', '')}")
        lines.append("")

    # ── Mass Assignment ───────────────────────────────────────────────────────
    mass = results.get("mass_assignment", [])
    if mass:
        lines.append(f"[MASS ASSIGNMENT] {len(mass)} bulgu:")
        for m in mass[:5]:
            lines.append(f"  [HIGH] {m['url']} payload: {m['payload']}")
        lines.append("")

    # ── Error Disclosure ──────────────────────────────────────────────────────
    errors = results.get("error_disclosure", [])
    if errors:
        lines.append(f"[ERROR DISCLOSURE] {len(errors)} bulgu:")
        for e in errors[:10]:
            lines.append(f"  [{e['severity']}] {e['type']}: {e['url']}")
        lines.append("")

    # ── Auth Test ─────────────────────────────────────────────────────────────
    login_ep = results.get("login_endpoint")
    if login_ep:
        lines.append(f"[AUTH] Login endpoint: {login_ep}")

    rate = results.get("rate_limit", {})
    if rate:
        if not rate.get("blocked"):
            lines.append(f"  [HIGH] Rate limiting YOK — brute force mümkün")
        else:
            lines.append(f"  [INFO] Rate limiting var, {rate.get('block_at')} denemede bloklandı")

    default = results.get("default_creds", [])
    if default:
        for d in default:
            lines.append(f"  [CRITICAL] Default creds: {d['username']}:{d['password']}")

    sql_bp = results.get("sql_bypass", [])
    if sql_bp:
        for s in sql_bp:
            if s.get("severity") == "CRITICAL":
                lines.append(f"  [CRITICAL] SQL Auth Bypass: {s['payload']}")

    nosql_bp = results.get("nosql_bypass", [])
    if nosql_bp:
        for n in nosql_bp:
            lines.append(f"  [CRITICAL] NoSQL Auth Bypass: {n['payload']}")

    if any([login_ep, rate, default, sql_bp, nosql_bp]):
        lines.append("")

    # ── GraphQL ───────────────────────────────────────────────────────────────
    gql = results.get("graphql", {})
    if gql.get("introspection"):
        lines.append(f"[GRAPHQL] Introspection AÇIK — endpoint: {gql.get('endpoint')}")
        lines.append(f"  Types: {', '.join(gql.get('types', [])[:10])}")
        lines.append(f"  Queries: {', '.join(gql.get('queries', [])[:10])}")
        if gql.get("mutations"):
            lines.append(f"  Mutations: {', '.join(gql.get('mutations', [])[:10])}")
        lines.append("")

    # ── Info Endpoints ────────────────────────────────────────────────────────
    info_eps = results.get("info_endpoints", [])
    if info_eps:
        lines.append(f"[INFO ENDPOINTS] {len(info_eps)} bulgu:")
        for ep in info_eps[:15]:
            lines.append(f"  [{ep['severity']}] {ep['url']} — {ep.get('note', '')}")
        lines.append("")

    # ── WebSocket ─────────────────────────────────────────────────────────────
    ws = results.get("websocket", {})
    if ws.get("found"):
        lines.append(f"[WEBSOCKET] Endpoint bulundu:")
        for ep in ws.get("endpoints", []):
            lines.append(f"  {ep['path']} [{ep['status']}]")
        lines.append("")

    # ── CORS ─────────────────────────────────────────────────────────────────
    cors = results.get("cors_advanced", [])
    if cors:
        lines.append(f"[CORS] {len(cors)} bulgu:")
        for c in cors[:5]:
            lines.append(f"  [{c['severity']}] Origin: {c['origin']} — {c.get('note', '')}")
        lines.append("")

    # ── SSRF ─────────────────────────────────────────────────────────────────
    ssrf = results.get("ssrf", [])
    if ssrf:
        lines.append(f"[SSRF] {len(ssrf)} bulgu:")
        for s in ssrf[:5]:
            lines.append(f"  [CRITICAL] {s['url']} — {s['payload']}")
        lines.append("")

    # ── JS Analiz ─────────────────────────────────────────────────────────────
    js_secrets = results.get("js_secrets", [])
    js_files   = results.get("js_files", [])
    trufflehog = results.get("trufflehog", [])
    if js_files or js_secrets:
        lines.append(f"[JS] {len(js_files)} dosya, {len(js_secrets)} secret")
        for s in js_secrets[:5]:
            lines.append(f"  [HIGH] {s.get('finding', '')[:80]}")
        for t in trufflehog[:3]:
            lines.append(f"  [{'CRITICAL' if t.get('verified') else 'MEDIUM'}] {t.get('detector')}: {t.get('raw','')[:60]}")
        lines.append("")

    # ── Subdomain Takeover ────────────────────────────────────────────────────
    takeover = results.get("takeover", [])
    if takeover:
        lines.append(f"[TAKEOVER] {len(takeover)} VULNERABLE:")
        for t in takeover:
            lines.append(f"  [HIGH] {t.get('subdomain')}")
        lines.append("")

    # ── API Endpoints ─────────────────────────────────────────────────────────
    kr_eps  = results.get("kr_endpoints", [])
    api_eps = results.get("api_endpoints", [])
    if kr_eps or api_eps:
        lines.append(f"[API] Kiterunner: {len(kr_eps)} | FFUF: {len(api_eps)}")
        for ep in (kr_eps + api_eps)[:15]:
            lines.append(f"  [{ep.get('status')}] {ep.get('url')}")
        lines.append("")

    # ── Nuclei ────────────────────────────────────────────────────────────────
    nuclei = sorted(
        results.get("nuclei_findings", []),
        key=lambda x: _sev_order(x.get("severity", "info"))
    )
    if nuclei:
        lines.append(f"[NUCLEİ] {len(nuclei)} bulgu:")
        for n in nuclei[:20]:
            sev  = n.get("severity", "?").upper()
            name = n.get("template-id", n.get("name", "?"))
            host = n.get("host", "")
            lines.append(f"  [{sev}] {name} → {host}")
    else:
        lines.append("[NUCLEİ] Bulgu yok")
    lines.append("")

    # ── ffuf ─────────────────────────────────────────────────────────────────
    ffuf_hits = results.get("ffuf_hits", [])
    if ffuf_hits:
        lines.append(f"[FFUF] {len(ffuf_hits)} dizin/dosya:")
        for h in ffuf_hits[:10]:
            lines.append(f"  [{h.get('status')}] {h.get('url')}")
        lines.append("")

    lines += [
        "=" * 65,
        "Bu çıktıyı Claude'a yapıştır:",
        "'Bu pentest taramasını analiz et, öncelikli saldırı",
        " vektörlerini ve exploit adımlarını söyle.'",
        "=" * 65,
    ]
    return "\n".join(lines)