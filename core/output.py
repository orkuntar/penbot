import json
import os
from datetime import datetime
from config import REPORTS_DIR


def save_scan(target: str, mode: str, aggressive: bool, results: dict) -> str:
    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_")
    filename   = f"{safe_target}_{mode}_{timestamp}.json"
    filepath   = os.path.join(REPORTS_DIR, filename)

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
    if len(alive) > 20:
        lines.append(f"  ... +{len(alive)-20}")
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
    ssl = results.get("sslscan", {})
    if ssl.get("findings"):
        lines.append("[SSL] Bulgular:")
        for f in ssl["findings"]:
            lines.append(f"  [{f['severity']}] {f['finding']}")
        lines.append("")

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

    # ── URL & Crawl ───────────────────────────────────────────────────────────
    urls     = results.get("urls", [])
    int_urls = results.get("interesting_urls", [])
    lines.append(f"[CRAWL] Toplam URL: {len(urls)}")
    if int_urls:
        lines.append("Dikkat çeken URL'ler:")
        for u in int_urls[:15]:
            lines.append(f"  {u}")
    lines.append("")

    # ── API Endpoints ─────────────────────────────────────────────────────────
    kr_eps  = results.get("kr_endpoints", [])
    api_eps = results.get("api_endpoints", [])
    if kr_eps or api_eps:
        lines.append(f"[API] Kiterunner: {len(kr_eps)} | FFUF: {len(api_eps)}")
        for ep in (kr_eps + api_eps)[:20]:
            lines.append(f"  [{ep.get('status')}] {ep.get('url')}")
        lines.append("")

    # ── CORS ─────────────────────────────────────────────────────────────────
    cors = results.get("cors_findings", [])
    if cors:
        lines.append(f"[CORS] {len(cors)} bulgu:")
        for c in cors:
            lines.append(f"  {c.get('url')}: {c.get('finding','')[:100]}")
        lines.append("")

    # ── GraphQL ───────────────────────────────────────────────────────────────
    gql = results.get("graphql", [])
    if gql:
        lines.append(f"[GRAPHQL] {len(gql)} endpoint tespit edildi")
        lines.append("")

    # ── JS Analiz ─────────────────────────────────────────────────────────────
    js_files    = results.get("js_files", [])
    js_secrets  = results.get("js_secrets", [])
    js_eps      = results.get("js_endpoints", [])
    trufflehog  = results.get("trufflehog", [])
    if js_files:
        lines.append(f"[JS] {len(js_files)} JS dosyası, {len(js_eps)} endpoint, {len(js_secrets)} secret")
        for s in js_secrets[:10]:
            lines.append(f"  [HIGH] {s.get('finding','')[:100]} → {s.get('source','')}")
        for t in trufflehog[:5]:
            sev = "CRITICAL" if t.get("verified") else "MEDIUM"
            lines.append(f"  [{sev}] {t.get('detector')}: {t.get('raw','')[:80]}")
        lines.append("")

    # ── Subdomain Takeover ────────────────────────────────────────────────────
    takeover = results.get("takeover", [])
    if takeover:
        lines.append(f"[TAKEOVER] {len(takeover)} VULNERABLE:")
        for t in takeover:
            lines.append(f"  [HIGH] {t.get('subdomain')}")
        lines.append("")

    # ── Nuclei ────────────────────────────────────────────────────────────────
    nuclei = sorted(
        results.get("nuclei_findings", []),
        key=lambda x: _sev_order(x.get("severity", "info"))
    )
    if nuclei:
        lines.append(f"[NUCLEİ] {len(nuclei)} bulgu:")
        for n in nuclei[:30]:
            sev  = n.get("severity", "?").upper()
            name = n.get("template-id", n.get("name", "?"))
            host = n.get("host", "")
            lines.append(f"  [{sev}] {name} → {host}")
        if len(nuclei) > 30:
            lines.append(f"  ... +{len(nuclei)-30}")
    else:
        lines.append("[NUCLEİ] Bulgu yok")
    lines.append("")

    # ── Gizli Parametreler ────────────────────────────────────────────────────
    params = results.get("hidden_params", {})
    if params:
        lines.append("[ARJUN] Gizli parametreler:")
        for url, pl in params.items():
            lines.append(f"  {url}: {', '.join(pl)}")
        lines.append("")

    # ── GF Patterns ───────────────────────────────────────────────────────────
    gf = results.get("gf_matches", {})
    if gf:
        lines.append("[GF] Pattern eşleşmeleri:")
        for pattern, matches in gf.items():
            if matches:
                lines.append(f"  {pattern}: {len(matches)} adet")
                for m in matches[:3]:
                    lines.append(f"    {m}")
        lines.append("")

    # ── ffuf ─────────────────────────────────────────────────────────────────
    ffuf_hits = results.get("ffuf_hits", [])
    if ffuf_hits:
        lines.append(f"[FFUF] {len(ffuf_hits)} dizin/dosya:")
        for h in ffuf_hits[:15]:
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