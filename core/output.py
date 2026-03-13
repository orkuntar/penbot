import json
import os
from datetime import datetime
from config import REPORTS_DIR


def save_scan(target: str, mode: str, aggressive: bool, results: dict) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_")
    filename = f"{safe_target}_{mode}_{timestamp}.json"
    filepath = os.path.join(REPORTS_DIR, filename)

    data = {
        "meta": {
            "target":     target,
            "mode":       mode,
            "aggressive": aggressive,
            "timestamp":  datetime.now().isoformat(),
            "tool":       "penbot",
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


def format_for_claude(data: dict) -> str:
    meta    = data.get("meta", {})
    results = data.get("results", {})

    lines = [
        "=" * 60,
        "PENBOT — CLAUDE ANALİZ ÖZET",
        "=" * 60,
        f"Hedef    : {meta.get('target')}",
        f"Mod      : {meta.get('mode')} | Agresif: {'EVET' if meta.get('aggressive') else 'HAYIR'}",
        f"Tarih    : {meta.get('timestamp', '')[:19]}",
        "",
    ]

    # ── Subdomainler ──────────────────────────────────────────────────────────
    subdomains = results.get("subdomains", [])
    alive      = results.get("alive_hosts", [])
    lines += [
        f"[RECON] Subdomain: {len(subdomains)} bulundu | Canlı: {len(alive)}",
    ]
    if alive:
        lines.append("Canlı hostlar:")
        for h in alive[:20]:
            lines.append(f"  {h}")
        if len(alive) > 20:
            lines.append(f"  ... ve {len(alive)-20} tane daha")
    lines.append("")

    # ── Açık portlar ─────────────────────────────────────────────────────────
    ports = results.get("open_ports", {})
    if ports:
        lines.append("[NMAP] Açık portlar:")
        for host, port_list in ports.items():
            lines.append(f"  {host}: {', '.join(str(p) for p in port_list)}")
        lines.append("")

    # ── Teknolojiler ──────────────────────────────────────────────────────────
    techs = results.get("technologies", [])
    if techs:
        lines.append(f"[FİNGERPRİNT] Tespit edilen teknolojiler: {', '.join(techs[:15])}")
        lines.append("")

    # ── URL'ler ───────────────────────────────────────────────────────────────
    urls = results.get("urls", [])
    interesting = results.get("interesting_urls", [])
    lines.append(f"[CRAWL] Toplam URL: {len(urls)}")
    if interesting:
        lines.append("Dikkat çeken URL'ler (SQLi/XSS/SSRF adayları):")
        for u in interesting[:15]:
            lines.append(f"  {u}")
    lines.append("")

    # ── Nuclei bulguları ──────────────────────────────────────────────────────
    nuclei = results.get("nuclei_findings", [])
    if nuclei:
        lines.append(f"[NUCLEİ] {len(nuclei)} bulgu:")
        # Severity sıralaması
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        nuclei_sorted = sorted(nuclei, key=lambda x: order.get(x.get("severity", "info").lower(), 9))
        for n in nuclei_sorted[:30]:
            sev  = n.get("severity", "?").upper()
            name = n.get("template-id", n.get("name", "?"))
            host = n.get("host", "")
            lines.append(f"  [{sev}] {name} → {host}")
        if len(nuclei) > 30:
            lines.append(f"  ... ve {len(nuclei)-30} tane daha")
    else:
        lines.append("[NUCLEİ] Bulgu yok")
    lines.append("")

    # ── Gizli parametreler ────────────────────────────────────────────────────
    params = results.get("hidden_params", {})
    if params:
        lines.append("[ARJUN] Gizli parametreler:")
        for url, param_list in params.items():
            lines.append(f"  {url}: {', '.join(param_list)}")
        lines.append("")

    # ── GF pattern eşleşmeleri ────────────────────────────────────────────────
    gf = results.get("gf_matches", {})
    if gf:
        lines.append("[GF] Pattern eşleşmeleri:")
        for pattern, matches in gf.items():
            if matches:
                lines.append(f"  {pattern}: {len(matches)} adet")
                for m in matches[:5]:
                    lines.append(f"    {m}")
        lines.append("")

    # ── ffuf dizinleri ────────────────────────────────────────────────────────
    ffuf_hits = results.get("ffuf_hits", [])
    if ffuf_hits:
        lines.append(f"[FFUF] Bulunan {len(ffuf_hits)} dizin/dosya:")
        for hit in ffuf_hits[:20]:
            lines.append(f"  [{hit.get('status')}] {hit.get('url')} ({hit.get('length','?')} byte)")
        lines.append("")

    lines += [
        "=" * 60,
        "Bu çıktıyı Claude'a yapıştır ve şunu söyle:",
        "'Bu pentest taramasını analiz et, öncelikli saldırı vektörlerini ve exploit adımlarını söyle.'",
        "=" * 60,
    ]

    return "\n".join(lines)