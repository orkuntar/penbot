#!/usr/bin/env python3
"""
GREYPHANTOM v3 — Automated Pentest Framework
"""
import argparse
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.dashboard import Dashboard, print_banner, ask_aggressive, console
from core.output    import save_scan, load_last_scan, format_for_claude
from modules.recon      import run_recon
from modules.crawl      import run_crawl
from modules.vuln       import run_vuln
from modules.js_analyze import run_js_analyze
from modules.api_fuzz   import run_api_fuzz
from modules.network    import run_network
from modules.analyze    import run_analyze
from modules.auth_test  import run_auth_test
from modules.discovery  import run_discovery


MODES = {
    "full":      ["recon", "network", "crawl", "js", "api", "vuln", "analyze", "auth", "discovery"],
    "quick":     ["recon", "vuln", "analyze"],
    "recon":     ["recon"],
    "network":   ["recon", "network"],
    "js":        ["recon", "js"],
    "api":       ["recon", "api", "analyze"],
    "crawl":     ["recon", "crawl"],
    "vuln":      ["recon", "vuln"],
    "analyze":   ["recon", "analyze"],
    "auth":      ["recon", "auth"],
    "discovery": ["recon", "discovery"],
}

PHASE_TASKS = {
    "recon":     ["subfinder", "assetfinder", "httpx", "nmap"],
    "network":   ["naabu", "testssl", "subzy", "gowitness"],
    "crawl":     ["gau", "waybackurls", "gf_patterns", "ffuf"],
    "js":        ["js_discovery", "secretfinder", "linkfinder", "trufflehog"],
    "api":       ["kiterunner", "ffuf_api", "corsy", "graphql"],
    "vuln":      ["nuclei", "arjun", "jwt_check"],
    "analyze":   ["sensitive_detect", "method_fuzz", "idor_scan", "mass_assign", "error_disclose"],
    "auth":      ["login_find", "rate_limit", "default_creds", "sql_bypass", "nosql_bypass"],
    "discovery": ["info_endpoints", "graphql", "websocket", "cors_advanced", "ssrf"],
}

TASK_LABELS = {
    "subfinder":       "Subfinder",
    "assetfinder":     "Assetfinder",
    "httpx":           "Httpx",
    "nmap":            "Nmap",
    "naabu":           "Naabu (port scan)",
    "testssl":         "TestSSL",
    "subzy":           "Subzy (takeover)",
    "gowitness":       "Gowitness",
    "gau":             "GAU",
    "waybackurls":     "Waybackurls",
    "gf_patterns":     "GF patterns",
    "ffuf":            "Ffuf",
    "js_discovery":    "JS discovery",
    "secretfinder":    "SecretFinder",
    "linkfinder":      "LinkFinder",
    "trufflehog":      "Trufflehog",
    "kiterunner":      "Kiterunner",
    "ffuf_api":        "Ffuf API",
    "corsy":           "Corsy (CORS)",
    "graphql":         "GraphQL",
    "nuclei":          "Nuclei",
    "arjun":           "Arjun",
    "jwt_check":       "JWT check",
    "sensitive_detect":"Sensitive data detect",
    "method_fuzz":     "HTTP method fuzz",
    "idor_scan":       "IDOR scan",
    "mass_assign":     "Mass assignment",
    "error_disclose":  "Error disclosure",
    "login_find":      "Login endpoint find",
    "rate_limit":      "Rate limit check",
    "default_creds":   "Default credentials",
    "sql_bypass":      "SQL auth bypass",
    "nosql_bypass":    "NoSQL auth bypass",
    "info_endpoints":  "Info endpoints",
    "websocket":       "WebSocket check",
    "cors_advanced":   "CORS advanced",
    "ssrf":            "SSRF check",
}


def parse_args():
    p = argparse.ArgumentParser(description="GREYPHANTOM — Automated Pentest Framework")
    p.add_argument("-t", "--target",   help="Hedef domain")
    p.add_argument("-m", "--mode",     default="full", choices=list(MODES.keys()))
    p.add_argument("--aggressive",     action="store_true")
    p.add_argument("--passive",        action="store_true")
    p.add_argument("--report",         action="store_true")
    p.add_argument("--report-file",    help="Belirli rapor dosyası")
    p.add_argument("--pdf", action="store_true", help="PDF rapor üret")
    return p.parse_args()


def run_scan(target: str, mode: str, aggressive: bool):
    phases      = MODES[mode]
    dash        = Dashboard(target, mode, aggressive)
    all_results: dict = {}

    for phase in phases:
        for task in PHASE_TASKS.get(phase, []):
            dash.add_task(task, TASK_LABELS.get(task, task))

    dash.start()

    def progress(name, status, pct):
        dash.update(name, status, pct)

    try:
        # ── Recon ────────────────────────────────────────────────────────────
        if "recon" in phases:
            dash.log("[cyan]Faz: Recon[/]")
            r = run_recon(target, aggressive, progress_cb=progress)
            all_results.update(r)
            dash.log(f"[green]Recon:[/] {len(r.get('subdomains',[]))} subdomain, {len(r.get('alive_hosts',[]))} canlı")

        alive      = all_results.get("alive_hosts", [target])
        subdomains = all_results.get("subdomains", [target])

        # ── Network ───────────────────────────────────────────────────────────
        if "network" in phases:
            dash.log("[cyan]Faz: Network & SSL[/]")
            r = run_network(target, subdomains, alive, aggressive, progress_cb=progress)
            all_results.update(r)
            dash.log(f"[green]Network:[/] {len(r.get('naabu_ports',[]))} port")

        # ── Crawl ─────────────────────────────────────────────────────────────
        if "crawl" in phases:
            dash.log("[cyan]Faz: Crawl[/]")
            r = run_crawl(target, alive, aggressive, progress_cb=progress)
            all_results.update(r)
            dash.log(f"[green]Crawl:[/] {len(r.get('urls',[]))} URL")

        # ── JS ────────────────────────────────────────────────────────────────
        if "js" in phases:
            dash.log("[cyan]Faz: JS Analiz[/]")
            r = run_js_analyze(target, alive, progress_cb=progress)
            all_results.update(r)
            dash.log(f"[green]JS:[/] {len(r.get('js_secrets',[]))} secret")

        # ── API ───────────────────────────────────────────────────────────────
        if "api" in phases:
            dash.log("[cyan]Faz: API Fuzzing[/]")
            r = run_api_fuzz(target, alive, aggressive, progress_cb=progress)
            all_results.update(r)
            dash.log(f"[green]API:[/] {len(r.get('api_endpoints',[]))} endpoint")

        # ── Vuln ──────────────────────────────────────────────────────────────
        if "vuln" in phases:
            dash.log("[cyan]Faz: Vuln Scan[/]")
            int_urls = all_results.get("interesting_urls", [])
            r = run_vuln(target, alive, int_urls, aggressive, progress_cb=progress)
            all_results.update(r)
            dash.log(f"[green]Vuln:[/] {len(r.get('nuclei_findings',[]))} bulgu")

        # ── Analyze ───────────────────────────────────────────────────────────
        if "analyze" in phases:
            dash.log("[cyan]Faz: Deep Analysis[/]")
            api_eps  = all_results.get("api_endpoints", [])
            ffuf_hits = all_results.get("ffuf_hits", [])
            r = run_analyze(target, alive, api_eps, ffuf_hits, progress_cb=progress)
            all_results.update(r)
            dash.log(f"[green]Analyze:[/] {len(r.get('secret_findings',[]))} secret, {len(r.get('idor_findings',[]))} IDOR")

        # ── Auth ──────────────────────────────────────────────────────────────
        if "auth" in phases:
            dash.log("[cyan]Faz: Auth Test[/]")
            r = run_auth_test(target, alive, progress_cb=progress)
            all_results.update(r)
            dash.log(f"[green]Auth:[/] login={'bulundu' if r.get('login_endpoint') else 'yok'}")

        # ── Discovery ─────────────────────────────────────────────────────────
        if "discovery" in phases:
            dash.log("[cyan]Faz: Discovery[/]")
            all_eps = [ep.get('url','') for ep in all_results.get("api_endpoints",[])]
            r = run_discovery(target, alive, all_eps, progress_cb=progress)
            all_results.update(r)
            info_count = len(r.get("info_endpoints", []))
            dash.log(f"[green]Discovery:[/] {info_count} info endpoint")

    except KeyboardInterrupt:
        dash.log("[yellow]Durduruldu.[/]")
    finally:
        dash.stop()

    report_path = save_scan(target, mode, aggressive, all_results)
    console.print(f"\n[dim]Rapor:[/] [bold]{report_path}[/]")

    output = format_for_claude({
        "meta":    {
            "target":    target,
            "mode":      mode,
            "aggressive": aggressive,
            "timestamp": __import__("datetime").datetime.now().isoformat(),
        },
        "results": all_results,
    })
    console.print("\n" + output)
    return all_results


def main():
    print_banner()
    args = parse_args()

    if args.pdf:
        from core.report import build_pdf
        from config import REPORTS_DIR
        files = sorted([f for f in os.listdir(REPORTS_DIR) if f.endswith(".json")], reverse=True)
        if not files:
            console.print("[red]Rapor bulunamadı. Önce tarama yap.[/]")
            sys.exit(1)
        json_path = os.path.join(REPORTS_DIR, files[0])
        pdf_path  = build_pdf(json_path)
        console.print(f"[green]PDF oluşturuldu:[/] [bold]{pdf_path}[/]")
        return

    if args.report or args.report_file:
        if args.report_file:
            import json
            with open(args.report_file) as f:
                data = json.load(f)
        else:
            data = load_last_scan()
        if not data:
            console.print("[red]Rapor bulunamadı.[/]")
            sys.exit(1)
        console.print(format_for_claude(data))
        return

    if not args.target:
        console.print("[red]Hedef belirt:[/] python3 penbot.py -t hedef.com")
        sys.exit(1)

    target = args.target.strip().lower()
    target = target.replace("https://", "").replace("http://", "").rstrip("/")

    if args.aggressive:
        aggressive = True
    elif args.passive:
        aggressive = False
    else:
        aggressive = ask_aggressive(target)

    run_scan(target, args.mode, aggressive)


if __name__ == "__main__":
    main()