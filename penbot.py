#!/usr/bin/env python3
"""
GREYPHANTOM — Automated Pentest Framework
Kullanım:
  python3 penbot.py -t hedef.com
  python3 penbot.py -t hedef.com -m full
  python3 penbot.py -t hedef.com -m quick
  python3 penbot.py -t hedef.com -m recon
  python3 penbot.py -t hedef.com -m network
  python3 penbot.py -t hedef.com -m js
  python3 penbot.py -t hedef.com -m api
  python3 penbot.py -t hedef.com -m vuln
  python3 penbot.py --report
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


MODES = {
    "full":    ["recon", "network", "crawl", "js", "api", "vuln"],
    "quick":   ["recon", "vuln"],
    "recon":   ["recon"],
    "network": ["recon", "network"],
    "js":      ["recon", "js"],
    "api":     ["recon", "api"],
    "crawl":   ["recon", "crawl"],
    "vuln":    ["recon", "vuln"],
}

TASK_LABELS = {
    # recon
    "subfinder":    "Subfinder",
    "assetfinder":  "Assetfinder",
    "httpx":        "Httpx",
    "nmap":         "Nmap",
    # network
    "naabu":        "Naabu (port scan)",
    "sslscan":      "SSLScan",
    "testssl":      "TestSSL",
    "subzy":        "Subzy (takeover)",
    "gowitness":    "Gowitness (screenshot)",
    # crawl
    "gau":          "GAU",
    "waybackurls":  "Waybackurls",
    "gf_patterns":  "GF patterns",
    "ffuf":         "Ffuf",
    # js
    "js_discovery": "JS discovery",
    "secretfinder": "SecretFinder",
    "linkfinder":   "LinkFinder",
    "trufflehog":   "Trufflehog",
    # api
    "kiterunner":   "Kiterunner",
    "ffuf_api":     "Ffuf API",
    "corsy":        "Corsy (CORS)",
    "graphql":      "GraphQL detect",
    # vuln
    "nuclei":       "Nuclei",
    "arjun":        "Arjun",
    "jwt_check":    "JWT check",
}

PHASE_TASKS = {
    "recon":   ["subfinder", "assetfinder", "httpx", "nmap"],
    "network": ["naabu", "sslscan", "testssl", "subzy", "gowitness"],
    "crawl":   ["gau", "waybackurls", "gf_patterns", "ffuf"],
    "js":      ["js_discovery", "secretfinder", "linkfinder", "trufflehog"],
    "api":     ["kiterunner", "ffuf_api", "corsy", "graphql"],
    "vuln":    ["nuclei", "arjun", "jwt_check"],
}


def parse_args():
    p = argparse.ArgumentParser(
        description="GREYPHANTOM — Automated Pentest Framework",
    )
    p.add_argument("-t", "--target",     help="Hedef domain")
    p.add_argument("-m", "--mode",       default="full", choices=list(MODES.keys()))
    p.add_argument("--aggressive",       action="store_true")
    p.add_argument("--passive",          action="store_true")
    p.add_argument("--report",           action="store_true")
    p.add_argument("--report-file",      help="Belirli rapor dosyası")
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
        # ── Recon (her modun temeli) ──────────────────────────────────────────
        if "recon" in phases:
            dash.log("[cyan]Faz: Recon[/]")
            r = run_recon(target, aggressive, progress_cb=progress)
            all_results.update(r)
            dash.log(
                f"[green]Recon:[/] {len(r.get('subdomains',[]))} subdomain, "
                f"{len(r.get('alive_hosts',[]))} canlı"
            )

        alive     = all_results.get("alive_hosts", [target])
        subdomains = all_results.get("subdomains", [target])

        # ── Network ───────────────────────────────────────────────────────────
        if "network" in phases:
            dash.log("[cyan]Faz: Network & SSL[/]")
            r = run_network(target, subdomains, alive, aggressive, progress_cb=progress)
            all_results.update(r)
            dash.log(
                f"[green]Network:[/] {len(r.get('naabu_ports',[]))} port, "
                f"{len(r.get('takeover',[]))} takeover"
            )

        # ── Crawl ─────────────────────────────────────────────────────────────
        if "crawl" in phases:
            dash.log("[cyan]Faz: Crawl[/]")
            r = run_crawl(target, alive, aggressive, progress_cb=progress)
            all_results.update(r)
            dash.log(f"[green]Crawl:[/] {len(r.get('urls',[]))} URL")

        # ── JS Analiz ─────────────────────────────────────────────────────────
        if "js" in phases:
            dash.log("[cyan]Faz: JS Analiz[/]")
            r = run_js_analyze(target, alive, progress_cb=progress)
            all_results.update(r)
            dash.log(
                f"[green]JS:[/] {len(r.get('js_files',[]))} dosya, "
                f"{len(r.get('js_secrets',[]))} secret"
            )

        # ── API Fuzz ──────────────────────────────────────────────────────────
        if "api" in phases:
            dash.log("[cyan]Faz: API Fuzzing[/]")
            r = run_api_fuzz(target, alive, aggressive, progress_cb=progress)
            all_results.update(r)
            dash.log(
                f"[green]API:[/] {len(r.get('kr_endpoints',[]))} kr, "
                f"{len(r.get('api_endpoints',[]))} ffuf"
            )

        # ── Vuln ──────────────────────────────────────────────────────────────
        if "vuln" in phases:
            dash.log("[cyan]Faz: Vuln Scan[/]")
            int_urls = all_results.get("interesting_urls", [])
            r = run_vuln(target, alive, int_urls, aggressive, progress_cb=progress)
            all_results.update(r)
            dash.log(f"[green]Vuln:[/] {len(r.get('nuclei_findings',[]))} nuclei bulgusu")

    except KeyboardInterrupt:
        dash.log("[yellow]Kullanıcı tarafından durduruldu.[/]")
    finally:
        dash.stop()

    report_path = save_scan(target, mode, aggressive, all_results)
    console.print(f"\n[dim]Rapor:[/] [bold]{report_path}[/]")

    output = format_for_claude({
        "meta":    {"target": target, "mode": mode, "aggressive": aggressive,
                    "timestamp": __import__("datetime").datetime.now().isoformat()},
        "results": all_results,
    })
    console.print("\n" + output)
    return all_results


def main():
    print_banner()
    args = parse_args()

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