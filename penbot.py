#!/usr/bin/env python3
"""
penbot — Automated Pentest Framework
Kullanım:
  python penbot.py --target hedef.com
  python penbot.py --target hedef.com --mode full
  python penbot.py --target hedef.com --mode recon
  python penbot.py --target hedef.com --mode vuln
  python penbot.py --report  (son taramayı Claude formatında göster)
"""

import argparse
import sys
import os

# WSL path fix
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from concurrent.futures import ThreadPoolExecutor, as_completed
from core.dashboard import Dashboard, print_banner, ask_aggressive, console
from core.output import save_scan, load_last_scan, format_for_claude
from modules.recon import run_recon
from modules.crawl import run_crawl
from modules.vuln  import run_vuln


MODES = {
    "full":  ["recon", "crawl", "vuln"],
    "recon": ["recon"],
    "crawl": ["crawl"],
    "vuln":  ["vuln"],
    "quick": ["recon", "vuln"],
}

TASK_LABELS = {
    # recon
    "subfinder":   "Subfinder",
    "assetfinder": "Assetfinder",
    "httpx":       "Httpx (alive check)",
    "nmap":        "Nmap (port scan)",
    # crawl
    "gau":         "GAU (URL harvest)",
    "waybackurls": "Waybackurls",
    "gf_patterns": "GF (pattern match)",
    "ffuf":        "Ffuf (dir brute)",
    # vuln
    "nuclei":      "Nuclei (vuln scan)",
    "arjun":       "Arjun (param fuzz)",
    "jwt_check":   "JWT check",
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="penbot — Automated Pentest Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target",  help="Hedef domain (örn: hedef.com)")
    parser.add_argument("-m", "--mode",    default="full",
                        choices=list(MODES.keys()),
                        help="Tarama modu (varsayılan: full)")
    parser.add_argument("--aggressive",    action="store_true",
                        help="Agresif modu zorla (sormadan)")
    parser.add_argument("--passive",       action="store_true",
                        help="Pasif modu zorla (sormadan)")
    parser.add_argument("--report",        action="store_true",
                        help="Son taramayı Claude formatında göster")
    parser.add_argument("--report-file",   help="Belirli bir rapor dosyasını göster")
    return parser.parse_args()


def run_scan(target: str, mode: str, aggressive: bool):
    phases = MODES[mode]
    dash   = Dashboard(target, mode, aggressive)
    all_results: dict = {}

    # Tüm task'ları dashboard'a ekle
    for phase in phases:
        if phase == "recon":
            for t in ["subfinder", "assetfinder", "httpx", "nmap"]:
                dash.add_task(t, TASK_LABELS[t])
        elif phase == "crawl":
            for t in ["gau", "waybackurls", "gf_patterns", "ffuf"]:
                dash.add_task(t, TASK_LABELS[t])
        elif phase == "vuln":
            for t in ["nuclei", "arjun", "jwt_check"]:
                dash.add_task(t, TASK_LABELS[t])

    dash.start()

    def progress(name, status, pct):
        dash.update(name, status, pct)

    try:
        if "recon" in phases:
            dash.log("[cyan]Faz 1: Recon başlıyor...[/]")
            recon_results = run_recon(target, aggressive, progress_cb=progress)
            all_results.update(recon_results)
            dash.log(
                f"[green]Recon tamamlandı:[/] "
                f"{len(recon_results.get('subdomains', []))} subdomain, "
                f"{len(recon_results.get('alive_hosts', []))} canlı host"
            )

        if "crawl" in phases:
            dash.log("[cyan]Faz 2: Crawl başlıyor...[/]")
            alive = all_results.get("alive_hosts", [target])
            crawl_results = run_crawl(target, alive, aggressive, progress_cb=progress)
            all_results.update(crawl_results)
            dash.log(
                f"[green]Crawl tamamlandı:[/] "
                f"{len(crawl_results.get('urls', []))} URL, "
                f"{len(crawl_results.get('ffuf_hits', []))} dizin bulundu"
            )

        if "vuln" in phases:
            dash.log("[cyan]Faz 3: Vuln scan başlıyor...[/]")
            alive   = all_results.get("alive_hosts", [target])
            int_url = all_results.get("interesting_urls", [])
            vuln_results = run_vuln(target, alive, int_url, aggressive, progress_cb=progress)
            all_results.update(vuln_results)
            n_findings = len(vuln_results.get("nuclei_findings", []))
            dash.log(f"[green]Vuln scan tamamlandı:[/] {n_findings} nuclei bulgusu")

    except KeyboardInterrupt:
        dash.log("[yellow]Tarama kullanıcı tarafından durduruldu.[/]")
    finally:
        dash.stop()

    # Kaydet
    report_path = save_scan(target, mode, aggressive, all_results)
    console.print(f"\n[dim]Rapor kaydedildi:[/] [bold]{report_path}[/]")

    # Claude formatı
    from core.output import format_for_claude
    import json
    data = {"meta": {"target": target, "mode": mode, "aggressive": aggressive}, "results": all_results}
    claude_output = format_for_claude(data)
    console.print("\n" + claude_output)

    return all_results


def main():
    print_banner()
    args = parse_args()

    # --report modu
    if args.report or args.report_file:
        if args.report_file:
            import json
            with open(args.report_file) as f:
                data = json.load(f)
        else:
            data = load_last_scan()

        if not data:
            console.print("[red]Rapor bulunamadı. Önce bir tarama yap.[/]")
            sys.exit(1)

        console.print(format_for_claude(data))
        return

    # Hedef gerekli
    if not args.target:
        console.print("[red]Hedef belirt:[/] python penbot.py --target hedef.com")
        sys.exit(1)

    target = args.target.strip().lower()
    target = target.replace("https://", "").replace("http://", "").rstrip("/")

    # Agresif mod kararı
    if args.aggressive:
        aggressive = True
    elif args.passive:
        aggressive = False
    else:
        aggressive = ask_aggressive(target)

    # Taramayı başlat
    run_scan(target, args.mode, aggressive)


if __name__ == "__main__":
    main()