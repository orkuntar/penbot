import os
import json
import subprocess
from core.engine import run_cmd
from config import TOOL_PATHS, TIMEOUTS

GF_PATTERNS = ["sqli", "xss", "ssrf", "redirect", "rce", "idor", "lfi", "ssti"]


def run_gau(target: str) -> list[str]:
    cmd = [os.path.expanduser(TOOL_PATHS["gau"]), "--threads", "5", "--timeout", "10", target]
    _, out, _ = run_cmd(cmd, timeout=TIMEOUTS["gau"])
    return [l.strip() for l in out.splitlines() if l.strip()]


def run_waybackurls(target: str) -> list[str]:
    wb  = os.path.expanduser(TOOL_PATHS["waybackurls"])
    cmd = f"echo {target} | {wb}"
    _, out, _ = run_cmd(cmd, timeout=TIMEOUTS["waybackurls"], shell=True)
    return [l.strip() for l in out.splitlines() if l.strip()]


def run_gf(urls: list[str], pattern: str) -> list[str]:
    if not urls:
        return []
    try:
        proc = subprocess.run(
            [os.path.expanduser(TOOL_PATHS["gf"]), pattern],
            input="\n".join(urls),
            capture_output=True,
            text=True,
            timeout=30,
        )
        return [l.strip() for l in proc.stdout.splitlines() if l.strip()]
    except Exception:
        return []


def run_ffuf(target: str, aggressive: bool) -> list[dict]:
    from config import WORDLISTS
    wordlist = WORDLISTS["dirs"] if aggressive else WORDLISTS["dirs_sm"]
    base = target.rstrip("/")
    if not base.startswith("http"):
        base = f"https://{base}"
    cmd = [
        os.path.expanduser(TOOL_PATHS["ffuf"]),
        "-u", f"{base}/FUZZ",
        "-w", wordlist,
        "-mc", "200,201,204,301,302,307,401,403,405",
        "-t", "40" if aggressive else "20",
        "-timeout", "10",
        "-json", "-s",
    ]
    _, out, _ = run_cmd(cmd, timeout=TIMEOUTS["ffuf"])
    hits = []
    for line in out.splitlines():
        try:
            obj = json.loads(line)
            for r in obj.get("results", [obj]):
                if r.get("url"):
                    hits.append({
                        "url":    r.get("url"),
                        "status": r.get("status", 0),
                        "length": r.get("length", 0),
                    })
        except Exception:
            pass
    return hits


def run_crawl(target: str, alive_hosts: list[str], aggressive: bool, progress_cb=None) -> dict:
    results = {}

    def upd(name, status, pct):
        if progress_cb:
            progress_cb(name, status, pct)

    from concurrent.futures import ThreadPoolExecutor

    upd("gau", "running", 0.0)
    upd("waybackurls", "running", 0.0)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(run_gau, target)
        f2 = ex.submit(run_waybackurls, target)
        gau_urls = f1.result()
        upd("gau", "done", 1.0)
        wb_urls  = f2.result()
        upd("waybackurls", "done", 1.0)

    all_urls = list(set(gau_urls + wb_urls))
    results["urls"] = all_urls

    upd("gf_patterns", "running", 0.0)
    gf_matches = {}
    for p in GF_PATTERNS:
        gf_matches[p] = run_gf(all_urls, p)
    results["gf_matches"]       = gf_matches
    results["interesting_urls"] = [u for matches in gf_matches.values() for u in matches]
    upd("gf_patterns", "done", 1.0)

    if alive_hosts:
        upd("ffuf", "running", 0.0)
        first = alive_hosts[0].split("] ")[-1] if "] " in alive_hosts[0] else alive_hosts[0]
        results["ffuf_hits"] = run_ffuf(first, aggressive)
        upd("ffuf", "done", 1.0)
    else:
        results["ffuf_hits"] = []

    return results