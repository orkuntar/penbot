import os
import json
import subprocess
from core.engine import run_cmd
from config import TOOL_PATHS, WORDLISTS, TIMEOUTS


def run_kiterunner(alive_hosts: list[str]) -> list[dict]:
    """API endpoint keşfi — kiterunner."""
    if not alive_hosts:
        return []

    kr_bin = os.path.expanduser(TOOL_PATHS["kr"])
    findings = []

    for host in alive_hosts[:10]:
        host = host.split("] ")[-1] if "] " in host else host
        host = host.strip()
        if not host:
            continue
        try:
            result = subprocess.run(
                [kr_bin, "scan", host,
                 "-w", "routes-large.kite",
                 "--fail-status-codes", "400,401,404,403",
                 "-j"],
                capture_output=True, text=True, timeout=TIMEOUTS["kr"],
            )
            for line in result.stdout.splitlines():
                try:
                    obj = json.loads(line)
                    findings.append({
                        "url":    obj.get("request", {}).get("url", ""),
                        "status": obj.get("response", {}).get("status", 0),
                        "method": obj.get("request", {}).get("method", "GET"),
                    })
                except Exception:
                    if line.strip() and "200" in line:
                        findings.append({"url": line.strip(), "status": 200, "method": "GET"})
        except Exception:
            pass

    return findings


def run_ffuf_api(alive_hosts: list[str], aggressive: bool) -> list[dict]:
    """API endpoint brute force — ffuf API wordlist."""
    if not alive_hosts:
        return []

    ffuf_bin  = os.path.expanduser(TOOL_PATHS["ffuf"])
    wordlist  = WORDLISTS.get("apis", WORDLISTS["dirs_sm"])
    if not os.path.exists(os.path.expanduser(wordlist)):
        wordlist = WORDLISTS["dirs_sm"]

    hits = []
    for host in alive_hosts[:5]:
        host = host.split("] ")[-1] if "] " in host else host
        host = host.strip().rstrip("/")
        if not host.startswith("http"):
            host = f"https://{host}"

        for prefix in ["/api/FUZZ", "/api/v1/FUZZ", "/api/v2/FUZZ", "/FUZZ"]:
            try:
                result = subprocess.run(
                    [ffuf_bin,
                     "-u", f"{host}{prefix}",
                     "-w", os.path.expanduser(wordlist),
                     "-mc", "200,201,204,301,302,307,401,403,405",
                     "-t", "30" if aggressive else "15",
                     "-timeout", "10",
                     "-json", "-s"],
                    capture_output=True, text=True, timeout=TIMEOUTS["ffuf"],
                )
                for line in result.stdout.splitlines():
                    try:
                        obj = json.loads(line)
                        for r in obj.get("results", [obj]):
                            if r.get("url"):
                                hits.append({
                                    "url":    r.get("url"),
                                    "status": r.get("status", 0),
                                    "length": r.get("length", 0),
                                    "words":  r.get("words", 0),
                                })
                    except Exception:
                        pass
            except Exception:
                pass

    return hits


def run_corsy(alive_hosts: list[str]) -> list[dict]:
    """CORS misconfiguration tara."""
    if not alive_hosts:
        return []

    corsy_path = os.path.expanduser(TOOL_PATHS["corsy"])
    findings   = []

    for host in alive_hosts[:10]:
        host = host.split("] ")[-1] if "] " in host else host
        host = host.strip()
        if not host.startswith("http"):
            host = f"https://{host}"
        try:
            result = subprocess.run(
                ["python3", corsy_path, "-u", host, "-q"],
                capture_output=True, text=True, timeout=TIMEOUTS["corsy"],
            )
            out = result.stdout.strip()
            if out and "cors" in out.lower():
                findings.append({
                    "url":     host,
                    "finding": out[:300],
                    "severity": "MEDIUM",
                })
        except Exception:
            pass

    return findings


def run_graphql(alive_hosts: list[str]) -> list[dict]:
    """GraphQL endpoint tespiti."""
    if not alive_hosts:
        return []

    gw_path  = os.path.expanduser(TOOL_PATHS["graphw00f"])
    findings = []

    for host in alive_hosts[:10]:
        host = host.split("] ")[-1] if "] " in host else host
        host = host.strip()
        if not host.startswith("http"):
            host = f"https://{host}"
        try:
            result = subprocess.run(
                ["python3", gw_path, "-d", "-t", host],
                capture_output=True, text=True, timeout=60,
            )
            out = result.stdout
            if "graphql" in out.lower() or "engine" in out.lower():
                findings.append({
                    "url":     host,
                    "finding": out[:300].strip(),
                    "severity": "INFO",
                })
        except Exception:
            pass

    return findings


def run_api_fuzz(target: str, alive_hosts: list[str], aggressive: bool, progress_cb=None) -> dict:
    results = {}

    def upd(name, status, pct):
        if progress_cb:
            progress_cb(name, status, pct)

    from concurrent.futures import ThreadPoolExecutor

    upd("kiterunner", "running", 0.0)
    upd("ffuf_api",   "running", 0.0)
    upd("corsy",      "running", 0.0)
    upd("graphql",    "running", 0.0)

    with ThreadPoolExecutor(max_workers=4) as ex:
        f1 = ex.submit(run_kiterunner, alive_hosts)
        f2 = ex.submit(run_ffuf_api,   alive_hosts, aggressive)
        f3 = ex.submit(run_corsy,      alive_hosts)
        f4 = ex.submit(run_graphql,    alive_hosts)

        results["kr_endpoints"]  = f1.result(); upd("kiterunner", "done", 1.0)
        results["api_endpoints"] = f2.result(); upd("ffuf_api",   "done", 1.0)
        results["cors_findings"] = f3.result(); upd("corsy",      "done", 1.0)
        results["graphql"]       = f4.result(); upd("graphql",    "done", 1.0)

    return results