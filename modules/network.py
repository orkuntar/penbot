import os
import json
import subprocess
from core.engine import run_cmd
from config import TOOL_PATHS, TIMEOUTS


def run_naabu(target: str, aggressive: bool) -> list[dict]:
    """Hızlı port tarama — naabu."""
    naabu_bin = os.path.expanduser(TOOL_PATHS["naabu"])
    ports     = "1-65535" if aggressive else "top-1000"
    try:
        result = subprocess.run(
            [naabu_bin, "-host", target,
             "-p", ports,
             "-silent", "-json",
             "-rate", "1000" if aggressive else "500"],
            capture_output=True, text=True, timeout=TIMEOUTS["naabu"],
        )
        findings = []
        for line in result.stdout.splitlines():
            try:
                obj = json.loads(line)
                findings.append({
                    "host": obj.get("host", target),
                    "ip":   obj.get("ip", ""),
                    "port": obj.get("port", 0),
                })
            except Exception:
                if ":" in line:
                    parts = line.strip().split(":")
                    if len(parts) == 2:
                        findings.append({"host": parts[0], "ip": "", "port": int(parts[1])})
        return findings
    except Exception:
        return []


def run_testssl(host: str) -> dict:
    """SSL/TLS analiz — testssl.sh."""
    testssl_path = os.path.expanduser(TOOL_PATHS["testssl"])
    if not os.path.exists(testssl_path):
        return {}
    try:
        result = subprocess.run(
            ["bash", testssl_path,
             "--jsonfile", "/tmp/testssl_out.json",
             "--quiet", "--color", "0",
             host],
            capture_output=True, text=True, timeout=TIMEOUTS["testssl"],
        )
        # JSON çıktısını oku
        if os.path.exists("/tmp/testssl_out.json"):
            with open("/tmp/testssl_out.json") as f:
                data = json.load(f)
            findings = []
            for entry in data:
                if isinstance(entry, dict):
                    severity = entry.get("severity", "INFO")
                    if severity in ("HIGH", "CRITICAL", "MEDIUM"):
                        findings.append({
                            "id":       entry.get("id", ""),
                            "finding":  entry.get("finding", ""),
                            "severity": severity,
                        })
            return {"findings": findings, "raw_count": len(data)}
    except Exception:
        pass
    return {}


def run_sslscan(host: str) -> dict:
    """SSL/TLS tarama — sslscan."""
    try:
        result = subprocess.run(
            ["sslscan", "--no-colour", host],
            capture_output=True, text=True, timeout=TIMEOUTS["sslscan"],
        )
        out = result.stdout
        findings = []

        # Kritik bulgular
        checks = [
            ("SSLv2",        "SSLv2 enabled",     "CRITICAL"),
            ("SSLv3",        "SSLv3 enabled",     "HIGH"),
            ("TLSv1.0",      "TLSv1.0 enabled",   "MEDIUM"),
            ("TLSv1.1",      "TLSv1.1 enabled",   "MEDIUM"),
            ("RC4",          "RC4 cipher",         "HIGH"),
            ("DES",          "DES cipher",         "HIGH"),
            ("EXPORT",       "EXPORT cipher",      "CRITICAL"),
            ("NULL",         "NULL cipher",        "CRITICAL"),
            ("Heartbleed",   "Heartbleed",         "CRITICAL"),
            ("POODLE",       "POODLE",             "HIGH"),
            ("ROBOT",        "ROBOT",              "HIGH"),
        ]
        for keyword, desc, severity in checks:
            if keyword.lower() in out.lower():
                findings.append({"finding": desc, "severity": severity})

        return {"findings": findings, "raw": out[:500]}
    except Exception:
        return {}


def run_subzy(subdomains: list[str]) -> list[dict]:
    """Subdomain takeover kontrolü."""
    if not subdomains:
        return []
    subzy_bin = os.path.expanduser(TOOL_PATHS["subzy"])

    # Subdomain listesini dosyaya yaz
    sub_file = "/tmp/penbot_subs.txt"
    with open(sub_file, "w") as f:
        f.write("\n".join(subdomains))

    try:
        result = subprocess.run(
            [subzy_bin, "run", "--targets", sub_file, "--hide-fails"],
            capture_output=True, text=True, timeout=TIMEOUTS["subzy"],
        )
        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and ("VULNERABLE" in line or "vulnerable" in line.lower()):
                findings.append({
                    "subdomain": line,
                    "severity":  "HIGH",
                    "type":      "Subdomain Takeover",
                })
        return findings
    except Exception:
        return []


def run_gowitness(alive_hosts: list[str]) -> list[str]:
    """Screenshot al — gowitness."""
    if not alive_hosts:
        return []

    from config import SCREENSHOTS_DIR
    gw_bin = os.path.expanduser(TOOL_PATHS["gowitness"])
    hosts  = "\n".join(
        h.split("] ")[-1] if "] " in h else h
        for h in alive_hosts[:20]
    )
    hosts_file = "/tmp/penbot_hosts.txt"
    with open(hosts_file, "w") as f:
        f.write(hosts)

    try:
        subprocess.run(
            [gw_bin, "file",
             "-f", hosts_file,
             "--screenshot-path", SCREENSHOTS_DIR,
             "--no-http"],
            capture_output=True, text=True, timeout=TIMEOUTS["gowitness"],
        )
        screenshots = [
            f for f in os.listdir(SCREENSHOTS_DIR)
            if f.endswith(".png")
        ]
        return screenshots
    except Exception:
        return []


def run_network(target: str, subdomains: list[str], alive_hosts: list[str], aggressive: bool, progress_cb=None) -> dict:
    results = {}

    def upd(name, status, pct):
        if progress_cb:
            progress_cb(name, status, pct)

    from concurrent.futures import ThreadPoolExecutor

    # Hedef host temizle
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]

    upd("naabu",     "running", 0.0)
    upd("sslscan",   "running", 0.0)
    upd("subzy",     "running", 0.0)
    upd("gowitness", "running", 0.0)

    with ThreadPoolExecutor(max_workers=4) as ex:
        f1 = ex.submit(run_naabu,     clean_target, aggressive)
        f2 = ex.submit(run_sslscan,   clean_target)
        f3 = ex.submit(run_subzy,     subdomains)
        f4 = ex.submit(run_gowitness, alive_hosts)

        results["naabu_ports"]  = f1.result(); upd("naabu",     "done", 1.0)
        results["sslscan"]      = f2.result(); upd("sslscan",   "done", 1.0)
        results["takeover"]     = f3.result(); upd("subzy",     "done", 1.0)
        results["screenshots"]  = f4.result(); upd("gowitness", "done", 1.0)

    # testssl ayrı çalıştır (uzun sürüyor)
    upd("testssl", "running", 0.0)
    results["testssl"] = run_testssl(clean_target)
    upd("testssl", "done", 1.0)

    return results