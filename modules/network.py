import os
import json
import subprocess
from core.engine import run_cmd
from config import TOOL_PATHS, TIMEOUTS


def run_naabu(target: str, aggressive: bool) -> list[dict]:
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
                        try:
                            findings.append({"host": parts[0], "ip": "", "port": int(parts[1])})
                        except Exception:
                            pass
        return findings
    except Exception:
        return []


def run_testssl(host: str) -> dict:
    """SSL/TLS tam analiz — testssl.sh (primary, güvenilir)."""
    testssl_path = os.path.expanduser(TOOL_PATHS["testssl"])
    if not os.path.exists(testssl_path):
        return {"error": "testssl.sh bulunamadı"}

    out_file = "/tmp/penbot_testssl.json"
    try:
        subprocess.run(
            ["bash", testssl_path,
             "--jsonfile", out_file,
             "--quiet", "--color", "0",
             "--protocols",
             "--vulnerable",
             "--headers",
             "--cipher-per-proto",
             host],
            capture_output=True, text=True, timeout=TIMEOUTS["testssl"],
        )

        if not os.path.exists(out_file):
            return {"error": "testssl çıktısı oluşturulamadı"}

        with open(out_file) as f:
            raw = json.load(f)

        findings   = []
        proto_info = []

        for entry in raw:
            if not isinstance(entry, dict):
                continue

            severity = entry.get("severity", "INFO")
            finding  = entry.get("finding", "")
            eid      = entry.get("id", "")

            # Protokol bilgisi
            if eid in ("SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"):
                proto_info.append({
                    "protocol": eid,
                    "status":   finding,
                    "severity": severity,
                })

            # Sadece kritik/yüksek/medium bulgular
            if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                findings.append({
                    "id":       eid,
                    "finding":  finding,
                    "severity": severity,
                })

        return {
            "findings":   findings,
            "protocols":  proto_info,
            "raw_count":  len(raw),
        }

    except Exception as e:
        return {"error": str(e)}
    finally:
        if os.path.exists(out_file):
            os.remove(out_file)


def run_subzy(subdomains: list[str]) -> list[dict]:
    if not subdomains:
        return []

    subzy_bin = os.path.expanduser(TOOL_PATHS["subzy"])
    sub_file  = "/tmp/penbot_subs.txt"
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
    if not alive_hosts:
        return []

    from config import SCREENSHOTS_DIR
    gw_bin     = os.path.expanduser(TOOL_PATHS["gowitness"])
    hosts_file = "/tmp/penbot_hosts.txt"

    hosts = "\n".join(
        h.split("] ")[-1] if "] " in h else h
        for h in alive_hosts[:20]
    )
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
        return [
            f for f in os.listdir(SCREENSHOTS_DIR)
            if f.endswith(".png")
        ]
    except Exception:
        return []


def run_network(
    target: str,
    subdomains: list[str],
    alive_hosts: list[str],
    aggressive: bool,
    progress_cb=None,
) -> dict:
    results = {}

    def upd(name, status, pct):
        if progress_cb:
            progress_cb(name, status, pct)

    from concurrent.futures import ThreadPoolExecutor

    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]

    upd("naabu",     "running", 0.0)
    upd("testssl",   "running", 0.0)
    upd("subzy",     "running", 0.0)
    upd("gowitness", "running", 0.0)

    with ThreadPoolExecutor(max_workers=4) as ex:
        f1 = ex.submit(run_naabu,     clean_target, aggressive)
        f2 = ex.submit(run_testssl,   clean_target)
        f3 = ex.submit(run_subzy,     subdomains)
        f4 = ex.submit(run_gowitness, alive_hosts)

        results["naabu_ports"] = f1.result(); upd("naabu",     "done", 1.0)
        results["testssl"]     = f2.result(); upd("testssl",   "done", 1.0)
        results["takeover"]    = f3.result(); upd("subzy",     "done", 1.0)
        results["screenshots"] = f4.result(); upd("gowitness", "done", 1.0)

    return results