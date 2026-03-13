import os
import json
import subprocess
from core.engine import run_cmd
from config import TOOL_PATHS, TIMEOUTS, NUCLEI_TAGS


def run_nuclei(targets: list[str], aggressive: bool) -> list[dict]:
    if not targets:
        return []

    tags  = NUCLEI_TAGS["aggressive"] if aggressive else NUCLEI_TAGS["active"]
    hosts = "\n".join(
        h.split("] ")[-1] if "] " in h else h
        for h in targets[:50]
    )

    cmd = [
        os.path.expanduser(TOOL_PATHS["nuclei"]),
        "-tags", tags,
        "-json",
        "-silent",
        "-c", "25",
        "-timeout", "10",
        "-no-color",
    ]

    try:
        result = subprocess.run(
            cmd,
            input=hosts,
            capture_output=True,
            text=True,
            timeout=TIMEOUTS["nuclei"],
        )
        out = result.stdout
    except Exception:
        return []

    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            findings.append({
                "template-id": obj.get("template-id", ""),
                "name":        obj.get("info", {}).get("name", ""),
                "severity":    obj.get("info", {}).get("severity", "info"),
                "host":        obj.get("host", ""),
                "url":         obj.get("matched-at", ""),
                "tags":        obj.get("info", {}).get("tags", []),
                "description": obj.get("info", {}).get("description", ""),
            })
        except json.JSONDecodeError:
            pass

    return findings


def run_arjun(urls: list[str]) -> dict:
    """Her URL için gizli parametreleri bul."""
    if not urls:
        return {}

    # Arjun için ilginç URL'leri seç (parametre içerebilecekler)
    candidates = [u for u in urls if "?" in u or any(
        x in u for x in ["/api/", "/v1/", "/v2/", "/search", "/query", "/get", "/fetch"]
    )][:10]

    if not candidates:
        return {}

    params_found = {}
    for url in candidates:
        cmd = ["arjun", "-u", url, "--json", "-q"]
        _, out, _ = run_cmd(cmd, timeout=TIMEOUTS["arjun"])
        for line in out.splitlines():
            try:
                obj = json.loads(line)
                found = obj.get("params", [])
                if found:
                    params_found[url] = found
            except Exception:
                pass

    return params_found


def run_jwt_check(urls: list[str]) -> list[dict]:
    """URL'lerde JWT içerip içermediğini kontrol et."""
    jwt_findings = []
    for url in urls:
        if any(keyword in url.lower() for keyword in ["token", "jwt", "auth", "bearer"]):
            jwt_findings.append({
                "url":  url,
                "note": "JWT/token parametresi tespit edildi — manuel analiz önerilir",
            })
    return jwt_findings[:10]


def run_vuln(
    target: str,
    alive_hosts: list[str],
    interesting_urls: list[str],
    aggressive: bool,
    progress_cb=None,
) -> dict:
    results = {}

    def upd(name, status, pct):
        if progress_cb:
            progress_cb(name, status, pct)

    from concurrent.futures import ThreadPoolExecutor

    # Nuclei + Arjun paralel
    upd("nuclei", "running", 0.0)
    upd("arjun",  "running", 0.0)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(run_nuclei, alive_hosts, aggressive)
        f2 = ex.submit(run_arjun,  interesting_urls)
        nuclei_findings = f1.result()
        upd("nuclei", "done", 1.0)
        hidden_params = f2.result()
        upd("arjun", "done", 1.0)

    results["nuclei_findings"] = nuclei_findings
    results["hidden_params"]   = hidden_params

    # JWT kontrol
    upd("jwt_check", "running", 0.0)
    results["jwt_findings"] = run_jwt_check(interesting_urls)
    upd("jwt_check", "done", 1.0)

    return results