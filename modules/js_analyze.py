import os
import re
import json
import subprocess
import urllib.request
from core.engine import run_cmd
from config import TOOL_PATHS, TIMEOUTS


def get_js_files(alive_hosts: list[str]) -> list[str]:
    """httpx ile JS dosyalarını bul."""
    if not alive_hosts:
        return []
    hosts = "\n".join(
        h.split("] ")[-1] if "] " in h else h
        for h in alive_hosts
    )
    httpx_bin = os.path.expanduser(TOOL_PATHS["httpx"])
    try:
        result = subprocess.run(
            [httpx_bin, "-silent", "-probe", "-no-color"],
            input=hosts, capture_output=True, text=True, timeout=60,
        )
        # katana ile JS tara
        js_files = []
        katana_bin = os.path.expanduser(TOOL_PATHS["katana"])
        for host in hosts.splitlines():
            host = host.strip()
            if not host:
                continue
            r = subprocess.run(
                [katana_bin, "-u", host, "-silent", "-jc", "-d", "2"],
                capture_output=True, text=True, timeout=TIMEOUTS["katana"],
            )
            for line in r.stdout.splitlines():
                if line.strip().endswith(".js"):
                    js_files.append(line.strip())
        return list(set(js_files))
    except Exception:
        return []


def run_secretfinder(js_files: list[str]) -> list[dict]:
    """JS dosyalarından secret/API key çıkar."""
    if not js_files:
        return []

    secrets = []
    sf_path = os.path.expanduser(TOOL_PATHS["secretfinder"])

    for js_url in js_files[:20]:
        try:
            result = subprocess.run(
                ["python3", sf_path, "-i", js_url, "-o", "cli"],
                capture_output=True, text=True, timeout=TIMEOUTS["secretfinder"],
            )
            out = result.stdout + result.stderr
            for line in out.splitlines():
                line = line.strip()
                if line and not line.startswith("["):
                    continue
                if any(kw in line.lower() for kw in [
                    "api", "key", "secret", "token", "password",
                    "auth", "aws", "private", "credential",
                ]):
                    secrets.append({
                        "source": js_url,
                        "finding": line,
                        "severity": "HIGH",
                    })
        except Exception:
            pass

    return secrets


def run_linkfinder(js_files: list[str], target: str) -> list[str]:
    """JS dosyalarından endpoint çıkar."""
    if not js_files:
        return []

    endpoints = set()
    lf_path = os.path.expanduser(TOOL_PATHS["linkfinder"])

    for js_url in js_files[:20]:
        try:
            result = subprocess.run(
                ["python3", lf_path, "-i", js_url, "-o", "cli"],
                capture_output=True, text=True, timeout=TIMEOUTS["linkfinder"],
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and (line.startswith("/") or line.startswith("http")):
                    endpoints.add(line)
        except Exception:
            pass

    return list(endpoints)


def run_trufflehog(target: str) -> list[dict]:
    """GitHub/URL üzerinde secret tara."""
    th_bin = os.path.expanduser(TOOL_PATHS["trufflehog"])
    findings = []
    try:
        result = subprocess.run(
            [th_bin, "http", "--url", f"https://{target}", "--json", "--no-update"],
            capture_output=True, text=True, timeout=TIMEOUTS["trufflehog"],
        )
        for line in result.stdout.splitlines():
            try:
                obj = json.loads(line)
                findings.append({
                    "detector": obj.get("DetectorName", ""),
                    "verified":  obj.get("Verified", False),
                    "raw":       obj.get("Raw", "")[:100],
                    "source":    obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                    "severity":  "CRITICAL" if obj.get("Verified") else "MEDIUM",
                })
            except Exception:
                pass
    except Exception:
        pass
    return findings


def run_js_analyze(target: str, alive_hosts: list[str], progress_cb=None) -> dict:
    results = {}

    def upd(name, status, pct):
        if progress_cb:
            progress_cb(name, status, pct)

    from concurrent.futures import ThreadPoolExecutor

    # JS dosyalarını bul
    upd("js_discovery", "running", 0.0)
    js_files = get_js_files(alive_hosts)
    results["js_files"] = js_files
    upd("js_discovery", "done", 1.0)

    # SecretFinder + LinkFinder paralel
    upd("secretfinder", "running", 0.0)
    upd("linkfinder",   "running", 0.0)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(run_secretfinder, js_files)
        f2 = ex.submit(run_linkfinder,   js_files, target)
        secrets   = f1.result()
        endpoints = f2.result()
        upd("secretfinder", "done", 1.0)
        upd("linkfinder",   "done", 1.0)

    results["js_secrets"]   = secrets
    results["js_endpoints"] = endpoints

    # Trufflehog
    upd("trufflehog", "running", 0.0)
    results["trufflehog"] = run_trufflehog(target)
    upd("trufflehog", "done", 1.0)

    return results