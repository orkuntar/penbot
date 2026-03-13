import json
from core.engine import run_cmd
from config import TOOL_PATHS, TIMEOUTS


def run_subfinder(target: str) -> list[str]:
    cmd = [TOOL_PATHS["subfinder"], "-d", target, "-silent", "-json"]
    _, out, err = run_cmd(cmd, timeout=TIMEOUTS["subfinder"])
    subdomains = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            subdomains.append(obj.get("host", ""))
        except json.JSONDecodeError:
            subdomains.append(line)
    return [s for s in subdomains if s]


def run_assetfinder(target: str) -> list[str]:
    cmd = [TOOL_PATHS["assetfinder"], "--subs-only", target]
    _, out, _ = run_cmd(cmd, timeout=TIMEOUTS["subfinder"])
    return [l.strip() for l in out.splitlines() if l.strip()]


def run_httpx(hosts: list[str]) -> tuple[list[str], list[str]]:
    """Canlı hostları ve tespit edilen teknolojileri döndür."""
    if not hosts:
        return [], []

    input_data = "\n".join(hosts)
    cmd = [
        TOOL_PATHS["httpx"],
        "-silent", "-json",
        "-tech-detect",
        "-status-code",
        "-title",
        "-no-color",
    ]
    proc_result = run_cmd(cmd, timeout=TIMEOUTS["httpx"])
    # httpx stdin bekliyor — pipe ile gönder
    import subprocess, shlex
    try:
        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=TIMEOUTS["httpx"],
        )
        out = result.stdout
    except Exception:
        return [], []

    alive = []
    techs = set()
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            url = obj.get("url", "")
            sc  = obj.get("status-code", 0)
            if url and sc:
                alive.append(f"[{sc}] {url}")
            for t in obj.get("tech", []):
                techs.add(t)
        except json.JSONDecodeError:
            if line.startswith("http"):
                alive.append(line)

    return alive, list(techs)


def run_nmap(hosts: list[str], aggressive: bool = False) -> dict:
    """Host başına açık portları döndür."""
    if not hosts:
        return {}

    # Sadece domain/IP al
    clean = []
    for h in hosts[:20]:  # nmap için max 20 host
        h = h.split("] ")[-1] if "] " in h else h
        h = h.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        if h:
            clean.append(h)

    if not clean:
        return {}

    flags = "-sV --open -T4" if aggressive else "-sV --open -T3 --top-ports 1000"
    targets = " ".join(set(clean[:10]))
    cmd = f"nmap {flags} {targets} -oG -"

    _, out, _ = run_cmd(cmd, timeout=TIMEOUTS["nmap"], shell=True)

    ports: dict[str, list[str]] = {}
    for line in out.splitlines():
        if "Ports:" not in line:
            continue
        parts = line.split()
        host  = parts[1] if len(parts) > 1 else "?"
        port_section = line.split("Ports:")[-1]
        open_ports = []
        for entry in port_section.split(","):
            entry = entry.strip()
            if "open" in entry:
                port_num = entry.split("/")[0].strip()
                service  = entry.split("/")[4] if len(entry.split("/")) > 4 else ""
                open_ports.append(f"{port_num}/{service}" if service else port_num)
        if open_ports:
            ports[host] = open_ports

    return ports


def run_recon(target: str, aggressive: bool, progress_cb=None) -> dict:
    results = {}

    def upd(name, status, pct):
        if progress_cb:
            progress_cb(name, status, pct)

    # Subdomain enumeration (paralel)
    from concurrent.futures import ThreadPoolExecutor, as_completed
    upd("subfinder", "running", 0.0)
    upd("assetfinder", "running", 0.0)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(run_subfinder, target)
        f2 = ex.submit(run_assetfinder, target)
        subs1 = f1.result()
        upd("subfinder", "done", 1.0)
        subs2 = f2.result()
        upd("assetfinder", "done", 1.0)

    all_subs = list(set(subs1 + subs2 + [target]))
    results["subdomains"] = all_subs

    # httpx
    upd("httpx", "running", 0.0)
    alive, techs = run_httpx(all_subs)
    results["alive_hosts"]   = alive
    results["technologies"]  = techs
    upd("httpx", "done", 1.0)

    # nmap
    upd("nmap", "running", 0.0)
    ports = run_nmap(alive, aggressive)
    results["open_ports"] = ports
    upd("nmap", "done", 1.0)

    return results