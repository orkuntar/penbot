import os

# ─── Araç yolları ────────────────────────────────────────────────────────────
GO_BIN   = os.path.expanduser("~/go/bin")
TOOLS    = os.path.expanduser("~/bugbounty/tools")
WORDLIST = os.path.expanduser("~/wordlists/SecLists")

TOOL_PATHS = {
    "subfinder":   f"{GO_BIN}/subfinder",
    "httpx":       f"{GO_BIN}/httpx",
    "nmap":        "nmap",
    "gau":         f"{GO_BIN}/gau",
    "waybackurls": f"{GO_BIN}/waybackurls",
    "ffuf":        f"{GO_BIN}/ffuf",
    "nuclei":      f"{GO_BIN}/nuclei",
    "arjun":       "arjun",
    "gf":          f"{GO_BIN}/gf",
    "assetfinder": f"{GO_BIN}/assetfinder",
    "jwt_tool":    f"{TOOLS}/jwt_tool/jwt_tool.py",
}

WORDLISTS = {
    "dirs":    f"{WORDLIST}/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "dirs_sm": f"{WORDLIST}/Discovery/Web-Content/common.txt",
    "params":  f"{WORDLIST}/Discovery/Web-Content/burp-parameter-names.txt",
}

NUCLEI_TAGS = {
    "passive":    "misconfig,exposure,info,tech",
    "active":     "cves,vulnerabilities,exposed-panels,misconfiguration,default-logins",
    "aggressive": "cves,vulnerabilities,exposed-panels,misconfiguration,default-logins,fuzzing,brute-force",
}

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

TIMEOUTS = {
    "subfinder":   120,
    "httpx":        60,
    "nmap":        300,
    "gau":         120,
    "waybackurls": 120,
    "ffuf":        180,
    "nuclei":      600,
    "arjun":       180,
}