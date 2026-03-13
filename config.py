import os

GO_BIN   = os.path.expanduser("~/go/bin")
TOOLS    = os.path.expanduser("~/bugbounty/tools")
WORDLIST = os.path.expanduser("~/wordlists/SecLists")

TOOL_PATHS = {
    "subfinder":    f"{GO_BIN}/subfinder",
    "httpx":        f"{GO_BIN}/httpx",
    "nmap":         "nmap",
    "gau":          f"{GO_BIN}/gau",
    "waybackurls":  f"{GO_BIN}/waybackurls",
    "ffuf":         f"{GO_BIN}/ffuf",
    "nuclei":       f"{GO_BIN}/nuclei",
    "arjun":        "arjun",
    "gf":           f"{GO_BIN}/gf",
    "assetfinder":  f"{GO_BIN}/assetfinder",
    "naabu":        f"{GO_BIN}/naabu",
    "subzy":        f"{GO_BIN}/subzy",
    "gowitness":    f"{GO_BIN}/gowitness",
    "kr":           f"{GO_BIN}/kr",
    "dalfox":       f"{GO_BIN}/dalfox",
    "katana":       f"{GO_BIN}/katana",
    "notify":       f"{GO_BIN}/notify",
    "interactsh":   f"{GO_BIN}/interactsh-client",
    "trufflehog":   f"{GO_BIN}/trufflehog",
    "sqlmap":       "sqlmap",
    "sslscan":      "sslscan",
    "testssl":      f"{TOOLS}/testssl.sh/testssl.sh",
    "secretfinder": f"{TOOLS}/SecretFinder/SecretFinder.py",
    "linkfinder":   f"{TOOLS}/LinkFinder/linkfinder.py",
    "graphw00f":    f"{TOOLS}/graphw00f/main.py",
    "corsy":        f"{TOOLS}/Corsy/corsy.py",
    "jwt_tool":     f"{TOOLS}/jwt_tool/jwt_tool.py",
}

WORDLISTS = {
    "dirs":    f"{WORDLIST}/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "dirs_sm": f"{WORDLIST}/Discovery/Web-Content/common.txt",
    "params":  f"{WORDLIST}/Discovery/Web-Content/burp-parameter-names.txt",
    "apis":    f"{WORDLIST}/Discovery/Web-Content/api/objects.txt",
    "apis_sm": f"{WORDLIST}/Discovery/Web-Content/api/api-endpoints.txt",
}

NUCLEI_TAGS = {
    "passive":    "misconfig,exposure,info,tech",
    "active":     "cves,vulnerabilities,exposed-panels,misconfiguration,default-logins",
    "aggressive": "cves,vulnerabilities,exposed-panels,misconfiguration,default-logins,fuzzing,brute-force",
}

REPORTS_DIR     = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
SCREENSHOTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "screenshots")
os.makedirs(REPORTS_DIR,     exist_ok=True)
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

TIMEOUTS = {
    "subfinder":    120,
    "httpx":         60,
    "nmap":         300,
    "naabu":        120,
    "gau":          120,
    "katana":       180,
    "waybackurls":  120,
    "ffuf":         180,
    "nuclei":       600,
    "arjun":        180,
    "dalfox":       120,
    "sqlmap":       300,
    "sslscan":       60,
    "testssl":      180,
    "secretfinder":  60,
    "linkfinder":    60,
    "kr":           180,
    "subzy":         60,
    "gowitness":     60,
    "corsy":         60,
    "trufflehog":   120,
}