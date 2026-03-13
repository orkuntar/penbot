import os
import re
import json
import subprocess
from core.engine import run_cmd

# API key pattern'leri
SECRET_PATTERNS = [
    (r'gsk_[a-zA-Z0-9]{40,}',                    'Groq API Key',       'CRITICAL'),
    (r'sk-[a-zA-Z0-9]{40,}',                      'OpenAI API Key',     'CRITICAL'),
    (r'AIza[0-9A-Za-z\-_]{35}',                   'Google API Key',     'CRITICAL'),
    (r'AKIA[0-9A-Z]{16}',                          'AWS Access Key',     'CRITICAL'),
    (r'[0-9a-zA-Z/+]{40}',                         'Possible Secret',    'HIGH'),
    (r'"password"\s*:\s*"[^"]{3,}"',               'Password Field',     'HIGH'),
    (r'"secret"\s*:\s*"[^"]{3,}"',                 'Secret Field',       'HIGH'),
    (r'"token"\s*:\s*"[^"]{8,}"',                  'Token Field',        'HIGH'),
    (r'"api_key"\s*:\s*"[^"]{8,}"',                'API Key Field',      'CRITICAL'),
    (r'"private_key"\s*:\s*"[^"]{8,}"',            'Private Key',        'CRITICAL'),
    (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}','JWT Token',          'HIGH'),
    (r'[a-f0-9]{32,}',                             'Possible Hash/Key',  'MEDIUM'),
]

HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']


def detect_secrets(url: str, response_text: str) -> list[dict]:
    """Response içinde hassas veri ara."""
    findings = []
    for pattern, name, severity in SECRET_PATTERNS:
        matches = re.findall(pattern, response_text)
        for match in matches:
            # Kısa veya genel pattern'leri filtrele
            if len(match) < 8:
                continue
            # Zaten bilinen değerleri atla
            findings.append({
                'url':      url,
                'type':     name,
                'severity': severity,
                'value':    match[:20] + '...' if len(match) > 20 else match,
                'pattern':  pattern[:30],
            })
    return findings


def http_method_fuzz(url: str) -> list[dict]:
    """Endpoint'e farklı HTTP metodları dene."""
    results = []
    for method in HTTP_METHODS:
        try:
            cmd = ['curl', '-s', '-o', '/dev/null', '-w',
                   '%{http_code}', '-X', method,
                   '-H', 'Content-Type: application/json',
                   '-d', '{}',
                   '--connect-timeout', '5',
                   url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            status = result.stdout.strip()
            if status and status != '404' and status != '000':
                results.append({
                    'url':    url,
                    'method': method,
                    'status': int(status),
                    'note':   'Unexpected method allowed' if method not in ['GET', 'POST'] and status == '200' else '',
                })
        except Exception:
            pass
    return results


def idor_scan(base_url: str, endpoint: str, max_ids: int = 20) -> list[dict]:
    """ID based endpoint'lerde IDOR tara."""
    findings = []
    url_template = f"{base_url}{endpoint}"

    # İlk response boyutunu referans al
    try:
        r0 = subprocess.run(
            ['curl', '-s', '-w', '\n%{http_code}', f"{url_template}/1"],
            capture_output=True, text=True, timeout=10,
        )
        parts    = r0.stdout.rsplit('\n', 1)
        base_len = len(parts[0]) if parts else 0
        base_sc  = parts[1].strip() if len(parts) > 1 else '0'
    except Exception:
        return []

    if base_sc not in ('200', '201'):
        return []

    for i in range(2, max_ids + 2):
        try:
            r = subprocess.run(
                ['curl', '-s', '-w', '\n%{http_code}', f"{url_template}/{i}"],
                capture_output=True, text=True, timeout=10,
            )
            parts  = r.stdout.rsplit('\n', 1)
            body   = parts[0] if parts else ''
            sc     = parts[1].strip() if len(parts) > 1 else '0'

            if sc == '200' and len(body) > 50:
                findings.append({
                    'url':      f"{url_template}/{i}",
                    'status':   sc,
                    'length':   len(body),
                    'severity': 'HIGH',
                    'type':     'IDOR',
                    'note':     f'ID {i} accessible without auth',
                })
        except Exception:
            pass

    return findings


def mass_assignment_check(url: str, method: str = 'POST') -> list[dict]:
    """Mass assignment — ekstra field'lar kabul ediliyor mu?"""
    findings  = []
    payloads  = [
        {'role': 'admin'},
        {'role': 'admin', 'is_admin': True},
        {'admin': True},
        {'is_admin': 1},
        {'privilege': 'admin'},
        {'user_type': 'admin'},
        {'access_level': 999},
    ]

    for payload in payloads:
        try:
            r = subprocess.run(
                ['curl', '-s', '-X', method,
                 '-H', 'Content-Type: application/json',
                 '-d', json.dumps(payload),
                 '-w', '\n%{http_code}',
                 url],
                capture_output=True, text=True, timeout=10,
            )
            parts = r.stdout.rsplit('\n', 1)
            body  = parts[0] if parts else ''
            sc    = parts[1].strip() if len(parts) > 1 else '0'

            if sc == '200' and any(
                k in body.lower() for k in ['admin', 'success', 'role', 'privilege']
            ):
                findings.append({
                    'url':      url,
                    'payload':  json.dumps(payload),
                    'status':   sc,
                    'response': body[:200],
                    'severity': 'HIGH',
                    'type':     'Mass Assignment',
                })
        except Exception:
            pass

    return findings


def error_disclosure_check(url: str) -> list[dict]:
    """Hatalı istek gönder — stack trace, path, versiyon sızıyor mu?"""
    findings = []
    payloads = [
        ('GET',  url + "/'"),
        ('GET',  url + '/undefined'),
        ('GET',  url + '/../../../etc/passwd'),
        ('POST', url),
        ('GET',  url + '?id=undefined&test=<script>'),
    ]

    for method, target_url in payloads:
        try:
            r = subprocess.run(
                ['curl', '-s', '-X', method,
                 '-H', 'Content-Type: application/json',
                 '-d', '{"id": null, "test": "' + "'" * 10 + '"}',
                 target_url],
                capture_output=True, text=True, timeout=10,
            )
            body = r.stdout

            # Stack trace veya path disclosure işaretleri
            indicators = [
                ('at Object.',        'Node.js stack trace',  'HIGH'),
                ('at Module.',        'Node.js stack trace',  'HIGH'),
                ('SyntaxError',       'Error disclosure',     'MEDIUM'),
                ('UnhandledPromise',  'Unhandled error',      'MEDIUM'),
                ('/home/',            'Path disclosure',      'MEDIUM'),
                ('/var/www/',         'Path disclosure',      'MEDIUM'),
                ('node_modules',      'Path disclosure',      'MEDIUM'),
                ('MySQL',             'DB error disclosure',  'HIGH'),
                ('SQLSTATE',          'SQL error disclosure', 'HIGH'),
                ('ORA-',             'Oracle DB error',      'HIGH'),
                ('root:x:0:0',        'LFI - /etc/passwd',   'CRITICAL'),
            ]

            for indicator, desc, severity in indicators:
                if indicator in body:
                    findings.append({
                        'url':      target_url,
                        'type':     desc,
                        'severity': severity,
                        'snippet':  body[body.find(indicator):body.find(indicator)+100],
                    })
        except Exception:
            pass

    return findings


def run_analyze(
    target: str,
    alive_hosts: list[str],
    api_endpoints: list[dict],
    ffuf_hits: list[dict],
    progress_cb=None,
) -> dict:
    results = {
        'secret_findings':    [],
        'method_findings':    [],
        'idor_findings':      [],
        'mass_assignment':    [],
        'error_disclosure':   [],
    }

    def upd(name, status, pct):
        if progress_cb:
            progress_cb(name, status, pct)

    base_url = f"https://{target}"
    all_endpoints = []

    # ffuf + api endpoint'lerini birleştir
    for ep in (api_endpoints or []):
        url = ep.get('url', '')
        if url:
            all_endpoints.append(url)
    for hit in (ffuf_hits or []):
        url = hit.get('url', '')
        if url:
            all_endpoints.append(url)

    # Deduplicate
    all_endpoints = list(set(all_endpoints))[:30]

    from concurrent.futures import ThreadPoolExecutor

    # 1. Sensitive data detection
    upd('sensitive_detect', 'running', 0.0)
    for url in all_endpoints:
        try:
            r = subprocess.run(
                ['curl', '-s', '--connect-timeout', '5', url],
                capture_output=True, text=True, timeout=15,
            )
            secrets = detect_secrets(url, r.stdout)
            results['secret_findings'].extend(secrets)
        except Exception:
            pass
    upd('sensitive_detect', 'done', 1.0)

    # 2. HTTP method fuzzing
    upd('method_fuzz', 'running', 0.0)
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = [ex.submit(http_method_fuzz, url) for url in all_endpoints[:15]]
        for f in futures:
            results['method_findings'].extend(f.result())
    upd('method_fuzz', 'done', 1.0)

    # 3. IDOR scan — /api/* endpoint'leri için
    upd('idor_scan', 'running', 0.0)
    api_paths = list(set(
        '/' + '/'.join(url.replace('https://', '').replace('http://', '').split('/')[1:-1])
        for url in all_endpoints
        if '/api/' in url
    ))
    for path in api_paths[:5]:
        findings = idor_scan(base_url, path)
        results['idor_findings'].extend(findings)
    upd('idor_scan', 'done', 1.0)

    # 4. Mass assignment
    upd('mass_assign', 'running', 0.0)
    post_endpoints = [
        ep for ep in all_endpoints
        if any(k in ep for k in ['/api/', '/auth/', '/user', '/login', '/register'])
    ][:5]
    for url in post_endpoints:
        findings = mass_assignment_check(url)
        results['mass_assignment'].extend(findings)
    upd('mass_assign', 'done', 1.0)

    # 5. Error disclosure
    upd('error_disclose', 'running', 0.0)
    for url in all_endpoints[:10]:
        findings = error_disclosure_check(url)
        results['error_disclosure'].extend(findings)
    upd('error_disclose', 'done', 1.0)

    return results