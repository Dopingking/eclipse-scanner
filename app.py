from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import re
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

def normalize_url(url):
    if not url.startswith('http'):
        url = 'https://' + url
    return url

def get_base(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def safe_request(url, timeout=5):
    try:
        return requests.get(url, timeout=timeout, headers={'User-Agent': 'EclipseScanner/1.0'})
    except:
        return None

def check_env(base):
    r = safe_request(f'{base}/.env')
    if r and r.status_code == 200 and any(k in r.text for k in ['DB_', 'SECRET', 'KEY', 'PASS']):
        return {
            'title': 'Exposed Environment File',
            'description': 'The .env file is publicly accessible and may contain database credentials, API keys, and application secrets.',
            'severity': 'critical',
            'fix': 'Move .env outside the web root. Restrict access via .htaccess or server configuration.'
        }
    return None

def check_api_keys(base):
    r = safe_request(base, timeout=10)
    if r and r.status_code == 200:
        if any(k in r.text for k in ['sk-', 'pk_', 'api_key', 'apikey', 'secret']):
            return {
                'title': 'Hardcoded API Keys',
                'description': 'API keys or secrets were detected in client-side JavaScript. These can be extracted and abused.',
                'severity': 'high',
                'fix': 'Move secrets to environment variables. Use a server-side proxy for external API calls.'
            }
    return None

def check_rate_limit(base):
    r = safe_request(base)
    if r:
        headers = r.headers
        if 'x-ratelimit-limit' not in headers and 'ratelimit-limit' not in headers:
            return {
                'title': 'Missing Rate Limiting',
                'description': 'No rate limiting headers detected. This can lead to brute-force and DDoS attacks.',
                'severity': 'medium',
                'fix': 'Implement rate limiting (e.g., express-rate-limit, django-ratelimit, or cloudflare).'
            }
    return None

def check_privacy(base):
    paths = ['/privacy', '/privacy-policy', '/legal/privacy']
    for p in paths:
        r = safe_request(f'{base}{p}')
        if r and r.status_code == 200:
            return None
    return {
        'title': 'Privacy Policy Missing',
        'description': 'No privacy policy found. This is required by GDPR, CCPA, and other regulations.',
        'severity': 'low',
        'fix': 'Add a privacy policy page. Use a generator if needed.'
    }

def check_cors(base):
    r = safe_request(base, timeout=5)
    if r and r.headers.get('access-control-allow-origin') == '*':
        return {
            'title': 'Wildcard CORS Policy',
            'description': 'CORS allows any domain to access your resources. This can lead to data leakage.',
            'severity': 'high',
            'fix': 'Restrict Access-Control-Allow-Origin to specific trusted domains.'
        }
    return None

def check_debug(base):
    r = safe_request(base)
    if r and r.status_code == 200:
        if any(k in r.text for k in ['DEBUG', 'traceback', 'Stack trace', 'Django', 'Laravel']):
            return {
                'title': 'Debug Mode Detected',
                'description': 'The application appears to be running in debug mode, exposing internal errors.',
                'severity': 'medium',
                'fix': 'Set APP_DEBUG=False, DEBUG=False, or NODE_ENV=production.'
            }
    return None

def check_https(url):
    if not url.startswith('https'):
        return {
            'title': 'HTTPS Not Enforced',
            'description': 'The site does not use HTTPS. Data is transmitted in plaintext.',
            'severity': 'high',
            'fix': 'Install an SSL certificate and redirect HTTP to HTTPS.'
        }
    return None

def check_directories(base):
    dirs = ['/admin', '/backup', '/logs', '/temp', '/test', '/old', '/dev']
    found = []
    for d in dirs:
        r = safe_request(f'{base}{d}')
        if r and r.status_code == 200:
            found.append(d)
    if found:
        return {
            'title': 'Exposed Directories',
            'description': f'Accessible directories found: {", ".join(found)}.',
            'severity': 'medium',
            'fix': 'Restrict access with .htaccess or server configuration.'
        }
    return None

def check_cookies(base):
    r = safe_request(base)
    if r and 'Set-Cookie' in r.headers:
        c = r.headers.get('Set-Cookie', '')
        if 'Secure' not in c or 'HttpOnly' not in c:
            return {
                'title': 'Insecure Cookie Configuration',
                'description': 'Cookies missing Secure or HttpOnly flags. Vulnerable to session theft.',
                'severity': 'medium',
                'fix': 'Add Secure, HttpOnly, and SameSite attributes to cookies.'
            }
    return None

def check_ssl_tls(base):
    parsed = urlparse(base)
    host = parsed.hostname
    if not host:
        return None
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.connect((host, 443))
            ver = s.version()
            if any(v in ver for v in ['SSL', 'TLSv1.0', 'TLSv1.1']):
                return {
                    'title': 'Outdated SSL/TLS Version',
                    'description': f'Server uses {ver}, which has known vulnerabilities.',
                    'severity': 'medium',
                    'fix': 'Disable SSLv3, TLSv1.0, TLSv1.1. Use only TLSv1.2 and TLSv1.3.'
                }
    except:
        pass
    return None

def check_security_headers(base):
    r = safe_request(base)
    if not r:
        return None
    missing = []
    if 'strict-transport-security' not in r.headers:
        missing.append('HSTS')
    if 'x-frame-options' not in r.headers:
        missing.append('X-Frame-Options')
    if 'content-security-policy' not in r.headers:
        missing.append('CSP')
    if missing:
        return {
            'title': 'Missing Security Headers',
            'description': f'Missing headers: {", ".join(missing)}. These help prevent MITM, clickjacking, and XSS.',
            'severity': 'high',
            'fix': 'Add HSTS, X-Frame-Options: DENY, and a Content-Security-Policy.'
        }
    return None

def check_open_redirect(base):
    test_url = f"{base}?redirect=https://evil.com"
    r = safe_request(test_url, timeout=5)
    if r and r.status_code in [301, 302, 303, 307, 308]:
        loc = r.headers.get('Location', '')
        if 'evil.com' in loc:
            return {
                'title': 'Open Redirect',
                'description': 'Unvalidated redirect parameter allows redirection to malicious sites.',
                'severity': 'medium',
                'fix': 'Validate redirect URLs against a whitelist or use relative paths.'
            }
    return None

def check_admin_panel(base):
    paths = ['/admin', '/administrator', '/wp-admin', '/dashboard', '/login', '/panel']
    for p in paths:
        r = safe_request(f'{base}{p}')
        if r and r.status_code == 200:
            return {
                'title': 'Admin Panel Exposed',
                'description': f'Admin panel accessible at {base}{p}.',
                'severity': 'high',
                'fix': 'Implement strong authentication, 2FA, and IP whitelisting.'
            }
    return None

def check_robots(base):
    r = safe_request(f'{base}/robots.txt')
    if r and r.status_code == 200:
        if any(k in r.text for k in ['admin', 'backup', 'private', 'secret']):
            return {
                'title': 'Sensitive Paths in robots.txt',
                'description': 'robots.txt exposes sensitive directories.',
                'severity': 'low',
                'fix': 'Remove sensitive paths from robots.txt or use authentication.'
            }
    return None

def check_email_exposure(base):
    r = safe_request(base)
    if r and r.status_code == 200:
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', r.text)
        if emails:
            return {
                'title': 'Email Addresses Exposed',
                'description': f'Found {len(emails)} email addresses in the response. This can lead to phishing.',
                'severity': 'low',
                'fix': 'Obfuscate emails or use contact forms instead.'
            }
    return None

def check_xss_header(base):
    r = safe_request(base)
    if r:
        if 'x-xss-protection' not in r.headers and 'content-security-policy' not in r.headers:
            return {
                'title': 'XSS Protection Missing',
                'description': 'No XSS protection headers detected.',
                'severity': 'low',
                'fix': 'Add X-XSS-Protection: 1; mode=block or a CSP header.'
            }
    return None

def check_backup_files(base):
    patterns = ['/backup.zip', '/backup.tar', '/site.sql', '/old.zip']
    for p in patterns:
        r = safe_request(f'{base}{p}')
        if r and r.status_code == 200:
            return {
                'title': 'Backup File Exposed',
                'description': f'Backup file accessible at {base}{p}.',
                'severity': 'high',
                'fix': 'Remove backup files from the web root and store them offline.'
            }
    return None

def check_sql_injection(base):
    payloads = ["'", "1' OR '1'='1", "1' OR 1=1--"]
    for p in payloads:
        r = safe_request(f"{base}?q={p}")
        if r and r.status_code == 200 and any(k in r.text.lower() for k in ['sql', 'mysql', 'error', 'syntax']):
            return {
                'title': 'Potential SQL Injection',
                'description': 'SQL error messages detected. The site may be vulnerable to SQL injection.',
                'severity': 'critical',
                'fix': 'Use prepared statements (parameterized queries). Avoid concatenating user input into SQL.'
            }
    return None

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    raw_url = data.get('url', '').strip()
    if not raw_url:
        return jsonify({'error': 'No URL provided'}), 400

    url = normalize_url(raw_url)
    base = get_base(url)

    checks = [
        check_env,
        check_api_keys,
        check_rate_limit,
        check_privacy,
        check_cors,
        check_debug,
        check_https,
        check_directories,
        check_cookies,
        check_ssl_tls,
        check_security_headers,
        check_open_redirect,
        check_admin_panel,
        check_robots,
        check_email_exposure,
        check_xss_header,
        check_backup_files,
        check_sql_injection
    ]

    findings = []
    for fn in checks:
        try:
            result = fn(base if fn.__name__ != 'check_https' else url)
            if result:
                findings.append(result)
        except:
            pass

    score = 100
    summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'passed': 0}

    for f in findings:
        sev = f.get('severity', 'low')
        if sev == 'critical':
            score -= 20
            summary['critical'] += 1
        elif sev == 'high':
            score -= 12
            summary['high'] += 1
        elif sev == 'medium':
            score -= 7
            summary['medium'] += 1
        else:
            score -= 3
            summary['low'] += 1

    score = max(0, min(100, score))
    summary['passed'] = len(findings) - (summary['critical'] + summary['high'] + summary['medium'] + summary['low'])

    response = {
        'target': url,
        'score': score,
        'summary': summary,
        'results': findings,
        'scanned_at': datetime.now().isoformat()
    }

    return jsonify(response)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
