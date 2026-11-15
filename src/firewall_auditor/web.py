"""Restricted loopback HTTPS UI. No mutation routes and no arbitrary filesystem serving."""
from copy import deepcopy
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
import ssl
import threading
import time

from .agent import AgentController, _scrub, model_view

ASSETS = Path(__file__).with_name('web_assets')


def browser_report(report):
    """Expose evidence, never connection configuration, raw exports or model reasoning."""
    result = {k: report.get(k) for k in ('status', 'failure', 'mode', 'host', 'generated_at',
        'llm_model', 'llm_api_version', 'read_only', 'firewall_modified', 'findings',
        'coverage_notes', 'events', 'connectivity_tested', 'effective_packet_flow_evaluated')}
    result['observations'] = []
    for obs in report.get('observations', []):
        item = model_view(obs)
        if item['tool'] == 'get_listening_services':
            item['data'].pop('text', None)
        # Service tool spelling is defined by Operation; discard any raw service text.
        if isinstance(item.get('data'), dict) and 'listeners' in item['data']:
            item['data'].pop('text', None)
        result['observations'].append(item)
    return _scrub(result)


class AuditState:
    def __init__(self, runner):
        self.runner = runner
        self.lock = threading.Lock()
        self.value = {'status': 'idle', 'events': [], 'report': None}
        self.last_start = -float('inf')

    def snapshot(self):
        with self.lock:
            return deepcopy(self.value)

    def start(self, goal):
        if not isinstance(goal, str) or not 1 <= len(goal.strip()) <= 2000:
            return 400
        with self.lock:
            if self.value['status'] == 'running' or time.monotonic() - self.last_start < 10:
                return 409
            self.last_start = time.monotonic()
            self.value = {'status': 'running', 'events': [], 'report': None}
        threading.Thread(target=self._run, args=(goal.strip(),), daemon=True).start()
        return 202

    def _run(self, goal):
        def progress(event):
            with self.lock:
                self.value['events'] = (self.value['events'] + [deepcopy(event)])[-24:]
        try:
            report = browser_report(self.runner(goal, progress))
            with self.lock:
                self.value.update(status=report['status'], report=report)
        except Exception:
            with self.lock:
                self.value.update(status='failed', report={'failure':
                    'Audit setup failed. Check local SSH agent, host configuration and Gemini settings.'})


def live_runner(root, model):
    def run(goal, progress):
        from .context import load_context
        from .gemini import GeminiProvider
        from .phase3_ledger import Ledger
        from .reports import write_report
        from .tools import Inspector
        from .transport import load_hosts

        class ObservedController(AgentController):
            def record(self, event):
                ok = super().record(event)
                progress(event)
                return ok

        provider = GeminiProvider(model, api_version='v1beta')
        try:
            report = ObservedController(Inspector(load_hosts(str(root / 'config/hosts.local.json'))),
                provider, 'ubuntu-vm', load_context(str(root / 'config/context.local.json'), 'ubuntu-vm'),
                audit=Ledger(root / 'audit/audit.sqlite3')).run(goal)
            write_report(report, root / 'reports/web-latest')
            return report
        finally:
            provider.close()
    return run


class LocalServer(HTTPServer):
    # Serial HTTP handling bounds socket/thread resource usage. Agent work is one background job.
    request_queue_size = 8
    def get_request(self):
        raw, addr = self.socket.accept()
        raw.settimeout(3)
        try:
            return self.tls.wrap_socket(raw, server_side=True), addr
        except Exception:
            raw.close()
            raise

    def handle_error(self, request, client_address):
        pass  # Never log request data, goals, credentials or SDK exception strings.


def make_server(cert, key, password, runner, port=8443):
    if not isinstance(password, str) or len(password) < 16:
        raise ValueError('Use an access password of at least 16 characters')
    server = LocalServer(('127.0.0.1', port), Handler)
    try:
        server.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.tls.minimum_version = ssl.TLSVersion.TLSv1_2
        server.tls.load_cert_chain(cert, key)
    except Exception:
        server.server_close()
        raise
    server.origin = f'https://127.0.0.1:{server.server_port}'
    server.authority = f'127.0.0.1:{server.server_port}'
    server.password = password
    server.session = None
    server.csrf = None
    server.session_created = server.session_used = 0
    server.failures = []
    server.state = AuditState(runner)
    return server


class Handler(BaseHTTPRequestHandler):
    server_version = 'LocalAudit'
    sys_version = ''
    def log_message(self, *args):
        pass

    def reply(self, status, value, kind='application/json', cookie=None):
        payload = json.dumps(value).encode() if kind == 'application/json' else value
        self.send_response(status)
        for key, val in {
            'Content-Type': kind + '; charset=utf-8', 'Content-Length': str(len(payload)),
            'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            'Connection': 'close',
        }.items():
            self.send_header(key, val)
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    def gate(self):
        if self.headers.get_all('Host') != [self.server.authority]:
            self.reply(403, {'error': 'Invalid host'})
            return False
        if self.headers.get('Sec-Fetch-Site') not in (None, 'same-origin', 'none'):
            self.reply(403, {'error': 'Cross-site access denied'})
            return False
        return True

    def authenticated(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get('Cookie', ''))
            supplied = cookie['__Host-audit'].value
        except (KeyError, ValueError, CookieError):
            return False
        now = time.monotonic()
        ok = (self.server.session is not None and
            secrets.compare_digest(supplied.encode(), self.server.session.encode()) and
            now - self.server.session_created < 28800 and now - self.server.session_used < 1800)
        if ok:
            self.server.session_used = now
        return ok

    def do_GET(self):
        if not self.gate():
            return
        assets = {'/': ('index.html', 'text/html'), '/app.js': ('app.js', 'text/javascript'),
                  '/style.css': ('style.css', 'text/css')}
        if self.path in assets:
            name, kind = assets[self.path]
            self.reply(200, (ASSETS / name).read_bytes(), kind)
        elif self.path == '/api/state':
            if not self.authenticated():
                return self.reply(401, {'error': 'Sign in required'})
            self.reply(200, {**self.server.state.snapshot(), 'csrf': self.server.csrf})
        else:
            self.reply(404, {'error': 'Not found'})

    def do_POST(self):
        if not self.gate():
            return
        if self.headers.get_all('Origin') != [self.server.origin]:
            return self.reply(403, {'error': 'Same-origin request required'})
        if self.headers.get('Content-Type') != 'application/json' or self.headers.get('Transfer-Encoding'):
            return self.reply(415, {'error': 'JSON body required'})
        try:
            sizes = self.headers.get_all('Content-Length') or []
            if len(sizes) != 1 or not sizes[0].isdigit() or not 1 <= int(sizes[0]) <= 8192:
                return self.reply(413, {'error': 'Body size rejected'})
            data = json.loads(self.rfile.read(int(sizes[0])))
            if not isinstance(data, dict):
                raise ValueError()
        except (ValueError, UnicodeError):
            return self.reply(400, {'error': 'Invalid JSON'})
        if self.path == '/api/login':
            now = time.monotonic()
            self.server.failures = [x for x in self.server.failures if now - x < 60]
            if len(self.server.failures) >= 5:
                return self.reply(429, {'error': 'Wait one minute before trying again'})
            password = data.get('password')
            if set(data) != {'password'} or not isinstance(password, str) or not secrets.compare_digest(password.encode(), self.server.password.encode()):
                self.server.failures.append(now)
                return self.reply(401, {'error': 'Invalid access password'})
            self.server.session = secrets.token_urlsafe(32)
            self.server.csrf = secrets.token_urlsafe(32)
            self.server.session_created = self.server.session_used = now
            return self.reply(200, {'csrf': self.server.csrf}, cookie=
                '__Host-audit=' + self.server.session + '; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800')
        if not self.authenticated():
            return self.reply(401, {'error': 'Sign in required'})
        if not secrets.compare_digest(self.headers.get('X-CSRF-Token', '').encode(), self.server.csrf.encode()):
            return self.reply(403, {'error': 'CSRF check failed'})
        if self.path == '/api/logout' and data == {}:
            self.server.session = self.server.csrf = None
            return self.reply(200, {}, cookie='__Host-audit=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
        if self.path == '/api/audit' and set(data) == {'goal'}:
            code = self.server.state.start(data['goal'])
            return self.reply(code, {'message': {202: 'Audit started', 400: 'Enter a goal of 1..2000 characters',
                                               409: 'Audit busy or cooldown active'}[code]})
        self.reply(404, {'error': 'Not found'})
