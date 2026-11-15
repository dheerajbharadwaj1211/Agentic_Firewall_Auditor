"""Real loopback TLS + synthetic agent tests. No Gemini, SSH or firewall mutation."""
import http.client
import json
import os
from pathlib import Path
import ssl
import tempfile
import threading
import time
from unittest.mock import patch

import pytest
from firewall_auditor.web import AuditState, browser_report, make_server
from firewall_auditor.web_cert import create_certificate

PASSWORD = 'test-password-at-least-16'


@pytest.fixture
def server():
    # All generated project intermediates stay in the designated work folder.
    with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2] / 'work') as temp:
        root = Path(temp)
        create_certificate(root)
        def runner(goal, progress):
            progress({'sequence': 1, 'turn': 1, 'tool': 'get_host_context', 'decision': 'allowed', 'status': 'success'})
            return {'status': 'complete', 'mode': 'synthetic_test', 'findings': [], 'observations': [], 'events': []}
        srv = make_server(root/'server.pem', root/'server-key.pem', PASSWORD, runner, 0)
        thread = threading.Thread(target=srv.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        thread.start()
        srv.test_context = ssl.create_default_context(cafile=str(root/'ca.pem'))
        yield srv
        srv.shutdown()
        srv.server_close()
        thread.join(3)


def request(srv, path='/', data=None, headers=None, method=None, context=None):
    conn = http.client.HTTPSConnection('127.0.0.1', srv.server_port, context=context or srv.test_context, timeout=5)
    hdr = {'Origin': srv.origin, 'Content-Type': 'application/json'}
    hdr.update(headers or {})
    conn.request(method or ('GET' if data is None else 'POST'), path,
                 body=None if data is None else json.dumps(data), headers=hdr)
    response = conn.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    conn.close()
    return result


def login(srv):
    code, headers, body = request(srv, '/api/login', {'password': PASSWORD})
    assert code == 200
    return {'Cookie': headers['Set-Cookie'].split(';')[0], 'X-CSRF-Token': json.loads(body)['csrf']}


def test_tls_verification_and_headers(server):
    with pytest.raises(ssl.SSLCertVerificationError):
        request(server, context=ssl.create_default_context())
    code, headers, body = request(server)
    assert code == 200 and b'Investigate with evidence' in body
    assert headers['Cache-Control'] == 'no-store'
    assert "frame-ancestors 'none'" in headers['Content-Security-Policy']
    assert headers['X-Content-Type-Options'] == 'nosniff'


def test_auth_csrf_origin_and_host(server):
    assert request(server, '/api/state')[0] == 401
    assert request(server, '/api/login', {'password': 'wrong'})[0] == 401
    headers = login(server)
    assert request(server, '/api/state', headers=headers)[0] == 200
    assert request(server, '/api/audit', {'goal': 'audit'}, {'Cookie': headers['Cookie']})[0] == 403
    assert request(server, '/api/audit', {'goal': 'audit'}, {**headers, 'X-CSRF-Token': '\xe9'})[0] == 403
    assert request(server, '/api/state', headers={'Cookie': '__Host-audit=\xe9'})[0] == 401
    assert request(server, '/api/audit', {'goal': 'audit'}, {**headers, 'Origin': 'https://evil.invalid'})[0] == 403
    assert request(server, headers={'Host': 'evil.invalid'})[0] == 403
    assert request(server, headers={'Sec-Fetch-Site': 'cross-site'})[0] == 403
    assert request(server, '/api/audit', {'goal': 'audit'}, {**headers, 'Origin': ''})[0] == 403


def test_live_job_route_validation_and_logout(server):
    hdr = login(server)
    for goal in ('', ' ', 'x'*2001, None, [], 123):
        assert request(server, '/api/audit', {'goal': goal}, hdr)[0] == 400
    assert request(server, '/api/audit', {'goal': 'audit', 'host': 'other'}, hdr)[0] == 404
    assert request(server, '/api/approve', {}, hdr)[0] == 404
    assert request(server, '/../../config/hosts.local.json', headers=hdr)[0] == 404
    assert request(server, '/api/audit', {'goal': 'Investigate services'}, hdr)[0] == 202
    for _ in range(100):
        state = json.loads(request(server, '/api/state', headers=hdr)[2])
        if state['status'] != 'running': break
        time.sleep(.01)
    assert state['status'] == 'complete'
    assert state['report']['mode'] == 'synthetic_test'
    assert state['events'][0]['status'] == 'success'
    assert request(server, '/api/audit', {'goal': 'again'}, hdr)[0] == 409
    assert request(server, '/api/logout', {}, hdr)[0] == 200
    assert request(server, '/api/state', headers=hdr)[0] == 401


def test_session_rotation_expiration_cookie_flags(server):
    old = login(server)
    code, headers, body = request(server, '/api/login', {'password': PASSWORD})
    assert all(x in headers['Set-Cookie'] for x in ('Secure', 'HttpOnly', 'SameSite=Strict', 'Path=/'))
    assert request(server, '/api/state', headers=old)[0] == 401
    current = {'Cookie': headers['Set-Cookie'].split(';')[0]}
    server.session_used -= 1801
    assert request(server, '/api/state', headers=current)[0] == 401


def test_login_rate_and_body_limits(server):
    for _ in range(5):
        assert request(server, '/api/login', {'password': 'wrong'})[0] == 401
    assert request(server, '/api/login', {'password': PASSWORD})[0] == 429
    assert request(server, '/api/login', {'password': 'x'*9000})[0] == 413
    assert request(server, '/api/login', {}, {'Content-Type': 'text/plain'})[0] == 415
    assert request(server, '/api/login', [1, 2])[0] == 400


def test_concurrent_jobs_bounded_and_error_sanitized():
    release = threading.Event()
    def blocked(goal, progress):
        release.wait(2)
        raise RuntimeError('secret private-key-path api-key')
    state = AuditState(blocked)
    assert state.start('audit') == 202
    assert state.start('second') == 409
    release.set()
    for _ in range(100):
        if state.snapshot()['status'] != 'running': break
        time.sleep(.01)
    assert state.snapshot()['status'] == 'failed'
    assert 'private-key-path' not in json.dumps(state.snapshot())


def test_browser_evidence_minimized():
    from test_phase2 import observations
    report = {'status': 'complete', 'findings': [{'title': 'test-secret'}],
              'observations': list(observations().values()), 'identity_file': 'private-path', 'context': {'secret': 'hidden'}}
    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-secret'}):
        rendered = browser_report(report)
    text = json.dumps(rendered)
    assert 'test-secret' not in text and 'private-path' not in text
    assert 'process_metadata' not in text and 'users:' not in text
    assert 'raw' not in rendered['observations'][0]['data']
    assert 'context' not in rendered


def test_real_controller_through_web_job():
    from firewall_auditor.agent import AgentController
    from test_phase2 import FakeInspector, PlanProvider
    def runner(goal, progress):
        class Controller(AgentController):
            def record(self, event):
                progress(event)
                return super().record(event)
        return Controller(FakeInspector(), PlanProvider(), 'vm').run(goal)
    state = AuditState(runner)
    assert state.start('Audit synthetic fixture') == 202
    for _ in range(100):
        value = state.snapshot()
        if value['status'] != 'running': break
        time.sleep(.01)
    assert value['status'] == 'complete'
    assert len(value['report']['observations']) == 7
    assert len(value['events']) == 10
    assert value['report']['firewall_modified'] is False


def test_cert_refuses_overwrite_and_password_minimum(server):
    with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2] / 'work') as temp:
        create_certificate(temp)
        with pytest.raises(ValueError): create_certificate(temp)
    with pytest.raises(ValueError): make_server('unused', 'unused', 'short', None, 0)
