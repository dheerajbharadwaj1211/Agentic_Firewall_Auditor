"""Run in a native terminal with SSH-agent access; no credentials in the browser."""
import argparse
import getpass
import os
from pathlib import Path
import sys
import warnings

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))


def hidden(prompt):
    if not sys.stdin.isatty():
        raise ValueError('Use an interactive native terminal for hidden credential entry')
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        return getpass.getpass(prompt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--init-cert', action='store_true', help='Generate local TLS files and exit; does not install trust')
    parser.add_argument('--port', type=int, default=8443)
    parser.add_argument('--model', default='models/gemini-3.1-flash-lite')
    args = parser.parse_args()
    original = os.environ.get('GEMINI_API_KEY')
    certdir = ROOT / 'config/web-tls'
    server = None
    try:
        if args.init_cert:
            from firewall_auditor.web_cert import create_certificate
            create_certificate(certdir)
            print('Generated 30-day local CA and loopback server certificate in config/web-tls.')
            print('Trust only ca.pem for restricted local testing; see docs/web-interface.md.')
            return 0
        if not 1024 <= args.port <= 65535:
            raise ValueError('Invalid port')
        if not (certdir / 'server.pem').is_file() or not (certdir / 'server-key.pem').is_file():
            print('Run this launcher with --init-cert first.'); return 1
        password = hidden('Set a local web access password (16-256 characters, hidden): ')
        if not 16 <= len(password) <= 256 or password != hidden('Repeat local web access password: '):
            print('Passwords must match and contain 16-256 characters.'); return 1
        if not original:
            os.environ['GEMINI_API_KEY'] = hidden('Gemini API key (hidden, memory only): ').strip()
        if not os.environ.get('GEMINI_API_KEY'):
            print('No API key supplied.'); return 1
        from firewall_auditor.web import live_runner, make_server
        server = make_server(certdir / 'server.pem', certdir / 'server-key.pem', password,
                             live_runner(ROOT, args.model), args.port)
        print(f'Local HTTPS interface: {server.origin}')
        print('Read-only target: ubuntu-vm. Stop with Ctrl+C. No firewall changes are available.')
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print('Local HTTPS server stopped. Any daemon audit stops with this process.')
    except Exception:
        print('Startup failed. Check certificate setup, port availability, hidden input and local configuration. No secrets logged.')
        return 1
    finally:
        if server:
            server.server_close()
        if original is None:
            os.environ.pop('GEMINI_API_KEY', None)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
