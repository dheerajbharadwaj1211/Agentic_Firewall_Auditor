"""Launch the native Phase 4 console; secrets stay in process memory."""
import argparse
import getpass
import os
from pathlib import Path
import sys
import warnings
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', default='models/gemini-3.1-flash-lite')
    args = parser.parse_args()
    original = os.environ.get('GEMINI_API_KEY')
    try:
        from PySide6.QtWidgets import QApplication
        from firewall_auditor.desktop import Console
        from firewall_auditor.transport import load_hosts
        hosts = load_hosts(str(ROOT / 'config/hosts.local.json'))
        if not original:
            if not sys.stdin.isatty():
                print('Run in native PowerShell to enter your API key securely.'); return 1
            with warnings.catch_warnings():
                warnings.simplefilter('error', getpass.GetPassWarning)
                key = getpass.getpass('Gemini API key (hidden, memory only): ').strip()
            if not key: return 1
            os.environ['GEMINI_API_KEY'] = key
        app = QApplication(sys.argv[:1])
        window = Console(ROOT, hosts, args.model); window.show()
        return app.exec()
    except Exception as exc:
        print('Desktop setup failed (' + type(exc).__name__ + '). See docs/phase4.md.'); return 1
    finally:
        if original is None: os.environ.pop('GEMINI_API_KEY', None)
        else: os.environ['GEMINI_API_KEY'] = original

if __name__ == '__main__':
    raise SystemExit(main())
