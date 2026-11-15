"""Run in the user's normal Windows terminal to use their SSH agent.

Read-only inspection only. Never prompts for or records passwords/passphrases.
Results stay on this PC under the existing project's snapshots directory.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
LIBS = ROOT.parent / 'work' / 'python_libs'
sys.path[:0] = [str(ROOT / 'src'), str(LIBS)]
from firewall_auditor.transport import Operation, load_hosts
from firewall_auditor.tools import Inspector


def main():
    destination = ROOT / 'snapshots'
    destination.mkdir(exist_ok=True)
    report = {'attempted_at': datetime.now(timezone.utc).isoformat(),
              'target': 'ubuntu-vm', 'mode': 'real_vm_read_only',
              'execution_context': 'user_windows_terminal',
              'observations': [], 'errors': []}
    try:
        inspector = Inspector(load_hosts(str(ROOT / 'config' / 'hosts.local.json')))
        # Check authentication first, then attempt each fixed read independently.
        operations = [Operation.HOST] + [op for op in Operation if op != Operation.HOST]
        for op in operations:
            try:
                result = inspector.call(op.value, 'ubuntu-vm')
                report['observations'].append(result)
                print('PASS:', op.value, flush=True)
            except Exception as exc:
                report['errors'].append({'tool': op.value, 'error': str(exc)})
                print('FAIL:', op.value, '-', str(exc), flush=True)
    except Exception as exc:
        report['errors'].append({'stage': 'configuration', 'error': str(exc)})
        print('FAIL: configuration -', str(exc), flush=True)
    report['inspection_complete'] = (len(report['observations']) == len(Operation)
                                     and not report['errors'])
    snapshot = destination / 'ubuntu-vm-inspection.json'
    snapshot.write_text(json.dumps(report, indent=2), encoding='utf-8')
    env = os.environ.copy()
    env['PYTHONPATH'] = os.pathsep.join([str(ROOT / 'src'), str(LIBS)])
    env['FWA_RUN_VM_TESTS'] = '1'
    env['FWA_HOSTS_FILE'] = str(ROOT / 'config' / 'hosts.local.json')
    env['FWA_HOST'] = 'ubuntu-vm'
    completed = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-rA',
                                '--junitxml=' + str(destination / 'phase1-tests.xml')],
                               cwd=ROOT, env=env, text=True, encoding='utf-8',
                               errors='replace', stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (destination / 'phase1-tests.txt').write_text(completed.stdout, encoding='utf-8')
    print(completed.stdout)
    report['pytest_exit_code'] = completed.returncode
    report['phase1_checks_passed'] = report['inspection_complete'] and completed.returncode == 0
    snapshot.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('Results saved in:', destination)
    print('Phase 1 checks passed:', report['phase1_checks_passed'])
    return 0 if report['phase1_checks_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
