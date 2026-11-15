"""Native-terminal watchdog demo; requires a separately approved /24 reset first."""
from pathlib import Path
import getpass,json,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from firewall_auditor.phase3_policy import ChangeDenied,digest
from firewall_auditor.phase3_ledger import Ledger
from firewall_auditor.phase3_transport import SSHChangeBackend
from firewall_auditor.remediation import Remediator
from firewall_auditor.transport import load_hosts
from firewall_auditor.watchdog_demo import watchdog_trial


def main():
    if not sys.stdin.isatty():print('Run in an interactive Windows terminal.');return 1
    ledger=Ledger(ROOT/'audit/audit.sqlite3')
    try:
        draft=json.loads((ROOT/'plans/phase3-live-draft.json').read_text())
        backend=SSHChangeBackend(load_hosts(str(ROOT/'config/hosts.local.json')),draft['host'],draft['verification'])
        prepared=Remediator(backend,ledger,draft['host']).prepare(draft['target'],draft['new_source'],draft['verification'])
        p=prepared['proposal']
        if p['old_source']!='192.168.56.0/24' or p['new_source']!='192.168.56.10/32' or p['port']!=3306:
            raise ChangeDenied('This demonstration is limited to the reviewed /24-to-APP02 lab restriction')
        print('WATCHDOG TEST: apply this exact restriction but deliberately do NOT confirm it.')
        print('The VM must restore the /24 lab baseline after about 120 seconds. This client will not request rollback.')
        print(json.dumps(p,indent=2,ensure_ascii=True))
        expected='APPROVE '+digest(p)
        answer=input('Type '+expected+' to approve this watchdog test, otherwise reject: ').strip()
        if answer!=expected:
            ledger.reject(p,getpass.getuser());print('Rejected; no rule change requested.');return 0
        token=ledger.approve(p,getpass.getuser())
        last=[-1]
        def progress(elapsed):
            bucket=elapsed//20
            if bucket!=last[0]:print('Waiting for independent VM watchdog:',elapsed,'seconds',flush=True);last[0]=bucket
        result=watchdog_trial(backend,ledger,prepared,token,progress=progress)
        path=ROOT/'reports/phase3-watchdog-result.json';path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(result,indent=2),encoding='utf-8')
        print(json.dumps(result,indent=2))
        print('Root evidence command: sudo journalctl -u '+result['service_unit']+' --no-pager')
        return 0 if result['status']=='independent_restore_observed' else 1
    except Exception as exc:
        print('Watchdog setup stopped ('+type(exc).__name__+'). Verify the approved /24 baseline, test listener, SSH access and helper policy.')
        return 1


if __name__=='__main__':raise SystemExit(main())
