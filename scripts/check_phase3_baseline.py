"""Read-only live lab baseline; creates an inert remediation draft, never applies it."""
from datetime import datetime,timezone
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from firewall_auditor.phase3_ledger import Ledger
from firewall_auditor.phase3_policy import (ChangeDenied,make_proposal,restricted_rule,validate_results)
from firewall_auditor.phase3_transport import SSHChangeBackend
from firewall_auditor.remediation import Remediator
from firewall_auditor.transport import load_hosts


def main():
    ledger=Ledger(ROOT/'audit/audit.sqlite3')
    report={'mode':'real_read_only_lab_baseline','observed_at':datetime.now(timezone.utc).isoformat(),
            'firewall_modified':False,'passed':False}
    try:
        plan=json.loads((ROOT/'config/phase3-verification.local.json').read_text(encoding='utf-8-sig'))
        backend=SSHChangeBackend(load_hosts(str(ROOT/'config/hosts.local.json')),'ubuntu-vm',plan)
        status=backend.status()
        if status['pending']:raise ChangeDenied('A previous change is pending; resolve it before baseline checks')
        raw=backend.snapshot()
        snapshot=ROOT/'reports/phase3-baseline-ruleset.json';snapshot.parent.mkdir(parents=True,exist_ok=True)
        snapshot.write_text(json.dumps(raw,indent=2),encoding='utf-8')
        candidates=[]
        for item in raw['nftables']:
            rule=item.get('rule')
            if not rule or rule.get('family')!='ip' or rule.get('table')!='fwa_lab' or rule.get('chain')!='input':continue
            try:
                unused,port,source=restricted_rule(rule,'192.168.56.10/32')
                if port==3306 and source=='192.168.56.0/24':
                    candidates.append({k:rule[k] for k in ('family','table','chain','handle')})
            except ChangeDenied:continue
        if len(candidates)!=1:raise ChangeDenied('Expected exactly one supported TCP 3306 rule allowing the lab /24 source range')
        engine=Remediator(backend,ledger,'ubuntu-vm')
        baseline=engine.gather(plan)
        validate_results(plan,baseline,before=True)
        proposal=make_proposal(raw,'ubuntu-vm',candidates[0],'192.168.56.10/32',plan,baseline=baseline)
        destination=ROOT/'plans/phase3-live-draft.json';destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_text(json.dumps(proposal,indent=2),encoding='utf-8')
        snapshot=ROOT/'reports/phase3-baseline-ruleset.json';snapshot.parent.mkdir(parents=True,exist_ok=True)
        snapshot.write_text(json.dumps(raw,indent=2),encoding='utf-8')
        report.update(passed=True,baseline=baseline,target_rule=candidates[0],
                      draft_saved_to=str(destination),helper_mutation_enabled=status['policy']['enabled'])
        for row in baseline['checks']:print('PASS: '+row['host']+' can connect to 192.168.56.30:3306')
        print('PASS: target management SSH')
        print('Draft created only; no restriction applied.')
    except Exception as exc:
        report.update(error_type=type(exc).__name__,error='Lab baseline not verified. Check that the approved fixture is applied, the TCP test service is running and SSH-agent/key access still works.')
        if isinstance(exc,ChangeDenied):report['detail']=str(exc)
        print('FAIL:',report.get('detail',report['error']))
    ledger.append('lab_baseline_check',report)
    path=ROOT/'reports/phase3-baseline-checks.json';path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('All baseline checks passed:',report['passed']);print('Saved:',path)
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
