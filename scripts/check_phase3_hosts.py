"""Native-terminal read-only SSH and host-only address checks. No firewall writes."""
from datetime import datetime,timezone
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from firewall_auditor.transport import load_hosts,SSHTransport,Operation
from firewall_auditor.phase3_ledger import Ledger


def main():
    report={'mode':'real_ssh_host_setup_check','observed_at':datetime.now(timezone.utc).isoformat(),
            'firewall_modified':False,'checks':[]}
    expected={'ubuntu-vm':'192.168.56.30','app02':'192.168.56.10','attacker':'192.168.56.20'}
    hosts=load_hosts(str(ROOT/'config/hosts.local.json'))
    ledger=Ledger(ROOT/'audit/audit.sqlite3')
    for alias,address in expected.items():
        item={'host':alias,'expected_host_only_ip':address}
        try:
            host=hosts[alias]
            ledger.append('host_setup_check_requested',{'host':alias,'expected_host_only_ip':address})
            kernel=SSHTransport().read(host,Operation.HOST).strip()
            interfaces=json.loads(SSHTransport().read(host,Operation.INTERFACES))
            addresses=[a.get('local') for interface in interfaces for a in interface.get('addr_info',[])]
            item.update(ssh_authenticated=True,host_only_address_present=address in addresses,
                        passed=address in addresses,kernel=kernel)
            if address not in addresses:item['error']='Authenticated, but expected host-only IP is not configured on this guest.'
        except Exception as exc:
            item.update(passed=False,error_type=type(exc).__name__,
                        error='Check actual username, installed public key, verified known-host entry, SSH agent, SSH server and host-only adapter.')
        ledger.append('host_setup_check_result',item)
        report['checks'].append(item)
        print(('PASS' if item['passed'] else 'FAIL')+': '+alias)
        if item.get('error'):print(item['error'])
    report['passed']=all(c['passed'] for c in report['checks'])
    path=ROOT/'reports/phase3-host-checks.json';path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('All host checks passed:',report['passed'])
    print('Saved:',path)
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
