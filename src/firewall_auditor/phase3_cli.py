"""Operator-only Phase 3 console. Never accepts a noninteractive approval flag."""
import argparse
import getpass
import json
from pathlib import Path
import sys
from .phase3_policy import ChangeDenied, digest, make_proposal
from .phase3_ledger import AuditFailure, Ledger
from .phase3_transport import SSHChangeBackend
from .remediation import Remediator
from .transport import load_hosts, InspectionError

ROOT=Path(__file__).resolve().parents[2]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    draft=commands.add_parser('plan',help='Build an inert draft from saved evidence; no SSH or firewall changes')
    draft.add_argument('--snapshot',required=True);draft.add_argument('--host',required=True)
    draft.add_argument('--family',choices=['ip','ip6'],required=True)
    draft.add_argument('--table',required=True);draft.add_argument('--chain',required=True)
    draft.add_argument('--handle',required=True,type=int);draft.add_argument('--source',required=True)
    draft.add_argument('--verification',required=True);draft.add_argument('--out',required=True)
    status=commands.add_parser('status',help='Read installed helper status; no changes')
    status.add_argument('--hosts',required=True);status.add_argument('--host',required=True)
    apply=commands.add_parser('apply',help='Refresh evidence, run baseline probes, review exact proposal and ask for human approval')
    apply.add_argument('--hosts',required=True);apply.add_argument('--proposal',required=True)
    apply.add_argument('--out',default=str(ROOT/'reports/phase3-last-result.json'))
    apply.add_argument('--audit-db',default=str(ROOT/'audit/audit.sqlite3'))
    audit=commands.add_parser('audit-verify',help='Verify persisted hash-chained local events')
    audit.add_argument('--audit-db',default=str(ROOT/'audit/audit.sqlite3'))
    args=parser.parse_args()
    try:
        if args.command=='audit-verify':
            ledger=Ledger(args.audit_db);print(json.dumps({'integrity_ok':ledger.verify(),'events':len(ledger.events())}));return 0
        if args.command=='plan':
            payload=json.loads(Path(args.snapshot).read_text(encoding='utf-8-sig'))
            raw=payload if 'nftables' in payload else next(o['data']['raw'] for o in payload['observations'] if o['tool']=='get_firewall_rules' and o['host']==args.host)
            target={'family':args.family,'table':args.table,'chain':args.chain,'handle':args.handle}
            verification=json.loads(Path(args.verification).read_text(encoding='utf-8-sig'))
            proposal=make_proposal(raw,args.host,target,args.source,verification)
            path=Path(args.out);path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(json.dumps(proposal,indent=2),encoding='utf-8')
            print(json.dumps({'mode':'inert_draft','saved_to':str(path.resolve()),'proposal_hash':digest(proposal),
                              'firewall_modified':False,'baseline_verified':False},indent=2));return 0
        hosts=load_hosts(args.hosts)
        if args.command=='status':
            print(json.dumps(SSHChangeBackend(hosts,args.host,{'checks':[]}).status(),indent=2));return 0
        if not sys.stdin.isatty():raise ChangeDenied('Approval requires an interactive operator terminal')
        draft=json.loads(Path(args.proposal).read_text(encoding='utf-8-sig'))
        host=draft['host'];plan=draft['verification']
        ledger=Ledger(args.audit_db)
        backend=SSHChangeBackend(hosts,host,plan)
        engine=Remediator(backend,ledger,host)
        prepared=engine.prepare(draft['target'],draft['new_source'],plan)
        proposal=prepared['proposal'];hashed=digest(proposal)
        print('REVIEW: one exact source restriction. Automatic rollback is part of this approval.')
        print('Before/after rule, baseline results and verification plan:')
        print(json.dumps(proposal,indent=2,ensure_ascii=True))
        print('Approval digest:',hashed)
        actor=getpass.getuser()
        answer=input('Type APPROVE '+hashed+' to apply, or anything else to reject: ').strip()
        if answer!='APPROVE '+hashed:
            ledger.reject(proposal,actor)
            print('Rejected. No firewall changes were requested.');return 0
        token=ledger.approve(proposal,actor)
        result=engine.execute(prepared,token)
        path=Path(args.out);path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(result,indent=2),encoding='utf-8')
        print(json.dumps(result,indent=2))
        return 0 if result['status']=='verified' else 1
    except (ChangeDenied,AuditFailure,InspectionError,ValueError,KeyError,TypeError,OSError,StopIteration) as exc:
        print('Phase 3 stopped: '+str(exc),file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
