"""Operator-controlled propose -> approve -> apply -> verify -> confirm/rollback.

No method in this module is advertised as an LLM tool. Only an approval issued
by the local ledger for this exact reviewed proposal permits the apply path.
"""
from copy import deepcopy
import time
from .phase3_ledger import AuditFailure
from .phase3_policy import (ChangeDenied, digest, fingerprint, make_proposal,
    replace_in_snapshot, validate_proposal, validate_results)


class Remediator:
    def __init__(self,backend,ledger,host):
        self.backend=backend;self.ledger=ledger;self.host=host

    def gather(self,plan):
        return {'management_ssh':self.backend.management(),
                'checks':[self.backend.probe(check,plan) for check in plan['checks']]}

    def prepare(self,target,new_source,plan):
        try:return self._prepare(target,new_source,plan)
        except Exception as exc:
            try:self.ledger.append('prepare_denied',{'host':self.host,'error_type':type(exc).__name__})
            except Exception:pass
            raise

    def _prepare(self,target,new_source,plan):
        self.ledger.append('inspection_requested',{'host':self.host,'target':target})
        raw=self.backend.snapshot()
        proposal=make_proposal(raw,self.host,target,new_source,plan)
        status=self.backend.status()
        # Independent root policy and local policy must both permit the same proposal.
        validate_proposal(raw,proposal,status['policy'],require_baseline=False)
        self.ledger.append('policy_allowed',{'host':self.host,'proposal_hash':digest(proposal),'operation':'restrict_source'})
        baseline=self.gather(plan)
        validate_results(plan,baseline,before=True)
        proposal['baseline']=baseline
        validate_proposal(raw,proposal,status['policy'])
        self.ledger.append('baseline_verified',{'host':self.host,'results':baseline})
        self.ledger.append('proposal',{'proposal_hash':digest(proposal),'proposal':proposal})
        lease=self.backend.prepare(proposal)
        if lease.get('proposal_hash')!=digest(proposal) or lease.get('change_id')!=proposal['change_id'] or lease.get('phase')!='prepared':
            raise ChangeDenied('Helper prepared a different proposal')
        self.ledger.append('prepared',{'change_id':proposal['change_id'],'proposal_hash':digest(proposal)})
        return {'proposal':proposal,'lease':lease}

    def execute(self,prepared,approval_token):
        proposal=deepcopy(prepared['proposal']);lease=deepcopy(prepared['lease'])
        if proposal['host']!=self.host or lease.get('proposal_hash')!=digest(proposal):
            raise ChangeDenied('Prepared change does not match selected host and proposal')
        try:
            self.ledger.verify()
            # Stale state invalidates approval before any mutation request.
            before=self.backend.snapshot()
            validate_proposal(before,proposal)
            self.ledger.consume(proposal,approval_token)
        except Exception as exc:
            try:self.ledger.append('apply_denied',{'change_id':proposal['change_id'],'error_type':type(exc).__name__})
            except Exception:pass
            raise
        self.ledger.append('apply_requested',{'change_id':proposal['change_id'],'proposal_hash':digest(proposal)})
        may_have_changed=False
        applied_reply=False
        try:
            may_have_changed=True  # Set BEFORE RPC: a lost reply is an uncertain mutation.
            applied=self.backend.apply(lease,digest(proposal))
            if applied.get('phase')!='applied':raise ChangeDenied('Helper did not report applied state')
            applied_reply=True
            self.ledger.append('applied',{'change_id':proposal['change_id'],'result':applied})
            expected=fingerprint(replace_in_snapshot(before,proposal['target'],proposal['after_rule']))
            if fingerprint(self.backend.snapshot())!=expected:raise ChangeDenied('Post-change rules differ from approved replacement')
            verification=self.gather(proposal['verification'])
            validate_results(proposal['verification'],verification)
            self.ledger.append('verification_passed',{'change_id':proposal['change_id'],'results':verification})
            # Persist commit intent first; helper also durably records verification/confirmation.
            self.ledger.append('confirmation_requested',{'change_id':proposal['change_id']})
            confirmed=self.backend.confirm(lease,verification)
            if confirmed.get('phase')!='confirmed':raise ChangeDenied('Helper did not confirm the exact verified change')
            self.ledger.append('confirmed',{'change_id':proposal['change_id']})
            return {'status':'verified','host':self.host,'change_id':proposal['change_id'],'proposal_hash':digest(proposal),
                    'after_fingerprint':expected,'before_fingerprint':proposal['before_fingerprint'],
                    'firewall_modified':True,'rollback_performed':False,'verification':verification}
        except BaseException as exc:
            if not may_have_changed:raise
            try:
                rollback=self.backend.rollback(lease)
                if rollback.get('phase')!='rolled_back' or rollback.get('rule_restored') is not True:
                    raise ChangeDenied('Rollback was not verified')
                result={'status':'rolled_back','host':self.host,'change_id':proposal['change_id'],
                        'firewall_modified':True if applied_reply or rollback.get('replacement_applied') else 'uncertain_before_restore',
                        'rollback_verified':True,'rollback_performed':rollback.get('replacement_applied',False),'rollback':rollback,'failure_type':type(exc).__name__}
            except Exception:
                result={'status':'rollback_pending_or_manual_review','host':self.host,'change_id':proposal['change_id'],
                        'firewall_modified':'unknown','rollback_performed':'unconfirmed',
                        'failure_type':type(exc).__name__,
                        'action':'Check the VM console and root helper state; independent rollback timer remains the safety mechanism.'}
            try:self.ledger.append('remediation_failed',result)
            except Exception:result['local_audit_write_failed']=True
            if isinstance(exc,(KeyboardInterrupt,SystemExit)):
                # Return explicit rollback outcome rather than hiding it behind an interrupt.
                result['interrupted']=True
            return result
