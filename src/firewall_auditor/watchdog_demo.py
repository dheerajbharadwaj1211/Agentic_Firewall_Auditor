"""Operator-approved watchdog demonstration, separate from normal remediation.

Intentionally NEVER calls confirm or rollback. Acknowledged restriction must
be observed, then the VM independently restores the exact before fingerprint.
The reset to a /24 lab baseline is a separate reviewed/manual operation.
"""
from copy import deepcopy
import time
from .phase3_policy import ChangeDenied,digest,fingerprint,replace_in_snapshot,validate_proposal,validate_results
from .remediation import Remediator


def watchdog_trial(backend,ledger,prepared,token,*,sleep=time.sleep,monotonic=time.monotonic,
                   max_wait=170,poll_interval=5,progress=None):
    p=deepcopy(prepared['proposal']);lease=deepcopy(prepared['lease'])
    if lease.get('proposal_hash')!=digest(p) or lease.get('change_id')!=p['change_id']:
        raise ChangeDenied('Prepared capability does not match the exact proposal')
    ledger.verify()
    before=backend.snapshot();validate_proposal(before,p)
    ledger.consume(p,token)
    ledger.append('watchdog_demo_apply_requested',{'change_id':p['change_id'],'proposal_hash':digest(p),
        'confirmation_will_be_withheld':True,'client_will_not_request_rollback':True})
    started=monotonic();applied=False
    result={'mode':'live_watchdog_demonstration','host':p['host'],'change_id':p['change_id'],
            'proposal_hash':digest(p),'status':'incomplete','client_requested_rollback':False,
            'client_confirmed':False,'firewall_modified':'unknown',
            'service_unit':'fwa-rollback-'+p['change_id']+'.service'}
    try:
        response=backend.apply(lease,digest(p))
        if response.get('phase')!='applied':raise ChangeDenied('No acknowledged applied state')
        applied=True;result['firewall_modified']=True
        after=fingerprint(replace_in_snapshot(before,p['target'],p['after_rule']))
        if fingerprint(backend.snapshot())!=after:raise ChangeDenied('The exact restriction was not observed')
        engine=Remediator(backend,ledger,p['host'])
        restricted=engine.gather(p['verification']);validate_results(p['verification'],restricted)
        result['restricted_verification']=restricted
        ledger.append('watchdog_demo_left_unconfirmed',{'change_id':p['change_id'],'after_fingerprint':after,
                                                       'restricted_verification':restricted})
        while monotonic()-started<max_wait:
            if progress:progress(int(monotonic()-started))
            try:status=backend.status()
            except Exception:
                sleep(poll_interval);continue
            if status['current_fingerprint']==p['before_fingerprint'] and p['change_id'] not in status['pending']:
                elapsed=monotonic()-started
                if elapsed<100:raise ChangeDenied('Restore occurred too early to attribute to the 120-second watchdog; review root journal')
                restored=engine.gather(p['verification']);validate_results(p['verification'],restored,before=True)
                result.update(status='independent_restore_observed',restored_verification=restored,
                              restored_fingerprint=status['current_fingerprint'],elapsed_seconds=round(elapsed,2),
                              root_service_journal_required=True,
                              final_lab_access='Temporary /24 baseline restored; reapply verified APP02-only restriction after evidence capture.')
                ledger.append('watchdog_independent_restore_observed',result)
                return result
            sleep(poll_interval)
        raise ChangeDenied('Restoration was not observed within the watchdog test window')
    except BaseException as exc:
        result.update(failure_type=type(exc).__name__,applied_reply_received=applied,
                      action='Do not confirm or blindly rerun. Inspect the VM console/root timer journal; an armed watchdog remains independent of this client.')
        try:ledger.append('watchdog_demo_incomplete',result)
        except Exception:result['audit_write_failed']=True
        return result
