"""Live checks READ ONLY. This test suite never approves or applies a change."""
import json
import os
from pathlib import Path
import unittest
from firewall_auditor.phase3_ledger import Ledger
from firewall_auditor.phase3_policy import validate_results
from firewall_auditor.phase3_transport import SSHChangeBackend
from firewall_auditor.transport import load_hosts


@unittest.skipUnless(os.environ.get('FWA_RUN_PHASE3_LIVE_TESTS')=='1','Phase 3 live helper checks not explicitly enabled')
class Phase3LiveChecks(unittest.TestCase):
    def backend(self,plan):
        return SSHChangeBackend(load_hosts(os.environ['FWA_PHASE3_HOSTS_FILE']),os.environ.get('FWA_HOST','ubuntu-vm'),plan)

    def test_installed_root_helper_status(self):
        status=self.backend({'checks':[]}).status()
        self.assertEqual(status['helper_version'],1)
        self.assertIsInstance(status['pending'],list)
        self.assertEqual(len(status['current_fingerprint']),64)

    def test_approved_change_receipt_and_current_traffic(self):
        if not os.environ.get('FWA_PHASE3_RECEIPT'):self.skipTest('No explicitly approved live change receipt supplied')
        receipt=json.loads(Path(os.environ['FWA_PHASE3_RECEIPT']).read_text())
        self.assertEqual(receipt['status'],'verified')
        self.assertIs(receipt['firewall_modified'],True)
        ledger=Ledger(os.environ['FWA_PHASE3_AUDIT_DB']);self.assertTrue(ledger.verify())
        events=ledger.events();proposal=None
        for event in events:
            payload=event['payload']
            if event['kind']=='proposal' and payload.get('proposal_hash')==receipt['proposal_hash']:proposal=payload['proposal']
        self.assertIsNotNone(proposal)
        self.assertTrue(any(e['kind']=='human_approval' and e['payload'].get('proposal_hash')==receipt['proposal_hash'] for e in events))
        self.assertTrue(any(e['kind']=='approval_consumed' and e['payload'].get('proposal_hash')==receipt['proposal_hash'] for e in events))
        backend=self.backend(proposal['verification'])
        self.assertEqual(backend.status()['current_fingerprint'],receipt['after_fingerprint'])
        current={'management_ssh':backend.management(),'checks':[backend.probe(c,proposal['verification']) for c in proposal['verification']['checks']]}
        self.assertTrue(validate_results(proposal['verification'],current))
