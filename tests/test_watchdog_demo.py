"""Watchdog client harness tests. nftables, systemd and clocks are simulated."""
from contextlib import nullcontext
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from test_phase3 import FakeLinux,FakeBackend,POLICY,TARGET,PLAN,raw_rules
from firewall_auditor.phase3_helper import RootHelper
from firewall_auditor.phase3_ledger import Ledger
from firewall_auditor.phase3_policy import ChangeDenied,fingerprint
from firewall_auditor.remediation import Remediator
from firewall_auditor.watchdog_demo import watchdog_trial


class WatchdogDemoTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.system=FakeLinux();self.state=Path(self.temp.name)/'root'
        self.helper=RootHelper(self.system,POLICY,self.state,lock_factory=nullcontext)
        self.backend=FakeBackend(self.helper,self.system)
        self.ledger=Ledger(Path(self.temp.name)/'local.sqlite3')
        self.prepared=Remediator(self.backend,self.ledger,'target').prepare(TARGET,'192.168.56.10/32',PLAN)
        self.backend.confirm=Mock(side_effect=AssertionError('Demo must not confirm'))
        self.backend.rollback=Mock(side_effect=AssertionError('Demo must not request rollback'))

    def run_trial(self,restore=True,at=120):
        clock=[0]
        def sleep(seconds):
            clock[0]+=seconds
            if restore and clock[0]>=at:
                # A separate fake helper instance is the simulated timer callback.
                RootHelper(self.system,POLICY,self.state,lock_factory=nullcontext).timed_rollback(self.prepared['proposal']['change_id'])
        token=self.ledger.approve(self.prepared['proposal'],'operator')
        return watchdog_trial(self.backend,self.ledger,self.prepared,token,sleep=sleep,
            monotonic=lambda:clock[0],max_wait=170,poll_interval=20)

    def test_independent_restore_is_observed_without_client_rollback_or_commit(self):
        result=self.run_trial()
        self.assertEqual(result['status'],'independent_restore_observed')
        self.assertEqual(result['elapsed_seconds'],120)
        self.assertEqual(result['restored_fingerprint'],fingerprint(raw_rules()))
        self.assertTrue(result['root_service_journal_required'])
        self.backend.confirm.assert_not_called();self.backend.rollback.assert_not_called()
        self.assertTrue(self.ledger.verify())

    def test_missing_restoration_never_passes(self):
        result=self.run_trial(restore=False)
        self.assertEqual(result['status'],'incomplete')
        self.backend.confirm.assert_not_called();self.backend.rollback.assert_not_called()

    def test_early_restore_is_not_mislabeled_as_timed_watchdog_success(self):
        result=self.run_trial(at=20)
        self.assertEqual(result['status'],'incomplete')
        self.backend.confirm.assert_not_called();self.backend.rollback.assert_not_called()

    def test_missing_approval_cannot_apply_test_change(self):
        with self.assertRaises(ChangeDenied):watchdog_trial(self.backend,self.ledger,self.prepared,'approved')
        self.assertEqual(self.backend.apply_calls,0)
