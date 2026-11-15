"""Opt-in live tests. No firewall writes. Never substitute a mock for this test."""
import os
import unittest
from firewall_auditor.tools import Inspector
from firewall_auditor.transport import load_hosts, Operation


@unittest.skipUnless(os.getenv("FWA_RUN_VM_TESTS") == "1", "Real VM test not explicitly enabled")
class RealVMTests(unittest.TestCase):
    def test_read_real_vm(self):
        hosts = load_hosts(os.environ["FWA_HOSTS_FILE"])
        alias = os.environ["FWA_HOST"]
        snapshot = Inspector(hosts).snapshot(alias)
        self.assertEqual(snapshot["mode"], "real_vm_read_only")
        self.assertEqual(len(snapshot["observations"]), len(Operation))
        rules = snapshot["observations"][0]["data"]
        self.assertIn("nftables", rules["raw"])
        self.assertTrue(all(o["untrusted_observation"] for o in snapshot["observations"]))
