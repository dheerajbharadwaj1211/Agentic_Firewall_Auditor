"""Explicit opt-in: real Gemini billing/network calls and real read-only VM access."""
import os
from pathlib import Path
import unittest
from firewall_auditor.agent import AgentController
from firewall_auditor.context import load_context
from firewall_auditor.gemini import GeminiProvider
from firewall_auditor.reports import write_report
from firewall_auditor.tools import Inspector
from firewall_auditor.transport import load_hosts, Operation


@unittest.skipUnless(os.environ.get("FWA_RUN_GEMINI_TESTS")=="1", "Live Gemini+VM test not explicitly enabled")
class GeminiLiveTests(unittest.TestCase):
    def test_real_gemini_investigates_real_vm(self):
        alias=os.environ["FWA_HOST"]
        provider=GeminiProvider()
        try:
            report=AgentController(Inspector(load_hosts(os.environ["FWA_HOSTS_FILE"])),provider,alias,
                load_context(os.environ.get("FWA_CONTEXT_FILE"),alias)).run()
        finally:
            provider.close()
        root=Path(__file__).resolve().parents[1]
        write_report(report,root/'reports'/'phase2-live-integration')
        self.assertEqual(report['status'],'complete',report.get('failure'))
        self.assertEqual({o['tool'] for o in report['observations']},{op.value for op in Operation})
        self.assertTrue(all(o['untrusted_observation'] for o in report['observations']))
        self.assertFalse(report['firewall_modified'])
        evidence={o['evidence_id'] for o in report['observations']}
        for finding in report['findings']:
            self.assertTrue(finding['evidence'])
            self.assertTrue(all(e['observation_id'] in evidence for e in finding['evidence']))
