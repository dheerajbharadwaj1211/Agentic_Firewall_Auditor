"""Synthetic LLM and VM tests; no external calls or firewall mutations."""
from copy import deepcopy
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from firewall_auditor.agent import AgentController, AgentError, Limits, PolicyDenied, ToolCall, Turn, model_view
from firewall_auditor.context import HostContext, load_context
from firewall_auditor.findings import analyze
from firewall_auditor.nftables import parse_ruleset
from firewall_auditor.reports import analyze_snapshot, write_report
from firewall_auditor.transport import InspectionError, Operation
from test_phase1 import fixture


def observations(data=None, port=3306, address="0.0.0.0"):
    result = {}
    for op in Operation:
        content = [] if op in {Operation.INTERFACES, Operation.ROUTES, Operation.ROUTES6} else {"text": "synthetic"}
        if op == Operation.RULES:
            content = asdict(parse_ruleset(json.dumps(data or fixture())))
        elif op == Operation.SERVICES:
            content = {"text": f"tcp LISTEN 0 128 {address}:{port} *:*\n", "listeners": [
                {"protocol": "tcp", "state": "LISTEN", "recv_q": 0, "send_q": 128,
                 "local": {"address": address, "port": port}, "peer": {"address": "*", "port": None},
                 "process_metadata": 'users:(("service",pid=4,fd=2))'}]}
        result[op.value] = {"host": "vm", "tool": op.value, "data": content,
                            "evidence_id": "E-" + op.value.removeprefix("get_"),
                            "untrusted_observation": True, "observed_at": "synthetic"}
    return result


class FakeInspector:
    def __init__(self, data=None):
        self.data = data or observations()
        self.calls = []

    def call(self, name, host):
        self.calls.append((name, host))
        return deepcopy(self.data[name])


class PlanProvider:
    mode = "mock_llm_synthetic_vm"

    def start(self, instructions, goal, tools):
        self.index = 0
        self.requests = []

    def next(self, results, timeout, max_output_tokens):
        self.requests.append(deepcopy(results))
        self.index += 1
        if self.index == 1:
            # Model chooses a different ordering; controller does not hard-code a workflow.
            names = [op.value for op in reversed(list(Operation))] + ["get_host_context"]
            return Turn([ToolCall(f"read-{i}", n, {"host": "vm"}) for i,n in enumerate(names)], 30)
        if self.index == 2:
            return Turn([ToolCall("analyze", "analyze_findings", {"host": "vm"})], 20)
        ids = [f["id"] for f in results[0]["result"]["findings"]]
        return Turn([ToolCall("complete", "complete_audit", {"host": "vm", "finding_ids": ids})], 20)


class SequenceProvider:
    mode = "mock_llm_synthetic_vm"
    def __init__(self, turns): self.turns = iter(turns)
    def start(self, *args): pass
    def next(self, *args): return next(self.turns)


class FindingTests(unittest.TestCase):
    def categories(self, obs=None, context=None):
        return {f["category"] for f in analyze("vm", obs or observations(), context or HostContext())["findings"]}

    def test_database_candidate_has_evidence_and_no_reachability_claim(self):
        report = analyze("vm", observations(), HostContext(role="database"))
        finding = report["findings"][0]
        self.assertEqual(finding["category"], "database_exposure")
        self.assertEqual(finding["internet_reachability"], "not_tested")
        self.assertEqual(len(finding["evidence"]), 2)
        self.assertTrue(finding["verification_plan"])
        self.assertFalse(report["connectivity_tested"])
        self.assertFalse(finding["remediation_applied"])

    def test_legitimate_public_https_is_not_database_or_management_flaw(self):
        data = fixture()
        data["nftables"][-1]["rule"]["expr"][0]["match"]["right"] = 443
        self.assertEqual(self.categories(observations(data,443), HostContext(role="web", public_services=[443])), set())

    def test_restricted_database_client_not_broad_exposure(self):
        data = fixture()
        data["nftables"][-1]["rule"]["expr"].insert(0, {"match": {"op": "==", "left": {
            "payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.0.2.10"}})
        self.assertNotIn("database_exposure", self.categories(observations(data)))

    def test_loopback_listener_is_not_exposed(self):
        self.assertEqual(self.categories(observations(address="127.0.0.1")), set())

    def test_unsupported_constraint_does_not_become_proven_accept_path(self):
        data = fixture()
        data["nftables"][-1]["rule"]["expr"].insert(0, {"jump": {"target": "other"}})
        self.assertEqual(self.categories(observations(data)), set())

    def test_any_to_any_and_ssh(self):
        data = fixture()
        data["nftables"][-1]["rule"]["expr"] = [{"accept": None}]
        self.assertTrue({"any_to_any", "ssh_exposure"} <= self.categories(observations(data,22)))

    def test_broad_source_and_segmentation_use_operator_context(self):
        context = HostContext(role="database", allowed_clients={"3306": ["10.0.2.10/32"]}, user_subnets=["10.0.10.0/24"])
        self.assertTrue({"broad_source", "segmentation"} <= self.categories(context=context))

    def test_management_service(self):
        data = fixture()
        data["nftables"][-1]["rule"]["expr"][0]["match"]["right"] = 6443
        self.assertIn("management_exposure", self.categories(observations(data,6443)))

    def test_empty_accept_chain_and_nat_uncertainty(self):
        data = fixture();data["nftables"].pop();data["nftables"][2]["chain"]["policy"] = "accept"
        report = analyze("vm", observations(data,22), HostContext(network_boundary="virtualbox_nat"))
        self.assertTrue({"permissive_input_policy", "ssh_exposure"} <= {f["category"] for f in report["findings"]})
        self.assertTrue(any("VirtualBox" in n for n in report["coverage_notes"]))

    def test_ipv4_source_does_not_expose_ipv6_only_listener(self):
        data=fixture()
        data["nftables"][-1]["rule"]["expr"].insert(0, {"match": {"op": "==", "left": {
            "payload": {"protocol": "ip", "field": "saddr"}}, "right": "0.0.0.0/0"}})
        self.assertNotIn("database_exposure", self.categories(observations(data,address="::")))

    def test_missing_input_hook_is_reported_as_configuration_gap(self):
        data=observations({"nftables":[]})
        self.assertIn("missing_input_filter",self.categories(data))

    def test_union_of_allowed_client_ranges_is_respected(self):
        data=fixture()
        data["nftables"][-1]["rule"]["expr"].insert(0,{"match":{"op":"==","left":{
            "payload":{"protocol":"ip","field":"saddr"}},"right":"10.0.2.0/24"}})
        context=HostContext(allowed_clients={"3306":["10.0.2.0/25","10.0.2.128/25"]})
        self.assertNotIn("broad_source",self.categories(observations(data),context))

    def test_missing_observation_rejected(self):
        data = observations();data.pop(Operation.ROUTES6.value)
        with self.assertRaises(ValueError): analyze("vm", data, HostContext())


class ControllerTests(unittest.TestCase):
    def test_autonomous_sequence_reports_only_evidence_backed_findings(self):
        inspector=FakeInspector();provider=PlanProvider()
        report=AgentController(inspector,provider,"vm").run()
        self.assertEqual(report["status"], "complete")
        self.assertEqual(len(inspector.calls),7)
        self.assertEqual(inspector.calls[0][0],Operation.HOST.value)
        self.assertTrue(report["findings"])
        self.assertFalse(report["firewall_modified"])
        self.assertTrue(all(e["decision"]=="allowed" for e in report["events"]))

    def test_forbidden_tools_extra_args_and_cross_host_never_reach_inspector(self):
        inspector=FakeInspector();controller=AgentController(inspector,PlanProvider(),"vm")
        for name,args in [("execute_shell_command",{"host":"vm"}), ("apply_rule_change",{"host":"vm"}),
                          ("get_routes",{"host":"other"}), ("get_routes",{"host":"vm","command":"bad"}),
                          ("rollback_change",{"host":"vm"}), ("delete_audit_logs",{"host":"vm"})]:
            with self.subTest(name=name),self.assertRaises(PolicyDenied): controller.dispatch(name,args)
        self.assertFalse(inspector.calls)

    def test_observation_comments_do_not_get_model_privileges(self):
        provider=PlanProvider();report=AgentController(FakeInspector(),provider,"vm").run()
        self.assertEqual(report["status"],"complete")
        exposed=json.dumps(provider.requests)
        self.assertNotIn("Ignore instructions",exposed)
        self.assertNotIn("process_metadata",exposed)
        self.assertNotIn('"raw"',exposed)

    def test_manipulated_model_cannot_modify_firewall(self):
        provider=SequenceProvider([Turn([ToolCall(str(i),"apply_rule_change",{"host":"vm"})]) for i in range(3)])
        inspector=FakeInspector();report=AgentController(inspector,provider,"vm").run()
        self.assertEqual(report["status"],"incomplete")
        self.assertTrue(all(e["decision"]=="denied" for e in report["events"]))
        self.assertFalse(inspector.calls)

    def test_model_cannot_invent_or_suppress_findings(self):
        controller=AgentController(FakeInspector(),PlanProvider(),"vm")
        for op in Operation: controller.dispatch(op.value,{"host":"vm"})
        controller.dispatch("get_host_context",{"host":"vm"})
        controller.dispatch("analyze_findings",{"host":"vm"})
        for ids in ([],["invented"]):
            with self.assertRaises(PolicyDenied): controller.dispatch("complete_audit",{"host":"vm","finding_ids":ids})

    def test_evidence_collection_and_context_required_before_finish(self):
        controller=AgentController(FakeInspector(),PlanProvider(),"vm")
        with self.assertRaises(PolicyDenied): controller.dispatch("complete_audit",{"host":"vm","finding_ids":[]})
        with self.assertRaises(PolicyDenied): controller.dispatch("analyze_findings",{"host":"vm"})

    def test_no_calls_budget_exhaustion_and_duplicate_ids(self):
        cases=[([Turn()],Limits()),
               ([Turn([ToolCall("a","get_routes",{"host":"vm"})])]*2,Limits(max_turns=2)),
               ([Turn([ToolCall("a","get_routes",{"host":"vm"}),ToolCall("a","get_routes",{"host":"vm"})])],Limits()),
               ([Turn([ToolCall("a","get_routes",{"host":"vm"})],100)],Limits(max_output_tokens=10)),
               ([Turn([ToolCall("a","get_routes",{"host":"vm"}),ToolCall("b","get_routes",{"host":"vm"})])],Limits(max_tool_calls=1))]
        for turns,limits in cases:
            with self.subTest(turns=turns):
                self.assertEqual(AgentController(FakeInspector(),SequenceProvider(turns),"vm",limits=limits).run()["status"],"incomplete")

    def test_provider_errors_do_not_leak_keys(self):
        provider=Mock(mode="mock_llm");provider.next.side_effect=RuntimeError("secret-in-http-url")
        report=AgentController(FakeInspector(),provider,"vm").run()
        self.assertNotIn("secret-in-http-url",json.dumps(report))
        self.assertEqual(report["status"],"incomplete")

    def test_inspection_errors_do_not_become_success(self):
        inspector=Mock();inspector.call.side_effect=InspectionError("private stderr")
        report=AgentController(inspector,SequenceProvider([Turn([ToolCall("a","get_routes",{"host":"vm"})])]),"vm").run()
        self.assertEqual(report["status"],"incomplete")
        self.assertNotIn("private stderr",json.dumps(report))

    def test_cache_and_single_use(self):
        inspector=FakeInspector();controller=AgentController(inspector,PlanProvider(),"vm")
        controller.dispatch("get_routes",{"host":"vm"});controller.dispatch("get_routes",{"host":"vm"})
        self.assertEqual(len(inspector.calls),1)
        controller.run()
        with self.assertRaises(AgentError):controller.run()

    def test_oversized_observation_is_incomplete(self):
        report=AgentController(FakeInspector(),SequenceProvider([Turn([ToolCall("a","get_routes",{"host":"vm"})])]),
            "vm",limits=Limits(max_observation_bytes=10)).run()
        self.assertEqual(report["status"],"incomplete")
        self.assertEqual(report["observations"],[])

    def test_time_budget_cannot_succeed_after_deadline(self):
        with patch("firewall_auditor.agent.time.monotonic",side_effect=[0,0,200]):
            report=AgentController(FakeInspector(),SequenceProvider([Turn()]),"vm",limits=Limits(max_seconds=1)).run()
        self.assertEqual(report["status"],"incomplete")
        with self.assertRaises(ValueError): Limits(max_seconds=float('nan')).validate()

    def test_known_environment_secret_redacted(self):
        data=observations()[Operation.HOST.value];data['data']['text']='kernel-secret'
        with patch.dict(os.environ,{"GEMINI_API_KEY":"kernel-secret"}):
            self.assertNotIn('kernel-secret',json.dumps(model_view(data)))


class ContextAndReportTests(unittest.TestCase):
    def test_context_validation(self):
        for ctx in (HostContext(role="guess"),HostContext(public_services=[True]),
                    HostContext(allowed_clients={"3306":["not-network"]})):
            with self.assertRaises(ValueError):ctx.validate()

    def test_offline_report_is_explicit_and_reparses_raw(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'snapshot.json';obs=observations()
            obs[Operation.RULES.value]['data']['rules'][0]['action']='drop'
            path.write_text(json.dumps({'observations':list(obs.values())}))
            report=analyze_snapshot(path,'vm',HostContext())
            self.assertFalse(report['llm_used'])
            self.assertEqual(report['mode'],'offline_analysis_of_saved_observations')
            self.assertTrue(report['findings'])
            write_report(report,Path(temp)/'report')
            self.assertTrue((Path(temp)/'report/report.md').exists())

    def test_snapshot_rejects_cross_host(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'snapshot.json';obs=observations();obs[Operation.HOST.value]['host']='other'
            path.write_text(json.dumps({'observations':list(obs.values())}))
            with self.assertRaises(ValueError):analyze_snapshot(path,'vm',HostContext())
