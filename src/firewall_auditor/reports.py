"""Local report output and explicit offline analysis of saved observations."""
from dataclasses import asdict
import json
from pathlib import Path
from .findings import analyze
from .nftables import parse_ruleset
from .services import parse_listeners
from .transport import Operation


def analyze_snapshot(path, host, context):
    payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    items = payload.get("observations")
    if not isinstance(items, list):
        raise ValueError("Snapshot must contain observation records")
    observations = {}
    for item in items:
        name = item["tool"]
        if name not in {op.value for op in Operation} or name in observations or item["host"] != host:
            raise ValueError("Duplicate, invalid or cross-host snapshot observation")
        observations[name] = dict(item, evidence_id="E-" + name.removeprefix("get_"), untrusted_observation=True)
    # Reparse source data rather than trusting a saved normalized firewall/listener model.
    raw = observations[Operation.RULES.value]["data"]["raw"]
    observations[Operation.RULES.value]["data"] = asdict(parse_ruleset(json.dumps(raw)))
    text = observations[Operation.SERVICES.value]["data"]["text"]
    observations[Operation.SERVICES.value]["data"] = {"text": text, "listeners": parse_listeners(text)}
    result = analyze(host, observations, context)
    return {"schema_version": 1, "phase": 2, "mode": "offline_analysis_of_saved_observations",
            "status": "offline_analysis_complete", "host": host, "read_only": True,
            "firewall_modified": False, "llm_used": False, "source_snapshot": str(Path(path).resolve()),
            **result, "observations": list(observations.values())}


def write_report(report, destination):
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    (root / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    lines = ["# Firewall audit report", "", f"Mode: {report['mode']}",
             f"Status: {report['status']}", f"Target: {report['host']}",
             "Read-only: yes. Firewall modifications: none.", ""]
    if report.get("failure"):
        lines.extend(["Failure: " + report["failure"], ""])
    for finding in report["findings"]:
        lines.extend([f"## {finding['severity']}: {finding['title']}", "", "ID: " + finding['id'],
                      "", finding['impact'], "", "Recommendation: " + finding['recommendation'],
                      "", "Evidence:"])
        lines.extend(f"- {e['observation_id']} {e['pointer']}" for e in finding['evidence'])
        lines.extend(["", "Verification plan:"])
        lines.extend("- " + x for x in finding['verification_plan'])
        lines.append("")
    if not report["findings"]:
        lines.extend(["No supported candidate findings were produced. This is not proof of security.", ""])
    lines.extend(["## Coverage notes", ""])
    lines.extend("- " + note for note in report["coverage_notes"])
    (root / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
