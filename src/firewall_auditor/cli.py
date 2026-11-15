"""Read-only VM inspection, offline analysis and Gemini agent investigations."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
from .nftables import parse_ruleset
from .context import load_context
from .agent import AgentController, AgentError
from .reports import analyze_snapshot, write_report
from .phase3_ledger import Ledger, AuditFailure
from .tools import Inspector
from .transport import load_hosts, InspectionError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    normalize = commands.add_parser("normalize", help="Normalize offline JSON; never contacts a VM")
    normalize.add_argument("file")
    inspect = commands.add_parser("inspect", help="Read an explicitly configured test VM")
    inspect.add_argument("--hosts", required=True)
    inspect.add_argument("--host", required=True)
    for name, help_text in (("audit", "Run a live read-only Gemini investigation"),
                            ("analyze-snapshot", "Offline deterministic analysis; no SSH or LLM")):
        sub = commands.add_parser(name, help=help_text)
        sub.add_argument("--host", required=True)
        sub.add_argument("--context")
        sub.add_argument("--out", required=True)
        if name == "audit":
            sub.add_argument("--hosts", required=True)
            sub.add_argument("--model")
            sub.add_argument("--goal", default="Audit the firewall configuration of this machine.")
        else:
            sub.add_argument("--snapshot", required=True)
    args = parser.parse_args()
    try:
        if args.command == "normalize":
            result = {"mode": "offline_fixture", "untrusted_observation": True,
                      "data": asdict(parse_ruleset(Path(args.file).read_text(encoding="utf-8")))}
        elif args.command == "inspect":
            result = Inspector(load_hosts(args.hosts)).snapshot(args.host)
        elif args.command == "analyze-snapshot":
            result = analyze_snapshot(args.snapshot, args.host, load_context(args.context, args.host))
            write_report(result, args.out)
        else:
            from .gemini import GeminiProvider
            hosts = load_hosts(args.hosts)
            if args.host not in hosts:
                raise ValueError("Unconfigured target")
            provider = GeminiProvider(args.model)
            try:
                result = AgentController(Inspector(hosts), provider, args.host,
                                         load_context(args.context, args.host),
                                         audit=Ledger(Path(args.out)/"audit.sqlite3")).run(args.goal)
            finally:
                provider.close()
            write_report(result, args.out)
            print(json.dumps({"status": result["status"], "findings": len(result["findings"]),
                              "report_directory": str(Path(args.out).resolve()), "failure": result.get("failure")}, indent=2))
            return 0 if result["status"] == "complete" else 1
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, TypeError, KeyError, ImportError, OSError, InspectionError, AgentError, AuditFailure) as exc:
        print(f"Inspection failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
