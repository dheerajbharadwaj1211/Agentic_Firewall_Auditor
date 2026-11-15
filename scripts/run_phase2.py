"""Native Windows launcher: unlock credentials locally, then run read-only Gemini audit."""
import argparse
import getpass
import json
import os
from pathlib import Path
import sys
import warnings

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model',help='Gemini model ID with function calling, available to your account')
    diagnostic=parser.add_mutually_exclusive_group()
    diagnostic.add_argument('--list-models',action='store_true',help='List model IDs, then exit without sending VM data')
    diagnostic.add_argument('--check-model',action='store_true',help='One small Gemini function-call request; no VM access/data')
    parser.add_argument('--api-version',choices=['v1','v1beta'],help='Explicit Gemini API version; defaults to v1beta')
    args=parser.parse_args()
    from firewall_auditor.agent import ProviderFailure
    original=os.environ.get('GEMINI_API_KEY')
    api_version=args.api_version or os.environ.get('GEMINI_API_VERSION','v1beta')
    if api_version not in {'v1','v1beta'}:
        print('API version must be v1 or v1beta.');return 1
    try:
        if not original:
            if not sys.stdin.isatty():
                print('Set GEMINI_API_KEY locally or run in an interactive terminal. Never paste a key into chat.')
                return 1
            with warnings.catch_warnings():
                warnings.simplefilter('error', getpass.GetPassWarning)
                os.environ['GEMINI_API_KEY']=getpass.getpass('Gemini API key (hidden; held in memory for this run only): ').strip()
        if not os.environ.get('GEMINI_API_KEY'):
            print('No key supplied. No API request made.');return 1
        if args.list_models:
            from google import genai
            from google.genai import types
            with genai.Client(vertexai=False,api_key=os.environ['GEMINI_API_KEY'],http_options=types.HttpOptions(api_version=api_version,timeout=15000)) as client:
                for model in client.models.list():
                    print(model.name, "supported actions:", ", ".join(model.supported_actions or []))
            return 0
        model=args.model or os.environ.get('GEMINI_MODEL')
        if not model:
            if not sys.stdin.isatty():
                print('Set GEMINI_MODEL or pass --model.');return 1
            model=input('Gemini model ID (choose one supported by your account): ').strip()
        from firewall_auditor.agent import AgentController
        from firewall_auditor.phase3_ledger import Ledger
        from firewall_auditor.context import load_context
        from firewall_auditor.gemini import GeminiProvider
        from firewall_auditor.reports import write_report
        from firewall_auditor.tools import Inspector
        from firewall_auditor.transport import load_hosts
        provider=GeminiProvider(model,api_version=api_version)
        try:
            if args.check_model:
                from firewall_auditor.agent import AgentError
                probe={"name":"audit_probe","description":"Return a harmless probe value. No execution occurs.",
                       "parameters_json_schema":{"type":"object","properties":{"value":{"type":"string","enum":["ok"]}},
                                                 "required":["value"],"additionalProperties":False}}
                provider.start("Call audit_probe exactly once with value ok. No other actions are available.",
                               "Verify function calling with the harmless probe.",[probe])
                turn=provider.next([],30,1024)
                passed=bool(turn.calls) and all(c.name=="audit_probe" and c.arguments=={"value":"ok"} for c in turn.calls)
                print(json.dumps({"model":provider.model,"api_version":provider.api_version,
                                  "function_call_probe_passed":passed,"output_tokens":turn.output_tokens,
                                  "vm_accessed":False},indent=2))
                return 0 if passed else 1
            report=AgentController(Inspector(load_hosts(str(ROOT/'config/hosts.local.json'))),provider,
                'ubuntu-vm',load_context(str(ROOT/'config/context.local.json'),'ubuntu-vm'),
                audit=Ledger(ROOT/'audit/audit.sqlite3')).run()
        finally:
            provider.close()
        destination=ROOT/'reports'/'phase2-live'
        write_report(report,destination)
        print(json.dumps({'status':report['status'],'findings':len(report['findings']),
                          'failure':report.get('failure'),'model':provider.model,'api_version':provider.api_version,'saved_to':str(destination)},indent=2))
        print('No firewall rules were changed.')
        return 0 if report['status']=='complete' else 1
    except ProviderFailure as exc:
        print(str(exc));return 1
    except Exception as exc:
        # Never print raw SDK exceptions: URLs/headers may contain the API key.
        print('Setup or API operation failed ('+type(exc).__name__+'). Check SSH-agent access, model availability, API key and quota.')
        return 1
    finally:
        if original is None:
            os.environ.pop('GEMINI_API_KEY',None)
        else:
            os.environ['GEMINI_API_KEY']=original


if __name__=='__main__':
    raise SystemExit(main())
