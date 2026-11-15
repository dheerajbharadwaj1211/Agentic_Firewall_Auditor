> Latest status: **Phase 2 live acceptance PASSED** using Gemini 3.1 Flash-Lite
> on API v1beta. See `phase2-acceptance.md`. Earlier failed/pending checks below
> are retained as history, not the current acceptance status.

# Phase 2 validation status

Phase 2 code extends the accepted Phase 1 implementation in place.

## Local verification

The isolated project .venv installation completed successfully. `pip check`
reported no broken requirements. The suite also passed inside this isolated
environment (60 passed, 2 skipped, 33 subtests), not just the temporary library
directory. Tested package versions are recorded in requirements-dev.lock.txt.

## Checks

- pytest: 60 passed, 2 skipped, 33 subtests passed; zero failures.
- The two skipped cases are the separately gated real-VM inspection test and
  real Gemini+VM agent test. The prior Phase 1 real-VM result remains accepted;
  it is not represented as a fresh Phase 2 live run.
- Original Phase 1 local tests remain passing.
- New tests cover six candidate categories, permissive/missing input hooks,
  legitimate public HTTPS, loopback exclusions, source-family differences,
  authorized client-range unions, missing evidence, malicious comments,
  forbidden tools, cross-host access, extra parameters, invented/suppressed
  findings, output limits, deadlines, token/tool budgets and provider failures.
- Gemini SDK tests use google-genai 3.3.0 with mocked HTTP. One test uses the
  full SDK request conversion and response parser; it validates actual function
  declarations and manual execution without any network request.
- Saved real VM snapshot analysis succeeded locally. It produced two
  configuration candidates: empty input chain defaults to accept, and broad
  SSH permission with a non-loopback listener. All evidence pointers resolve
  to saved source observations. This run used no LLM and no fresh SSH access.

XML: D:\codex\firewall\work\phase2-local-tests.xml.
Offline report: reports/phase2-saved-vm/report.json and report.md.

## Pending live acceptance

A Gemini key is not available to the Codex execution process. The user chose
Gemini and will enter their key privately using scripts/run_phase2.py in normal
Windows PowerShell. That process can also access their SSH authentication agent.
Live Gemini success must be verified from reports/phase2-live/report.json,
including complete status, all seven actual VM observations and evidence-backed
findings. No live Gemini request or live Phase 2 success is claimed yet.

No firewall rules have been changed. Phase 3 has not started. The actual VM
still has no explicit rules in the accepted snapshot; real nonempty rule-expression
validation needs an operator-approved isolated lab scenario. This gap is not
hidden by synthetic test success. See phase2.md for scope and security boundaries.


## First live attempt and compatibility correction

The user's real Gemini attempt returned 404 with no tool events or observations.
This is a failed live acceptance run, not a firewall failure. The SDK was observed
to default to v1. The adapter/listing now pin v1beta by default and support an
explicit v1 override. Added tests verify API-version selection, invalid versions,
and identical request paths for prefixed and short model IDs. Safe report metadata
includes model/API version. The launcher has a no-VM --check-model probe.
Latest isolated tests: 60 passed, 2 gated live tests skipped, 33 subtests passed.
A successful live generation probe and full audit are still pending; no key was
provided to the Codex process and no successful real LLM audit is claimed.
