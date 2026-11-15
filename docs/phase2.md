> Latest status: **Phase 2 live acceptance PASSED** using Gemini 3.1 Flash-Lite
> on API v1beta. See `phase2-acceptance.md`. Earlier failed/pending checks below
> are retained as history, not the current acceptance status.

# Phase 2: read-only Gemini agent

Phase 1 was accepted against the real Ubuntu VM before Phase 2 began. This extends
the existing transport, parser and tools; it does not replace the project.

## What is implemented

- A Python controller receives a high-level audit goal. Gemini chooses the order
  and batches of narrow inspection calls. All seven baseline observations and
  operator context must be collected before findings can be finalized.
- The official `google-genai` SDK uses manual function calling through the
  GenerateContent API. Automatic SDK execution is explicitly disabled. No Python
  shell function, raw SSH command or mutation capability is exposed to the model.
- Every call is independently checked for exact tool name, host, argument keys,
  audit state and remaining budgets. Wrong hosts and extra command parameters
  are rejected even if Gemini requests them. Repeated observations use a cache
  within one audit; a new audit starts with fresh observations.
- Deterministic candidate checks cover broad SSH, database and management-port
  permissions; unrestricted inbound accept rules; overly broad sources relative
  to operator-declared clients; and user/database segmentation overlap. Additional
  checks flag missing input hooks and empty accept-policy input chains.
- Findings include severity, affected rule handles, stable IDs, observation IDs
  and JSON pointers, impact, recommendations and a verification plan. Gemini
  cannot invent or suppress IDs at completion. The factual core is computed from
  evidence, rather than accepting arbitrary model-written vulnerability claims.
- Public HTTPS on an operator-declared web service is a negative test case. A
  TCP 3306 listener is described as a database-port listener, not proof that its
  process is MySQL. Loopback-only listeners are excluded from exposure checks.
- Observations and tool results are untrusted. Raw firewall comments, full exports
  and process metadata are omitted from Gemini input. Structured fields such as
  rules, addresses and route data are still sent to Gemini for this audit. Exact
  known API-key environment values are redacted. No SSH configuration/key material
  is provided to the model. Do not place unrelated secrets in VM metadata.
- Complete SDK model content/signatures are retained in memory for continuation,
  never persisted as private reasoning. Saved reports contain observable tool
  events, evidence and findings. Phase 3's append-only audit storage is still future.

## Boundaries

This is a read-only investigation. No firewall changes, automatic remediation,
connectivity probes, approvals or rollback are implemented in Phase 2. Existing
nft read-only sudo permissions are sufficient. The GUI remains Phase 4 scope.

Supported rules provide candidate paths, not complete nftables packet-flow
simulation. Earlier drops, other base chains, named sets, jumps, NAT and external
firewalls may alter reachability. Unsupported expressions remain incomplete and
cannot be treated as proven allow paths. Only empty accept-policy input chains
are used to infer a default-policy candidate path; more complex chains require
explicit supported rules. Source and destination semantics remain conservative.

An API key, model access/quota and access to the local SSH agent are external
prerequisites. Run the project in normal Windows PowerShell, where Phase 1 already
worked. Do not weaken host-key checks, key passphrases, agent permissions or sudo
rules to make the Codex sandbox access the user's authentication agent.

The real VM has zero explicit rules. We do not alter its firewall to manufacture
an acceptance case. Rule-expression scenarios are synthetic until the operator
configures and approves an isolated real-rule lab case. Offline and mocked tests
are always labelled as such. No claim of zero limitations is made.

## Install and run

The project has a dedicated `.venv`. Tested dependency versions are recorded in
`requirements-dev.lock.txt` (Windows/Python 3.13); `pyproject.toml` remains the
portable dependency definition. From normal Windows PowerShell:

```powershell
Set-Location 'D:\codex\firewall\firewall-auditor'
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/run_phase2.py
```

The launcher prompts for your Gemini key with hidden input if GEMINI_API_KEY is
not already set. It keeps the key in memory only for the run and clears it
when finished. It also asks for a Gemini model ID if GEMINI_MODEL is not set.
Choose a model with function calling that your Google account can use. To list
model IDs first, without sending VM data:

```powershell
.\.venv\Scripts\python.exe scripts/run_phase2.py --list-models
```

Use your chosen model explicitly if desired:

```powershell
.\.venv\Scripts\python.exe scripts/run_phase2.py --model YOUR_MODEL_ID
```

API calls may incur provider charges and transmit the minimized VM observations
to Gemini. The launcher never asks you to paste a key into chat or a source file.
Do not capture the key in terminal commands/history. There are no .env files.
Provider model IDs change, so this project requires an explicit model instead of
hard-coding a potentially retired model name.

If recreating the environment on another Windows installation:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev,gemini]'
```

The Codex sandbox's temporary path contains braces that confuse setuptools. A
local build from that sandbox uses D:\codex\firewall\work\tmp for TEMP/TMP.
This is an environment-specific build workaround, not a normal Windows requirement.

## Context and reports

Edit `config/context.local.json` locally to declare the VM role, boundary, public
services, allowed-client CIDRs keyed by service port and user subnets. The current
VM is truthfully configured as role unknown, boundary virtualbox_nat. Dependency
addresses are not guessed. Example database context is in context.example.json.
Unknown role is reported as a coverage note, not silently assumed to be database.

A live audit writes `reports/phase2-live/report.json` and `report.md`. Status
`complete` means all required observations and evidence-grounded completion
succeeded. It does not mean the host is secure. `incomplete` includes the failure
and available evidence; it is a failed acceptance run even if it has findings.
A new run replaces this named live report; copy evidence if retaining history.

Default budgets: 16 model turns, 24 tool requests, 180 seconds, 16,000 output
(including thinking) tokens, three denials, and 512,000 bytes per observation.
API requests use a 30-second timeout and one attempt. SSH calls keep Phase 1's
15-second timeout. A running bounded operation can finish after the overall
wall-clock deadline, but the controller must then return incomplete; the budget
is not a hard OS-level process-kill deadline. Input/billing usage depends on
collected evidence and model pricing; these limits are not a monetary cap.

## Explicit local/offline mode

```powershell
.\.venv\Scripts\python.exe -m firewall_auditor.cli analyze-snapshot --snapshot snapshots/ubuntu-vm-inspection.json --host ubuntu-vm --context config/context.local.json --out reports/phase2-saved-vm
```

This reparses original nft JSON and listener text. It does not use Gemini, access
SSH, or prove that the saved configuration is still current. The report mode is
`offline_analysis_of_saved_observations`, and llm_used is false.

## Optional live integration tests

Only enable these in normal PowerShell with SSH agent access and API credentials
available in that process. The Gemini test consumes API quota. Never enter a key
in a command line to enable it; use an appropriately protected process environment
or the secure launcher for the normal audit.

```powershell
$env:FWA_RUN_VM_TESTS = '1'
$env:FWA_HOSTS_FILE = "$PWD\config\hosts.local.json"
$env:FWA_HOST = 'ubuntu-vm'
$env:FWA_CONTEXT_FILE = "$PWD\config\context.local.json"
$env:FWA_RUN_GEMINI_TESTS = '1'
# GEMINI_API_KEY and GEMINI_MODEL must already be set securely in this process.
.\.venv\Scripts\python.exe -m pytest -q
Remove-Item Env:FWA_RUN_VM_TESTS
Remove-Item Env:FWA_RUN_GEMINI_TESTS
```

The Gemini integration test saves reports/phase2-live-integration. Its acceptance
requires complete status, all seven real observations, evidence references and no
firewall modifications. Synthetic controller tests use a scripted provider; SDK
contract tests use real SDK types with mocked network calls. Neither is a live
Gemini success. A secure launcher run producing a validated complete report is
also an end-to-end check, separate from the gated pytest live test.

## Official references

- Google Gen AI Python SDK: https://googleapis.github.io/python-genai/
- Gemini function calling: https://ai.google.dev/gemini-api/docs/function-calling
- Gemini API key setup: https://ai.google.dev/gemini-api/docs/api-key


## Model 404 troubleshooting update

The installed google-genai 3.3.0 SDK defaults to API v1 (changed in SDK 3.0).
The original app inherited that default. The adapter and model listing now
explicitly select v1beta unless --api-version or GEMINI_API_VERSION selects v1.
Both prefixed models/... and short model IDs serialize to the same SDK resource
path; the models/ prefix was not duplicated. Tests verify both formats.

A models.list entry is metadata, not proof that generateContent is enabled for
that model, API version and account. Some older-model access is restricted.
The observed first live attempt returned HTTP 404 before any inspection calls:
zero tool events and zero VM observations. API-version or account/model access
is suspected; the precise server-side reason is not proven by a generic 404.
The safe error now describes both possibilities rather than asserting that the
model does not exist. New reports record the model ID and API version.

Before repeating an audit, run a small function-calling request with no VM data:

```powershell
.\.venv\Scripts\python.exe scripts/run_phase2.py --model models/gemini-2.5-flash-lite --check-model --api-version v1beta
```

The prompt keeps the API key hidden and in memory. This performs one small API
request (may consume quota) and never invokes SSH or any firewall tool. If it
passes, rerun the normal audit with the same model/version. If it still returns
404, try the available gemini-3.1-flash-lite model with --check-model first.
No automatic model fallback is performed: it could silently change cost.
Official references: https://github.com/googleapis/python-genai/releases/tag/v3.0.0
and https://ai.google.dev/gemini-api/docs/deprecations .
