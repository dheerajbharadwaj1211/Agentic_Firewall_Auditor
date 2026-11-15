> **Phase 4 desktop console is available; native live acceptance is pending.**
> Run `.venv\Scripts\python.exe scripts\run_desktop.py` in native PowerShell.
> See [Phase 4 guide and demo](docs/phase4.md). No firewall changes were made for Phase 4.

> **Phase 3 passed scoped live acceptance.** See [acceptance evidence](docs/phase3-acceptance.md).
> The current verified lab rule permits APP02 and blocks ATTACKER on IPv4 TCP 3306;
> management SSH remains available, and independent watchdog restoration was demonstrated.
> Earlier implementation-status notes below are historical.

> Phase 3 implementation is now available. See [Phase 3 guide](docs/phase3.md)
> for exact approval, root helper, verification, rollback and live acceptance.
> No real Phase 3 firewall modification or helper deployment has been performed.

# Secure Agentic Firewall Auditor

**Phase 2 passed live Gemini + VM acceptance; see [acceptance report](docs/phase2-acceptance.md).
Phase 2 is implemented with Gemini. See [Phase 2 guide](docs/phase2.md)
for secure launch, configuration, evidence reports and acceptance status.**
The Phase 1 description below is retained as history; read-only inspection tools
remain in use. No firewall modification capability has been added.


Phase 1 foundation of a one-month graduate security project. The foundation reads an explicitly
configured Linux test VM over SSH and normalizes nftables JSON. Phase 2 now adds Gemini-driven inspection and evidence-grounded findings.
GUI, firewall modification, connectivity verification, rollback and persistent
audit storage remain later-phase work. No security finding or effective Internet
exposure is asserted by this version.

In simple terms, the final application is an AI firewall inspector. It collects
evidence, recommends a fix, asks a human to approve it, then checks that the fix
blocks unwanted traffic while preserving required traffic.

## Run locally

Python 3.11+ and OpenSSH client are required. Runtime Python dependencies: none.
From this project folder in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m firewall_auditor.cli normalize lab/synthetic_ruleset.json
```

Without installation, use `PYTHONPATH=src` (PowerShell syntax below):

```powershell
$env:PYTHONPATH = (Resolve-Path src).Path
python -m unittest discover -s tests -v
python -m firewall_auditor.cli normalize lab/synthetic_ruleset.json
```

`normalize` is explicitly marked `offline_fixture`; it never contacts a host.
Both pytest and unittest can run the tests. The VM integration test is skipped
unless explicitly enabled. See [lab guide](docs/lab.md) before configuring a VM.

```powershell
python -m firewall_auditor.cli inspect --hosts config/hosts.local.json --host db01
```

`inspect` executes real read-only operations. Errors stop the snapshot rather than
being reported as empty/safe observations. Output is JSON and may include private
network details. Save it only to a protected local directory. JSON escapes terminal
control characters; future GUI/LLM code must still treat all observations as data.

## Structure

```text
docs/project_requirements.pdf   supplied authoritative 30-page specification
docs/plan.md                    architecture, MVP, milestones, open decisions
docs/lab.md                     isolated VM setup and live test procedure
docs/validation.md              results and limitations of this implementation
src/firewall_auditor/
  models.py                    normalized chain/rule/ruleset models
  nftables.py                  conservative JSON adapter
  transport.py                 validated hosts and fixed OpenSSH operations
  tools.py                     allowlisted inspection dispatch
  cli.py                       temporary read-only console
tests/                         synthetic, mocked transport and opt-in VM tests
config/hosts.example.json       placeholder configuration, no secrets
lab/                           synthetic JSON and manually applied lab rules
```

Phase 1 was reviewed and accepted against the real VM; see docs/phase1-acceptance.md. Future
packages (`security`, `remediation`, `audit`, `ui`) will be added
when implemented; there are no placeholder production claims.

## Ubuntu VirtualBox target

See [VM authentication and read-only sudo setup](docs/ubuntu-virtualbox-setup.md).
The configured local target is `viper@127.0.0.1:2222` (`ubuntu-vm`).
An encrypted key can use the local SSH agent through explicit `use_agent: true`.
Agent forwarding stays disabled. `ss -lntup` output is now normalized and retained.

## Local HTTPS interface

The Phase 2 web interface wraps the existing read-only agent. Start with `scripts/run_web.py --init-cert`, establish local certificate trust explicitly, then run `scripts/run_web.py` in native Windows PowerShell. See [the HTTPS operation guide](docs/web-interface.md) and [observed validation](docs/web-validation.md). Default test URL: `https://127.0.0.1:8443/`. No Phase 3 mutation or approval routes are exposed.
