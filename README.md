# Secure Agentic Firewall Auditor

A Python application that inspects real Linux nftables firewalls, gathers host and network evidence, and uses Gemini to investigate potential misconfigurations through controlled tools.

Includes a local HTTPS interface, a PySide6 desktop console, and a separate command-line workflow for approved firewall changes with verification and rollback protection.

## Features

- Inspect firewall rules, listening services, interfaces, IPv4/IPv6 routes and host information over SSH.
- Use structured Gemini function calls with validated tools, arguments and target hosts.
- Produce evidence-backed findings, recommendations and coverage notes.
- Run read-only audits through the web interface or desktop console.
- Apply narrowly scoped source restrictions with explicit human approval.
- Verify legitimate access, unauthorized-client blocking and management connectivity.
- Maintain audit records and target-local rollback protection.

## Requirements

- Python 3.11+
- OpenSSH client
- Linux test VM with nftables and SSH access
- Gemini API key and a function-calling model
- Native Windows PowerShell for the supplied launchers and SSH-agent setup

The tested model is `models/gemini-3.1-flash-lite`, using API version `v1beta`.

## Installation

From the repository directory:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,web,desktop]"
```

## Configuration

If local configurations do not already exist, copy the examples:

```powershell
Copy-Item config/hosts.example.json config/hosts.local.json
Copy-Item config/context.example.json config/context.local.json
```

Update the SSH address, port, username, dedicated identity path and verified known-hosts path. Configure the host role and service dependencies in the context file.

The supplied native launchers use the target alias `ubuntu-vm`; use that alias in both local configurations.

For an encrypted identity loaded into the Windows SSH agent, set `use_agent` to `true` in the host profile. Preserve strict host-key checking. Grant only narrowly scoped read-only sudo permission for nftables inspection.


## Usage

### Desktop console

Load the dedicated SSH key and start the console:

```powershell
ssh-add "$env:USERPROFILE\.ssh\id_ed25519_firewall"
.\.venv\Scripts\python.exe scripts/run_desktop.py
```

Enter the Gemini API key at the hidden prompt, select the configured target and click **Run live audit**. Network work runs in a background worker.

### Local HTTPS interface

Generate certificates once:

```powershell
.\.venv\Scripts\python.exe scripts/run_web.py --init-cert
```

Follow the [HTTPS guide](docs/web-interface.md) to inspect the generated CA and establish local browser trust. Do not bypass certificate warnings or overwrite existing certificates unnecessarily.

Start the server:

```powershell
.\.venv\Scripts\python.exe scripts/run_web.py
```

Enter a local access password and Gemini API key at the hidden prompts. Open **https://127.0.0.1:8443/**, sign in and submit an investigation request. Keep the terminal running.

The server listens only on loopback; the URL is accessible from the same computer, not other class machines.

### Command-line inspection

```powershell
.\.venv\Scripts\python.exe -m firewall_auditor.cli inspect --hosts config/hosts.local.json --host ubuntu-vm
```

Offline normalization without contacting a VM:

```powershell
.\.venv\Scripts\python.exe -m firewall_auditor.cli normalize lab/synthetic_ruleset.json
```

### Approved remediation

Firewall changes use the separate CLI, not the read-only web or desktop audit interfaces:

```powershell
.\.venv\Scripts\python.exe scripts/run_phase3.py --help
```


## Testing

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The latest recorded local run completed with **111 passed tests, 57 passed subtests and 4 skipped live tests**. Gated live tests require explicit configuration and are separate from local fixture-based tests.

Real desktop and web audits completed against the Ubuntu lab VM. A scoped IPv4 TCP/3306 restriction and independent watchdog restoration were also demonstrated.


## Project Structure

```text
src/firewall_auditor/   Agent, adapters, policy, reporting and interfaces
scripts/               Launchers and lab validation utilities
config/                Example configuration and ignored local settings
lab/                   Synthetic fixtures and controlled lab scenarios
tests/                 Unit, integration and opt-in live tests
docs/                  Setup, architecture, validation and operation guides
```

## Security

The LLM has no arbitrary shell or root execution tool. Deterministic code validates requests before fixed commands execute. Remote observations are treated as untrusted data.

The web interface uses authentication, secure session cookies, CSRF and origin checks, request limits and bounded jobs. Remediation requires exact, expiring, one-use approval and independent privileged-helper policy checks.

Never commit API keys, passwords, SSH/TLS private keys or sensitive reports. Enter credentials locally and keep them out of investigation goals.

Local settings, TLS material, generated reports, snapshots and audit databases are excluded from version control.

## Limitations

- Linux/nftables is the supported MVP; other firewall products and Windows Defender Firewall are not implemented.
- Some nftables expressions and interactions between chains are not fully analyzed. Findings are configuration-risk candidates, not proof of effective reachability or Internet exposure.
- Agent sequencing can require an explicit request; incomplete evidence produces an incomplete audit.
- Live remediation validation covers a limited IPv4 TCP/3306 lab scenario with a TCP test service, not a MySQL deployment.
- Remediation approval is a CLI workflow rather than a desktop approval dialog.
- Browser certificate trust remains unresolved in the current operator setup. A certificate warning must be resolved before claiming trusted HTTPS.
- Shared Cyber Range deployment and class access are not yet complete. The HTTPS server is designed for one local operator.
