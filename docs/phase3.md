> Latest status: **Phase 3 live acceptance PASSED**. See `phase3-acceptance.md`.
> Earlier pending/proposed checks below are retained as implementation history.

# Phase 3: approved remediation, verification, rollback and audit

Status: implemented and locally tested; REAL VM mutation acceptance is pending.
No real firewall changes or privileged helper installation were performed by Codex.

## The implemented workflow

1. Build an inert proposal draft from a saved ruleset, one target handle, a narrower
   source and an explicitly configured verification topology.
2. In a normal Windows terminal, refresh the target's actual rules and inspect the
   installed root helper's independent policy. Confirm the chain/source/port are
   permitted BEFORE probes. The helper is disabled on a fresh installation.
3. Confirm management SSH works and both legitimate and unauthorized source VMs can
   connect BEFORE a change. Baselines identify the actual route-selected source IP.
4. The helper independently checks the proposal, runs nft's syntax check, and
   saves a backup/capability. Preparation does not arm a timer or change a rule.
5. Display the full refreshed before/after rule, source restriction, verification
   plan, baseline results, expiry and proposal SHA-256 to the operator.
6. The operator must type `APPROVE <exact hash>` in an interactive terminal.
   Every other response rejects. There is no --yes, --approve or API approval flag.
   The SQLite ledger binds approval to the full proposal, actor and expiry, and
   permits one consumption only. A model-provided boolean is not approval.
7. Recheck the snapshot fingerprint. The root helper revalidates its own allowlist
   and the current snapshot again. Persist the backup, arm a target-local 120-second
   systemd rollback timer, verify the timer is active, THEN issue one nft JSON
   replacement transaction. Boot recovery must be enabled before apply can proceed.
8. Check the exact post-change fingerprint, SSH management and new TCP connections
   from both source types. Allowed traffic must connect; denied traffic must time
   out or be refused while allowed-source controls remain healthy. Wrong source,
   missing result, unreachable/inconclusive route or failed SSH cannot pass.
9. Persist successful verification and confirm with the helper before the lease
   expires. Wall time, monotonic time and boot identity constrain confirmation.
   Only confirmation stops the watchdog. No LLM participates in commit decisions.
10. On any failure, uncertain apply reply, interruption or post-change audit failure,
    attempt immediate exact-rule rollback. A client/SSH crash leaves the independent
    timer to recover. Boot recovery retries unconfirmed durable state after reboot.
    Do not claim rollback worked unless the original rule was read back successfully.

## Supported safe subset

Only source restriction of an existing, single-port inbound TCP ACCEPT rule in an
explicit IPv4 `ip` or IPv6 `ip6`, default-DROP filter INPUT base chain is supported.
The new CIDR must be strictly narrower. Supported expressions are a source equality
(optional), explicit tcp dport equality, optional TCP l4proto and one counter.
Comments remain data and are preserved. Packet/byte counts and export metadata are
excluded from freshness fingerprints; rule order, handles, policies, expressions
and comments are retained. Changing traffic counters alone does not stale approval.

SSH port 22 and RDP port 3389 cannot be modified. The helper cannot disable the
firewall, change a chain policy, flush a table/ruleset, remove/add arbitrary rules,
open ports, run shell commands, edit permissions, change its policy or delete logs.
inet-family/compound rules, sets/maps, jumps, NAT, other selectors and ambiguous
rules must be reviewed manually or implemented/tested as a later extension.

A source restriction in an ACCEPT-policy chain may have no effect, so it is
refused. Your accepted VM snapshot has empty ACCEPT-policy chains: it has no
supported existing rule to remediate. Do not automatically change those policies.
A separate, explicitly approved isolated lab scenario is needed for live Phase 3.
An IPv4 remediation is not a claim about IPv6 protection. Existing connections
accepted by conntrack rules are not terminated; verification tests new connections.

## Components

- phase3_policy.py: shared pure deterministic policy, proposals, semantic hashes,
  exact diff construction and verification-result validation.
- phase3_ledger.py: SQLite audit hash chain, UPDATE/DELETE guard triggers, exact,
  expiring one-use approval tickets. Connections close deterministically on Windows.
- remediation.py: local operator workflow and fail-safe state machine.
- phase3_transport.py: fixed SSH helper command and a fixed Python TCP probe.
  No caller-supplied command/program is accepted by the workflow. IPs/ports and
  configured source VMs bound the probes. Input/output sizes and time are bounded.
- phase3_helper.py: root-owned Linux implementation, protected backups, independent
  policy, systemd watchdog, recovery and separate root-owned audit log.
- phase3_cli.py / scripts/run_phase3.py: plan/status/apply/audit-verify console.
- Existing Gemini controller: still read-only; future investigations now persist
  tool decisions and observation hashes to the local ledger when using launchers.

## Trust and approval boundary

The Gemini model, remote comments, metadata, arbitrary JSON requests and proposal
files are not authorization. Privileged requests are never advertised to Gemini.
An authenticated operator uses the deterministic console and recorded approval;
root independently validates scope, state, digest and an unpredictable change
capability. The helper trusts the authenticated operator account/client to report
its human decision and probe results; it does not provide hardware attestation
of a human click. Local OS/code/operator accounts and the root administrator are
trusted. Giving an attacker unrestricted Python or shell access as that operator
is outside this boundary. Do not expose helper JSON as a generic LLM tool.

Root policy/code/state must be root-owned and not writable by the operator.
The installed wrapper checks its bundle before importing it, and Python -I ignores
user import paths. The sudo rule allows exactly the no-argument helper, not Python,
nft *, systemd-run *, a shell, or arbitrary helper arguments.

SQLite triggers and hashes protect normal application history and detect partial
corruption, not a privileged administrator rewriting/truncating a whole database.
Root-side logs provide a separate protected record. Root backup files and local
reports contain network data and must stay access-controlled. Credentials are not
logged; approval tickets and helper capabilities stay in memory, not report files.

Only one pending applied change is allowed. All helper operations serialize with a
file lock. The lab requires exclusive firewall ownership: UFW/firewalld/Docker or
another administrator must not concurrently manage the affected firewall. External
processes do not honor this helper's lock. Unexpected target changes cause a
rollback conflict and manual review rather than overwriting another owner's rule.
Unrelated changes are preserved during rollback. Reboots may recreate different
handles/configuration; recovery then refuses ambiguous targets and requires the
VM console. This is safer than blindly flushing and restoring the whole ruleset.
No runtime changes are written to nftables.conf; permanent configuration management
is outside this initial subset.

## Prepare deployment (no firewall change)

A small bundle is generated at `deploy/phase3-helper-bundle.zip`. Review its files
before installation. Copy only this bundle to the explicitly designated test VM,
not private keys or the Windows virtual environment:

```powershell
scp -P 2222 "D:\codex\firewall\firewall-auditor\deploy\phase3-helper-bundle.zip" viper@127.0.0.1:~/phase3-helper-bundle.zip
```

Inside the Ubuntu VM, from its console or normal SSH session:

```sh
python3 -m zipfile -e ~/phase3-helper-bundle.zip ~/phase3-helper-bundle
cd ~/phase3-helper-bundle
sh -n deploy/phase3/install-helper.sh
# Review the installer and Python modules BEFORE executing this administrative step.
sudo sh deploy/phase3/install-helper.sh --ack-test-vm viper
```

The installer copies a root-owned minimal Python bundle and fixed entry point,
creates a private state directory, installs the exact sudoers rule, and enables
boot recovery. It preserves an existing policy and refuses upgrades with an
unconfirmed change. New installations have enabled=false and exclusive ownership
false. This step grants a scoped privileged capability and must be reviewed by
the operator. It does not apply lab fixtures or change nftables rules.

The generated sudo line is deliberately:

```sudoers
viper ALL=(root) NOPASSWD: /usr/local/libexec/firewall-auditor-helper ""
```

The empty argument string disallows all command-line arguments. Without it,
sudoers permits arbitrary arguments to that path. The existing exact read-only
nft sudo rule can remain. Never grant unrestricted sudo/nft/Python access.

Helper paths:

- /usr/local/libexec/firewall-auditor-helper: fixed executable wrapper.
- /usr/local/lib/firewall-auditor/firewall_auditor/: trusted Python bundle.
- /etc/firewall-auditor/policy.json: root-owned allowlist, disabled initially.
- /var/lib/firewall-auditor/: private backups, state files and audit.jsonl.
- firewall-auditor-recover.service: recover unconfirmed state on boot.
- fwa-rollback-<change_id>.timer/.service: per-change transient watchdog.

Read status without changing rules:

```powershell
Set-Location 'D:\codex\firewall\firewall-auditor'
.\.venv\Scripts\python.exe scripts/run_phase3.py status --hosts config/hosts.local.json --host ubuntu-vm
```

The installer and Linux nft/systemd integration have NOT been executed here.
A Git Bash syntax-only attempt was blocked by the Windows sandbox's MSYS named
object permission restriction, so shell validation must run with sh -n on Ubuntu.
Python syntax, policy and fake backend behavior were tested locally.

## Isolated live lab requirements

Use VM snapshots and console access. Do not use a bridged/public network for the
intentionally broad database scenario. A concrete example uses a VirtualBox
host-only data network plus the existing NAT adapter for Windows SSH:

| System | Host-only IP | Purpose |
| --- | --- | --- |
| Target Ubuntu VM | 192.168.56.30 | TCP 3306 listener and scoped firewall rule |
| APP01 source VM | 192.168.56.10 | Legitimate client that must remain connected |
| Attacker source VM | 192.168.56.20 | Unauthorized client that must become blocked |

These are examples, not IPs observed on your current VM. Configure and verify them
before enabling root policy. Both sources need their own key-authenticated SSH
login and /usr/bin/python3. Install only public keys and verify host fingerprints.
Do not pretend two Windows NAT port numbers are independent target-visible clients.
The verification plan explicitly requires no source NAT on these data paths.

Merge the actual source profiles into config/hosts.local.json using
lab/phase3/hosts.example.json as a template. Keep actual credentials outside source.
Configure the actual data endpoints using lab/phase3/verification.example.json.
The local target alias and root policy host_alias must agree. No targets are
silently invented or added to your existing configuration by this implementation.

After approving the isolated scenario, the operator may review/syntax-check and
manually apply lab/phase3/isolated-database.nft on a disposable target. It creates
a new IPv4 default-DROP input chain, explicitly preserves SSH, and intentionally
allows TCP 3306 broadly. This IS a firewall change and is NOT automatically
executed by setup, plan, audit, tests or Codex. Check the exact interface/service
requirements and snapshot before doing it. It is not a generic safe production
configuration. Other base chains can still influence traffic.

A simple `python3 -m http.server 3306 --bind 0.0.0.0` can simulate the TCP endpoint;
it is HTTP, not an actual MySQL server. Both source VMs must reach it initially.
Use a real database if demonstrating process-specific MySQL evidence.

Root administrator must then set policy.json to the actual host_alias, target IP,
exact allowed chain and allowed source CIDR/port combination, enabled=true and
exclusive_firewall_owner=true. Do not edit policy, helper code or rules during
an active lease. Capture fresh JSON and actual rule handles; do not reuse the
synthetic handle 7 without checking the real VM.

## Inert draft example (safe to run locally)

```powershell
.\.venv\Scripts\python.exe scripts/run_phase3.py plan --snapshot lab/phase3/synthetic_ruleset.json --host ubuntu-vm --family ip --table fwa_lab --chain input --handle 7 --source 192.168.56.10/32 --verification lab/phase3/verification.example.json --out plans/phase3-synthetic-draft.json
```

This is synthetic evidence; it runs no SSH, probes, sudo or nft commands. A draft
has no verified baseline and cannot serve as a completed human approval. For a
real draft, substitute a fresh snapshot and the real target handle/topology.

After live lab setup and review:

```powershell
.\.venv\Scripts\python.exe scripts/run_phase3.py apply --hosts config/hosts.local.json --proposal plans/YOUR-REVIEWED-DRAFT.json
```

The command refreshes the draft into a NEW exact proposal, runs baseline probes,
prepares the helper, prints the full diff and asks for the exact approval phrase.
Rejecting does not request a firewall change. Approved changes are applied only
within root policy and automatically verified. Results are written to
reports/phase3-last-result.json; local events to audit/audit.sqlite3.
No --approve flag or Gemini API key is required for this operator workflow.

Verify the audit chain:

```powershell
.\.venv\Scripts\python.exe scripts/run_phase3.py audit-verify
```

On an uncertain outcome, inspect the VM console and root state/logs. A missing SSH
reply is not proof of failure or success. Timer recovery continues independently.
After root-console review, `sudo /usr/local/libexec/firewall-auditor-helper --recover`
can recover pending changes; it requires normal root privileges, since the operator
NOPASSWD helper rule intentionally permits no arguments. Conflicts require manual
comparison with the saved before-rule; never blindly flush the current ruleset.

## Acceptance still required

1. Run existing tests and helper status on the configured Ubuntu test VM.
2. Approve one exact live source restriction and show unauthorized new TCP blocked,
   legitimate client connected, SSH preserved and exact post-change state.
3. Demonstrate a failed legitimate check or client loss restores the actual rule.
   Unit/fake watchdog tests alone are not a real systemd watchdog demonstration.
4. Verify local/root audit records and preserve the real receipt and configuration.

Read-only live pytest checks can validate installed helper and a previously
approved receipt; they NEVER issue a mutation or manufacture approval:

```powershell
$env:FWA_RUN_PHASE3_LIVE_TESTS='1'
$env:FWA_PHASE3_HOSTS_FILE="$PWD\config\hosts.local.json"
$env:FWA_HOST='ubuntu-vm'
$env:FWA_PHASE3_AUDIT_DB="$PWD\audit\audit.sqlite3"
$env:FWA_PHASE3_RECEIPT="$PWD\reports\phase3-last-result.json"
.\.venv\Scripts\python.exe -m pytest -q tests/test_phase3_live.py
Remove-Item Env:FWA_RUN_PHASE3_LIVE_TESTS
```

## Upstream references

- nftables JSON/check/replace command semantics: https://netfilter.org/projects/nftables/manpage.html
- Target-local timers: https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html
- Exact sudo command argument matching: https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in
