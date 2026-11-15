> Latest status: **Phase 1 PASSED**. See `phase1-acceptance.md` for verified
> real-VM evidence and test results. Earlier failed attempts below are retained
> as history and were resolved by running in the user's native terminal.

# Ubuntu VM inspection: current result

## Configuration and code changes

The existing Phase 1 codebase at D:\codex\firewall\firewall-auditor was inspected
and updated in place; it was not regenerated. Local configuration:

- Alias: ubuntu-vm
- Address: 127.0.0.1
- SSH port: 2222 (VirtualBox NAT forwarding)
- User: viper
- Test VM: explicitly enabled
- Identity path: C:/Users/Dheeraj/.ssh/id_ed25519_firewall
- Known hosts: C:/Users/Dheeraj/.ssh/known_hosts
- use_agent: true (explicit opt-in for an encrypted key held by Windows agent)

No password or private-key material is stored in the project. Host checking is
strict, agent forwarding is disabled and allowed remote commands remain fixed.
The existing Windows known_hosts entry was reused, not automatically enrolled.
The selected identity file has not yet been generated and the SSH agent is not
currently reachable. These are setup requirements, not completed authentication.

## Real checks actually executed

| Check | Result |
| --- | --- |
| TCP to 127.0.0.1:2222 and SSH banner | PASS: SSH-2.0-OpenSSH_10.5p1 Ubuntu-1ubuntu3.1 |
| Existing SSH host-key check | PASS during strict-checking SSH connection |
| Noninteractive SSH login as viper | FAIL: Permission denied (publickey,password) |
| Actual nftables ruleset retrieval | BLOCKED by authentication |
| Actual listening services retrieval | BLOCKED by authentication |
| Actual interfaces retrieval | BLOCKED by authentication |
| Actual IPv4/IPv6 routing retrieval | BLOCKED by authentication |
| Parsing/normalizing actual VM results | NOT RUN: no authenticated observations |
| Firewall rules changed | NONE |

The SSH banner is server-provided data; it does not independently verify the
complete Ubuntu OS release. The user's stated version is Ubuntu Server 26.10.
The TCP connection is successful, but authenticated SSH connectivity is not yet
successful. Do not interpret it as a completed real-VM inspection.

## Test results

1. `python -m pytest -q -rA`: 23 passed, 1 skipped; pytest also reported 22 passing
   subtests. The skipped case was the explicitly gated live-VM integration test.
   All 17 original local tests passed. Six added cases cover explicit agent mode,
   NAT host settings and service normalization.
2. Explicitly enabled `tests/test_vm_integration.py`: 1 FAILED. Failure occurred
   in Host.validate before any SSH command because the configured dedicated
   identity file does not exist. This is an authentication setup blocker.
3. No unit/normalization regression failed. No live firewall test passed.

Detailed XML records are at D:\codex\firewall\work\phase1-local-tests.xml and
D:\codex\firewall\work\phase1-vm-tests.xml. pytest 9.2.0 was downloaded into
D:\codex\firewall\work\python_libs without changing global Python packages.

## Required next steps

Follow ubuntu-virtualbox-setup.md to generate a passphrase-protected key outside
source, start the Windows SSH agent, load the key, and append only its public key
to viper's authorized_keys using an interactive password prompt on the user's PC.
Then configure the exact read-only sudo command:

    viper ALL=(root) NOPASSWD: /usr/sbin/nft -j list ruleset

Validate it with visudo and test `sudo -n /usr/sbin/nft -j list ruleset` on the VM.
Do not grant wildcard nft or unrestricted NOPASSWD access.

After setup, retry all seven read-only observations, save the real snapshot,
compare parsed models with the source JSON and rerun the explicit VM test.
Public/unauthorized reachability cannot be inferred from NAT forwarding alone.
Phase 2 has not started and must not start before real inspection succeeds.


## Retry after user completed setup

The dedicated key file now exists. A strict-host-checking SSH connection reached
the VM; debug output shows the VM accepts the offered configured public key.
However, this Codex process receives `Permission denied` when accessing the
Windows SSH-agent socket, and authentication still exits 255. The agent/service
visibility from this process must not be treated as proof of the user's native
Windows service state. No passwords or key contents were read or collected.

Local pytest rerun: 23 passed, 1 gated live test skipped, 22 passing subtests.
The application CLI failed at its first read-only SSH operation (exit 255).
No actual ruleset, listeners, interfaces or routes have been retrieved in this
retry; no live test passed and no firewall rules were changed.

The helper `scripts/validate_phase1.py` lets the user run the existing tools in
normal Windows PowerShell, where their unlocked SSH agent is accessible. It
attempts each fixed inspection operation, preserves real observations and errors,
and runs the full test suite with the live VM test enabled. Results go under
`snapshots/ubuntu-vm-inspection.json`, `snapshots/phase1-tests.xml` and
`snapshots/phase1-tests.txt`. The helper stores no credentials and issues no
firewall modification commands. Phase 1 remains pending until those results
confirm all seven real observations and the live test pass.
