> Latest status: **Phase 3 live acceptance PASSED**. See `phase3-acceptance.md`.
> Earlier pending/proposed checks below are retained as implementation history.

# Phase 3 local validation: PASS; real VM acceptance: PENDING

Run in the existing project on Windows using its isolated .venv Python.
Latest pytest result: 94 passed, 4 skipped, 57 subtests passed; zero failures.
The four skipped cases are the gated Phase 1 real-VM check, Gemini+VM live audit,
and two Phase 3 read-only live helper/approved-receipt checks. No skipped test is
represented as an executed live success. Earlier Phase 1 and Phase 2 acceptances
remain documented separately.

## Executed checks

- Existing Phase 1 and Phase 2 local regression tests.
- Shared strict policy for IPv4 and IPv6 source restrictions, expired/stale or
  tampered proposals, broadening/SSH/RDP/sets/jumps/ambiguous family rejection,
  root-owned chain/port/source/host/target allowlists and topology validation.
- Real SQLite transaction, exact one-use approval, expiry, secret redaction,
  update/delete trigger and partial-corruption detection tests. An initial
  connection-lifetime issue on Windows was fixed; database handles now close
  deterministically and the full suite passes.
- Fake nft/systemd state-machine tests: success, rejected/missing approval,
  failed allowed-client check, lost management SSH, inconclusive denial, expired
  lease, reboot identity mismatch, stale state, lost apply response, failed timer,
  client death, watchdog/recovery, conflicting/unrelated changes and disk-full
  audit failures. Fake backends are explicitly labelled in test_phase3.py.
- Agent inspection/policy events persist through the real SQLite ledger; agent
  investigations stop if logging fails. No mutation tools were added to Gemini.
- Fixed TCP program syntax and parameter validation; fixed nft JSON syntax-check
  command, recovery-service prerequisite and systemd timer argv assertions.
- All Python source, test/helper scripts and installed-wrapper source parsed.
- CLI --help and synthetic plan creation succeeded. The draft has baseline=null,
  is labelled inert_draft, and caused no SSH, probes or firewall modifications.

XML: D:\codex\firewall\work\phase3-local-tests.xml.
Synthetic draft: plans/phase3-synthetic-draft.json (NOT a live approval).

## Not executed

No helper installation, sudoers change, root-policy enable, actual nft mutation,
live connectivity remediation, real systemd watchdog or boot recovery was run on
the Ubuntu VM. Only ubuntu-vm currently exists in the configured host allowlist;
no independent APP01/attacker profiles were invented or silently enabled.
A Git Bash shell syntax-only attempt was blocked by a Windows sandbox/MSYS
named-object access denial. Run sh -n on Ubuntu before reviewing/installing the
helper. nft/kernel/systemd and installation behavior still require real Linux
validation; Python/fake tests do not substitute for it.

## Reviewable deployment artifacts

- deploy/phase3-helper-bundle.zip: minimal root helper, disabled root policy,
  installer and recovery service; no credentials, snapshots or local host config.
- deploy/phase3/: unpacked sources for review.
- docs/phase3.md: exact scope, approval boundary, installation steps, isolated
  three-VM topology and remaining acceptance criteria.

Starting Phase 3 authorized implementation, not an arbitrary live firewall diff.
A real mutation requires a fresh supported target rule, verified baseline,
reviewed exact proposal and explicit human approval. Current observed empty
ACCEPT-policy chains are deliberately not tightened automatically.

Phase 3 has not passed live acceptance. Phase 4 has not started.

The user confirmed only the current Ubuntu VM is available. See
phase3-lab-setup.md for the proposed source-client setup; no extra hosts or
network changes have been made.
