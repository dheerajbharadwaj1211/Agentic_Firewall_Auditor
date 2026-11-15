# Phase 3 live acceptance: PASSED

Accepted from actual CLI receipts, a valid local audit chain and matching
user-supplied target systemd journal evidence. No mocked result is counted as
live acceptance. Phase 4 has not been started by this chat.

## Real normal remediation and final state

Target: ubuntu-vm / viper@127.0.0.1:2222, host-only IP 192.168.56.30.
The IPv4 TCP 3306 rule ip/fwa_lab/input handle 5 was restricted from
192.168.56.0/24 to 192.168.56.10/32 with an exact, recorded human approval.
Final change ID: ef5e5b07e90f48a4b92c12520f0f010a.

Observed final traffic:
- APP02 192.168.56.10: connected.
- ATTACKER 192.168.56.20: timeout (unauthorized connection blocked).
- Target management SSH: working.
- Status verified; no rollback was needed in the successful final workflow.

The proposal digest matches the saved proposal. Human approval, one-use approval
consumption, applied, verification_passed, confirmation_requested and confirmed
records are present. The local ledger integrity check passed.

## Real independent watchdog demonstration

Watchdog change ID: 92ced62059dd417fb651b834e66f4adb.
The demo observed the approved restriction (APP02 connected, ATTACKER timed out),
then deliberately withheld confirmation and never requested client-side rollback.
The original semantic ruleset was observed restored after 123.72 seconds.
Both clients could connect again and management SSH worked at the restored /24
baseline. The root helper's fingerprint ignores volatile packet/byte counters
and export metadata; this is semantic restoration, not byte-identical counters.

The user supplied journalctl output for the exact matching systemd service.
It shows systemd starting the helper with --rollback and that change ID, a
successful helper result with replacement_applied, rule_restored and
ruleset_matches_before all true, then successful service deactivation.
This journal was supplied by the user; Codex did not independently fetch it
from the guest. Its source text and provenance record are preserved separately.

After evidence capture, the normal workflow was rerun and confirmed the final
APP02-only state above. The temporary /24 reset was explicitly approved in chat
and recorded; it was not treated as implicit permission from the first change.

## Evidence

- reports/phase3-last-result.json: final verified restricted state.
- reports/phase3-watchdog-result.json: real independent restore observation.
- reports/phase3-watchdog-journal.txt: supplied root service journal.
- reports/phase3-watchdog-journal-provenance.json: origin and integrity hash.
- audit/audit.sqlite3: proposals, approvals, policy/application/verification events.

## Test accounting and scope

Prior complete local suite: 94 passed, 4 gated live checks skipped, 57 subtests
passed. New watchdog client harness: 4 targeted fake-backend tests passed.
Live acceptance was through native CLI workflows and journal evidence; skipped
pytest live cases are not falsely counted as executed tests.

This acceptance covers the implemented scoped source-restriction path, exact
human approval, two-source new-connection verification, preserved management
SSH, independent 120-second unconfirmed-change rollback and persistent evidence.
It is a TCP test listener, not a real MySQL server. It is not a general firewall
security certification. Only the tested IPv4 TCP 3306 scope is covered; complex
nft control flow/inet rules, persistent nftables.conf changes, existing-session
termination, a forced full-client crash and real reboot recovery were not live
validated here. Root policy still limits mutations and requires approval; do
not remove those controls because the lab passed.
