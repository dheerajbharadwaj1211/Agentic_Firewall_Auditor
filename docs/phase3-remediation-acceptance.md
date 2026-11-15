> Latest status: **Phase 3 live acceptance PASSED**. See `phase3-acceptance.md`.
> Earlier pending/proposed checks below are retained as implementation history.

# Live remediation verified; independent watchdog demonstration remains pending

The user's real receipt reports verified for ubuntu-vm, change ID 9dba5847dbd1413696b1f565d4b2171f.
The receipt and local SQLite audit chain were independently checked. The exact
proposal, human approval, one-use approval consumption, application, verification
and confirmation records are present and consistent.

Actual new-connection outcomes: APP02 192.168.56.10 connected; ATTACKER
192.168.56.20 timed out; target management SSH worked. Rule ip/fwa_lab/input
handle 5 was narrowed from 192.168.56.0/24 to 192.168.56.10/32 for TCP 3306.
No rollback occurred during this successful normal workflow.

The remaining live test is the independent VM watchdog. Its prepared native
launcher deliberately never confirms and never requests client rollback. It
requires a separate approval for temporarily restoring the lab /24 preimage,
then an interactive exact-hash approval for the test restriction. It observes
actual restriction and exact original-state restoration, and prints a root
journalctl command to collect evidence that systemd executed the rollback.
Finally reapply the normal approved APP02-only restriction to end in the verified
restricted state. Do not leave the temporary broadened lab baseline as the final
configuration. The reset is proposed at plans/phase3-watchdog-reset.nft.json,
not executed. No real firewall change was made during this preparation turn.
