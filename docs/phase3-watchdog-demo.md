> Latest status: **Phase 3 live acceptance PASSED**. See `phase3-acceptance.md`.
> Earlier pending/proposed checks below are retained as implementation history.

# Remaining live watchdog demonstration ? prepared, NOT executed

The normal live remediation is verified. Its receipt and matching local audit
records were independently checked; see phase3-remediation-acceptance.md.

To exercise the existing 120-second independent watchdog, the lab must first
return the one TCP 3306 rule from APP02-only /32 to the previous host-only /24.
The exact reset JSON was built from the recorded approved preimage at
plans/phase3-watchdog-reset.nft.json. No command has applied it. This temporary
broadening requires a NEW explicit operator approval; approval of the initial
lab setup or the successful narrowing is not treated as approval to broaden it.

After the reset is approved and performed, keep the fixed-response TCP test
listener running and run scripts/demo_phase3_watchdog.py in normal Windows
PowerShell. It refreshes the baseline and independently gated proposal, displays
the actual diff, and requires its own exact-hash approval. It uses the existing
installed helper; no root code update is needed. The demo records the human
approval and consumes its token before requesting the permitted source restriction.

The demo observes APP02 connected and ATTACKER denied, but deliberately NEVER
calls confirm or client rollback. It waits for the VM to restore the exact before
fingerprint and verifies both baseline connections plus SSH again. It refuses
to label an early unexplained restore as the 120-second watchdog. The result is
saved to reports/phase3-watchdog-result.json. Root journal evidence is still
required to identify the systemd rollback execution; the demo prints that exact
journalctl command with the new change ID. Do not expose helper capabilities or
approval tokens in screenshots or logs.

The demo therefore ends temporarily at /24. After capturing evidence, rerun the
normal Phase 3 apply workflow and approve a fresh APP02-only restriction to finish
in the verified /32 state. Phase 3 acceptance needs the successful normal receipt,
the actual independent restore evidence/root journal, and a secure final state.

New watchdog harness tests use explicitly fake nft/systemd backends and a simulated
clock. They verify no confirm or rollback is requested by the client, correct
independent restoration, no false success on missing/early restore, and mandatory
one-use approval. These tests do not count as the real VM watchdog demonstration.
No firewall changes were made in this preparation turn.
