# Phase 1 acceptance: PASSED

Verified from real result files on November 14, 2026, after the user ran the
existing application tools and live tests in normal Windows PowerShell.

- Target: viper@127.0.0.1:2222 (VirtualBox NAT SSH forwarding).
- Authenticated Linux/OS read succeeded.
- `sudo -n /usr/sbin/nft -j list ruleset` succeeded: nftables v1.1.6,
  three inet/filter chains, zero explicit rules, accept policies for input,
  forward and output.
- `ss -lntup` succeeded: eight TCP/UDP listeners normalized.
- `ip -j addr` succeeded: two interfaces.
- `ip -j route` succeeded: five IPv4 route entries.
- IPv6 route inspection succeeded: seven entries.
- All seven observations are tagged as untrusted data; no inspection errors.
- Saved raw nftables and ss evidence was independently reparsed and matched
  the saved normalized structures.
- Full pytest result: 24 passed, 22 subtests passed; no failures, errors or
  skips. XML records 46 entries including the subtests. The real-VM integration
  test is present and passed; pytest exit code is zero.

Evidence: snapshots/ubuntu-vm-inspection.json, snapshots/phase1-tests.xml,
snapshots/phase1-tests.txt. The snapshot records the inspection start as
2026-11-14T23:06:56.483543+00:00 (6:06 PM Eastern).

This validates Phase 1 connectivity, read-only collection and parsing against
this real VM. It does not establish vulnerability detection or remediation.
Because the actual ruleset contains no explicit rules, real rule-expression
normalization has not yet been exercised on this VM; that remains covered by
synthetic tests. No nftables packet restrictions are configured in the observed
accept-policy chains. VirtualBox NAT is a separate boundary; this observation
alone does not establish public Internet reachability or overall host security.

No firewall rules were modified. Phase 2 has not started.

The user's normal Windows process could access their SSH agent and complete the
inspection. The Codex execution process still could not access that agent;
repeat live checks through the native-terminal helper unless that access changes.
No passwords, private-key contents or passphrases were collected or saved.
