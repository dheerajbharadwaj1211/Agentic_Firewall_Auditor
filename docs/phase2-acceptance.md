# Phase 2 acceptance: PASSED

Verified November 14, 2026 from the user's actual native Windows launcher output
and saved live report. This extends the previously accepted Phase 1 codebase.

## Live end-to-end evidence

- Provider: Gemini Developer API, model models/gemini-3.1-flash-lite, API v1beta.
- Target: configured Ubuntu VM, viper@127.0.0.1:2222.
- Complete status, null failure, read-only true, firewall_modified false.
- Ten successful allowed calls across ten model turns: operator context,
  host information, nft version, rules, listeners, interfaces, IPv4 routes,
  IPv6 routes, findings analysis and structured completion.
- Seven fresh actual VM observations, all marked untrusted, collected between
  6:39:19 PM and 6:39:33 PM Eastern. Report completed at 6:39:34 PM Eastern.
- Original nft JSON and ss listener output were independently reparsed and
  matched saved normalized models.
- The findings engine was rerun locally against the saved evidence and operator
  context; it exactly reproduced both live findings.
- Every finding's observation ID and JSON pointer resolved to source evidence.

## Findings

1. HIGH configuration candidate: Empty input chain defaults to accept.
2. HIGH configuration candidate: Broad SSH permission with a non-loopback listener.

Neither finding asserts verified Internet exposure. External connectivity and
complete packet flow were not tested; VirtualBox NAT is a separate boundary.
No firewall rules were modified, and no remediation or rollback was attempted.

## Test accounting

Latest local pytest run: 60 passed, 2 explicitly gated live tests skipped,
33 subtests passed, zero failures. The actual live Gemini+VM validation here
was performed through scripts/run_phase2.py; the skipped pytest live cases
are NOT falsely counted as executed. The preceding model-only function-call
probe also passed on the same Gemini model and API version.

Evidence files: reports/phase2-live/report.json and report.md.
Local test XML: D:\codex\firewall\work\phase2-local-tests.xml.
No API keys, passphrases or private-key contents are included in this document.

## Acceptance scope

The real autonomous read-only audit works. The existing VM's ruleset has zero
explicit rules, so real nonempty expression scenarios still need a separately
approved isolated lab fixture; those categories currently have synthetic test
coverage. Unknown host role/dependencies remain explicit coverage notes until
configured by the operator. General nftables control flow is not fully simulated.
These boundaries do not turn this read-only success into a firewall-security
certification. Normal Windows execution remains necessary for local SSH-agent
access in this environment. Phase 3 has not started.
