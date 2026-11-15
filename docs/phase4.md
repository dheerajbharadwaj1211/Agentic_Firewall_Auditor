# Phase 4: operator interface and acceptance

Status: implementation started; native desktop and HTTPS live acceptance pending.

## Run the desktop console

In native Windows PowerShell, with all three lab VMs running:

```powershell
cd D:\codex\firewall\firewall-auditor
ssh-add "$env:USERPROFILE\.ssh\id_ed25519_firewall"
.\.venv\Scripts\python.exe scripts\run_desktop.py
```

Enter the Gemini key at the hidden terminal prompt. The default working model is
`models/gemini-3.1-flash-lite`, API `v1beta`. Select `ubuntu-vm`, then Run live audit.
Do not put credentials in the goal. VM inspection data is sent to Gemini.
The launcher restores the original API-key environment value on exit.

Results: `reports/phase4-desktop-latest`. JSON includes complete/incomplete status,
findings and evidence. An incomplete result with zero findings is not a clean audit.
Network/API work runs in a QThread worker; only signals update widgets. One job
runs at a time. Closing is blocked until the bounded investigation finishes.
Errors display their class, never raw SDK exception text. Configuration stays in
existing local JSON files; the console does not edit SSH keys or trust host keys.

The saved-evidence button loads existing Phase 3 receipts and verifies the local
SQLite hash chain. This checks historical evidence, not current VM connectivity.
No mutation controls or LLM mutation tools are added. Use the existing Phase 3
CLI for fresh proposal review, exact hash approval, verification and rollback.
Do not reset the accepted /32 restriction just to repeat a demonstration.

## Remaining acceptance checklist

- [ ] Launch natively with encrypted SSH key loaded in the Windows agent.
- [ ] Run a real Gemini/VM desktop audit; retain complete report and screenshot.
- [ ] Confirm the window remains responsive while the audit runs.
- [ ] Inspect findings and limitations; never infer Internet reachability from NAT.
- [ ] Complete the separate HTTPS browser workflow and live audit, retaining URL,
  trusted-certificate evidence, login and result screenshots for the new assignment.
- [ ] Review regression results, security cases and known limitations.
- [ ] Add actual team contributions and prepare the final assignment report.
- [ ] Record a 5?10 minute demonstration using the script below.

## Demonstration (approximately 7 minutes)

1. (0?1 min) Explain Windows controller, Ubuntu target .30, legitimate APP02 .10
   and attacker .20. Show that this is an isolated lab and describe SSH trust.
2. (1?3 min) Launch the console, run a read-only live audit and inspect evidence.
   Show progress and explain that model output cannot execute arbitrary commands.
3. (3?4 min) Show the separately implemented HTTPS UI, trusted local certificate,
   login, and its own live result. CLI evidence alone does not satisfy web acceptance.
4. (4?6 min) Review the saved verified Phase 3 receipt: legitimate client connected,
   attacker timed out, management SSH remained available. Show the independent
   watchdog receipt and target journal with rule_restored/ruleset_matches_before.
   Clearly label historical evidence rather than pretending to apply a new change.
5. (6?7 min) Show exact-hash approval requirements, regression results, limitations,
   and remaining work. Do not reveal API keys, private keys, approval tokens or nonces.

## Scope and limitations

The desktop is an operator console, not the HTTPS interface required by the newer
assignment; both acceptance paths are tracked separately. Firewall changes remain
in the existing tested CLI. Live evaluation covers the known IPv4 TCP/3306 lab
restriction and watchdog restoration, not arbitrary production policies, IPv6
remediation, reboot recovery or a new forced-crash test. Local tests and offscreen
renders do not replace a real desktop/Gemini/VM run. Findings coverage is limited
to the existing deterministic detectors. No production accuracy metrics are claimed.
