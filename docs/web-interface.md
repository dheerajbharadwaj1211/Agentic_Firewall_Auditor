# Local HTTPS interface operation

This additive interface implements the Phase 2 assignment's HTTPS requirement. The authoritative assignment is `C:\Users\Dheeraj\Downloads\AI_Agent_Term_Project_Phase_2.docx` (due November 16, 2026). It supersedes the older PDF's desktop-only allowance. This guide is operational evidence, not a completed assignment report or submission.

## Start in native Windows PowerShell

Use a normal interactive Windows PowerShell terminal, where the existing SSH agent works. Do not launch through Codex subprocesses or GUI terminal automation. Keep the Ubuntu VM running and the existing dedicated encrypted SSH identity loaded in the Windows agent. Preserve the existing pinned known-hosts and allowlisted host configuration. Do not print private keys or paste API keys into chat.

```powershell
Set-Location 'D:\codex\firewall\firewall-auditor'
# The existing environment already contains Gemini and cryptography.
# If setting up a fresh environment only:
# .\.venv\Scripts\python.exe -m pip install -e '.[dev,web]'
.\.venv\Scripts\python.exe scripts\run_web.py --init-cert
```

Certificate generation is one-time and refuses to overwrite existing certificate files. It creates a 30-day CA and a leaf certificate valid specifically for IP `127.0.0.1` in `config/web-tls`. The CA signing key is not saved. The leaf private key is restricted to the current Windows account and SYSTEM by directory ACL, and the entire directory is ignored by Git. Do not share or commit `server-key.pem`.

### Trust the local certificate without bypassing checks

The certificate is locally signed, not publicly trusted. HTTPS encrypts the connection, but the browser must trust the issuing CA and verify the URL identity to authenticate this server. An initial certificate warning means trust has not yet been established; do not click through it or disable verification.

Inspect the generated CA certificate and fingerprint locally:

```powershell
$localCa = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('D:\codex\firewall\firewall-auditor\config\web-tls\ca.pem')
$localCa | Format-List Subject,Issuer,Thumbprint,NotBefore,NotAfter
```

For Edge/Chrome local testing, explicitly trust this generated CA in **Current User / Trusted Root Certification Authorities** only. This changes your user trust store; run it yourself after inspecting the local certificate:

```powershell
Import-Certificate -FilePath '.\config\web-tls\ca.pem' -CertStoreLocation 'Cert:\CurrentUser\Root'
```

Restart the browser if needed. Browser-specific trust behavior can vary; this trust installation and browser padlock check have not been performed by Codex. Do not install the private key or trust arbitrary certificates. Remove this CA after local testing, using the exact recorded thumbprint:

```powershell
# Replace with the exact CA thumbprint inspected above; never use a wildcard.
# Remove-Item -LiteralPath 'Cert:\CurrentUser\Root\EXACT_CA_THUMBPRINT'
```

After expiry, remove the old trust entry and deliberately archive/replace the three local certificate files before regenerating; the launcher never silently rotates trusted material.

### Run the real agent

```powershell
.\.venv\Scripts\python.exe scripts\run_web.py
```

The launcher prompts twice for a new local access password (16-256 characters), then prompts for the Gemini key if `GEMINI_API_KEY` is not already set in this native process. All prompts are hidden and fail closed if hidden terminal input is unavailable. Neither password nor API key is saved by the launcher. Use separate values. The model defaults to the previously verified `models/gemini-3.1-flash-lite` with API `v1beta`; a deliberate `--model` override is available only in the local terminal.

Open **https://127.0.0.1:8443/** (not localhost, which is not in this certificate or Host allowlist). Enter the local access password, enter an audit goal, then select **Run live audit**. Tool activity updates every 1.5 seconds while the agent runs. Findings cite evidence IDs and pointers; expand the JSON to inspect minimized observations and coverage. Recommendations and verification plans are informational and never executed by this interface.

The browser does not accept SSH credentials, arbitrary hosts, shell commands, model tool definitions or Gemini keys. No saved-report fallback exists: an unavailable API or SSH connection produces an explicit incomplete/failed result. Existing saved reports are not presented as fresh web results.

Latest real audit output is written to `reports/web-latest/report.json` and `report.md`; validated tool events use the existing SQLite ledger in `audit/audit.sqlite3`. Report writes replace the previous web-latest output, so preserve needed evidence before another run. Raw operator goals are not logged or included in reports. Native reports contain fuller VM observations and should be reviewed before sharing.

Press Ctrl+C in the launcher to stop the local service. Signing out invalidates the session but does not cancel an already running bounded audit. Stopping the process can interrupt an audit and leaves no new complete report; inspect timestamps rather than assuming an existing web-latest report belongs to the interrupted run.

## Security design and trust boundaries

Browser input is untrusted. The HTTP layer requires the exact loopback Host, exact same-origin Origin for every POST, JSON content type, bounded bodies, a secure authenticated session and a matching CSRF header for audit/logout. It rejects cross-site Fetch Metadata, arbitrary paths and unknown routes. There is no CORS allowance. Login is limited to five failed attempts per minute. Sessions rotate at login, expire after 30 minutes idle or eight hours absolute, and use `Secure`, `HttpOnly`, `SameSite=Strict`, `__Host-` cookies. Logout invalidates the session server-side. The local password is required even on loopback; other local users may connect to loopback but cannot access audit data without it.

Untrusted VM/model data crosses the existing controller policy boundary. The UI calls the real AgentController, Inspector, Gemini adapter and evidence-grounded analysis. Existing manual tool validation, fixed commands, pinned SSH host checks and budgets remain authoritative. VM data and high-level goals cannot grant mutation authority. No Phase 3 helper installation, policy changes, approval routes, probes or mutations are exposed.

Only validated tool name/status events are streamed, never private model reasoning or thought signatures. The browser receives a minimized report, excluding SSH configuration and operator-context configuration. Raw firewall exports/comments and service process metadata/text are omitted. Known API-key environment values are redacted. Every dynamic DOM value uses `textContent`; no untrusted HTML rendering or Markdown execution occurs. A restrictive CSP, no-store caching, frame denial and MIME sniffing protection supplement escaping.

One background audit may run at a time; there is no job queue. A ten-second start cooldown, 2,000-character goals, 8 KiB HTTP bodies, a 24-event progress window and the existing 16-turn / 24-call / 180-second / 16,000-output-token controller budgets bound resource usage. The server handles HTTP serially with a small connection backlog and three-second socket timeout; this is intended for a single local operator. The agent's individual API/SSH operations retain their own timeouts. Errors never include raw SDK exceptions or request/credential content. Generic startup/job messages intentionally require local configuration diagnosis.

TLS uses the standard-library SSLContext, minimum TLS 1.2, a SAN IP certificate and a local CA. No unverified client contexts or certificate-check bypasses are used. The custom standard-library HTTP server is a restricted local test service, not a public production server. Python explicitly cautions against production use of http.server: https://docs.python.org/3.13/library/http.server.html . Certificate primitives follow https://cryptography.io/en/stable/x509/tutorial/ . Public/class deployment, stronger multi-user identity, hardened hosting, request-level deadlines and deployment review belong to a later phase. Do not bind to LAN, port-forward, tunnel or publish this service.

The local OS account and administrators remain trusted: browser protections do not defend against a compromised local administrator, malicious same-origin code or someone reading server-process memory. The local TLS key must remain private. Bounded execution limits abuse but cannot guarantee provider availability, quotas or instantaneous cancellation.

## Evidence collection for the assignment (pending live run)

1. Capture the trusted HTTPS URL, entered high-level request and start of real tool activity. Exclude passwords, API keys and terminal prompts.
2. Capture the completed fresh result with its generated timestamp, Gemini model, findings, evidence references and coverage notes. Do not substitute the older `phase2-live` result.
3. Capture expanded relevant observations, the read-only indicator and limitations. Internet reachability and effective packet flow remain untested.
4. Preserve `reports/web-latest` and screenshots in a clearly dated evidence folder under this project. Record observed failures honestly if Gemini or SSH fails.
5. Use `docs/web-validation.md` and the sanitized regression log for implemented security checks; capture additional browser checks if required by the report.

No team identities/contributions, Canvas submission, public URL or completed report have been created.
