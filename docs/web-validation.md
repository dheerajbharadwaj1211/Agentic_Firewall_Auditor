# HTTPS interface validation record

Date: November 14, 2026. This records observed implementation tests, not a live Gemini/VM acceptance or a completed assignment answer.

## Verified

Command from `D:\codex\firewall\firewall-auditor`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Result: **103 passed, 4 gated live tests skipped, 57 subtests passed**. The suite includes nine focused web tests. See `evidence/web/regression-results.txt` for the sanitized output. Existing CLI/controller/Phase 3 regression tests were included; the skipped external tests were not forced on. Test certificates and other intermediates were placed in `D:\codex\firewall\work`.

| Test | Expected | Observed |
| --- | --- | --- |
| Real loopback TLS with untrusted CA | Certificate verification fails | SSLCertVerificationError |
| Same server with explicit generated CA trust | Verified HTTPS page response | HTTP 200 with no-store, CSP, nosniff headers |
| Unauthenticated state access and wrong password | Reject | HTTP 401 |
| Missing/wrong CSRF, foreign Origin, invalid Host, cross-site Fetch Metadata | Reject | HTTP 403 |
| Authenticated bounded synthetic audit through HTTP | Accepted; progress and result accessible | HTTP 202, validated event and labelled synthetic result |
| Blank, oversized and wrong-type goals | Reject without starting job | HTTP 400 |
| Unexpected host field, mutation route and path traversal | No matching route | HTTP 404 |
| Second job during active audit/cooldown | Reject without queuing | HTTP 409 |
| Five failed logins then another attempt | Throttle | HTTP 429 |
| Oversized body / wrong content type | Reject | HTTP 413 / 415 |
| Session rotation, idle expiration and logout | Old session no longer authorized | HTTP 401 |
| Non-ASCII cookie/CSRF values | Controlled rejection without handler exception | HTTP 401 / 403 |
| Synthetic runner exception containing secret-like text | Generic error only | Failure message omitted exception content |
| Browser report minimization | Omit private config, raw exports, process details and known API secret | Assertions passed |
| Real AgentController using synthetic provider/VM observations | Seven observations, ten tool events, complete read-only result | Passed; firewall_modified=false |
| Certificate regeneration / short password | Fail closed | ValueError; existing certificate files not overwritten |

These synthetic tests use fake model/VM collaborators and never claim Gemini or SSH connectivity. The HTTPS tests use real sockets, TLS handshakes and certificate verification, not an HTTP mock.

## Problems observed and resolved

The first sandboxed test attempt could bind but could not connect to loopback (`WinError 10013`). Specific network access was requested and granted; the tests then exercised actual TLS. No security checks were weakened.

The first generated certificate was rejected by Python 3.13 strict verification because it lacked Authority Key Identifier. The generator was corrected to include subject and authority key identifiers, CA/basic constraints, key usage, IP SAN and server-auth extended usage. Verified HTTPS then passed with the generated CA explicitly trusted by the test client. The negative untrusted-CA test still fails as expected.

## Pending and limitations

- No API key is available to Codex, and its subprocesses cannot use the Windows SSH agent. No live Gemini/VM request was run through the new UI. Earlier phase2-live evidence is not evidence for this web interface.
- No CA was installed into the user's certificate trust store. Actual Edge/Chrome trust, browser cookie behavior and trusted address-bar display remain to be checked by the native operator.
- Both computer-use entry points failed to initialize with `failed to write kernel assets`. A bundled Playwright/Edge fallback also failed to start (Crashpad/named-pipe process failure). No browser screenshots were captured; no screenshot or successful visual QA is claimed. A static layout preview exists only in the work directory and is explicitly marked as a preview, not HTTPS/live evidence. Browser layout, responsive behavior, JavaScript event flow and DOM rendering still need native visual confirmation.
- No public deployment, topology change, fixtures, privileged helper installation, mutation policy enabling, connectivity probe or firewall modification occurred.
- The server is for a single loopback operator, not public deployment. New deployment requirements need a separate hosting/security review.

Follow `web-interface.md` for the final native launch, local CA trust, real audit and screenshot collection. Capture both the high-level request and fresh meaningful result before treating Q1/Q2 demonstration evidence as complete.
