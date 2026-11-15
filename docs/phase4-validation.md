# Phase 4 local evaluation

Local regression: **111 passed, 4 skipped, 57 subtests passed**, 49.27 seconds.
No failed tests. Gated live tests were skipped; these results are not a new VM or
Gemini acceptance run. Machine-readable results: `reports/phase4/local-tests.xml`.

| Area | Expected behavior | Evidence |
|---|---|---|
| Desktop responsiveness | Audit executes off GUI thread; duplicate start blocked; busy close refused | test_desktop.py |
| Desktop failure handling | Exception class shown without provider secret; blank goal rejected | test_desktop.py |
| Saved evidence | Missing evidence is not called a pass; historical receipts labeled | test_desktop.py |
| Finding coverage | Database, SSH, management, any-to-any, broad source, segmentation; contextual negative cases | test_phase2.py |
| Prompt/tool abuse | Comments grant no privilege; cross-host/arbitrary tool calls rejected; no model mutation | test_phase2.py |
| Approval integrity | Exact, expiring, one-use approvals; tampered/stale proposal refused | test_phase3.py |
| Failure safety | Broken legitimate traffic, management loss, uncertain reply cause rollback; timer required first | test_phase3.py |
| Audit integrity | Updates/deletes refused; hash tampering detected; secrets redacted | test_phase3.py |
| HTTPS protections | Trusted TLS, auth, CSRF, origin/host, cookie and resource limits | test_web.py |
| Watchdog observation | Missing or early restoration never mislabeled successful timed rollback | test_watchdog_demo.py |

These are controlled fixtures and local integration tests, not a statistical
accuracy study. No live LLM adversarial success rate, precision or recall is claimed.
Historical real VM and Gemini evidence is documented in the Phase 1?3 acceptance
notes. New native desktop and HTTPS-browser acceptance remain pending.

`reports/phase4/desktop-saved-evidence-offscreen.png` was rendered with Qt's offscreen
platform and a locally loaded Segoe UI font. It shows actual saved Phase 3 receipts;
it is not a screenshot of a fresh native audit or the HTTPS browser interface.

The first run passed assertions but exposed a Qt test-harness shutdown access violation.
The QApplication fixture now retains a process-wide application and drains deferred
Qt deletions. The focused rerun exited cleanly (4 passed, exit code 0); the final
full-suite rerun below is the acceptance result.

Final full-suite rerun: 111 passed, 4 skipped, 57 subtests passed in 49.27 seconds; process exit code 0. Dependency integrity: pip check passed.
