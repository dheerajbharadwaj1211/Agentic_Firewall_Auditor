> Latest status: **Phase 1 PASSED**. See `phase1-acceptance.md` for verified
> real-VM evidence and test results. Earlier failed attempts below are retained
> as history and were resolved by running in the user's native terminal.

# Phase 1 validation

Executed on 2026-11-14 in the provided Windows environment using Python 3.13.

## Results

- `python -m unittest discover -s tests -v`: 18 discovered, 17 passed,
  1 explicitly skipped live-VM test, zero failures.
- `python -m firewall_auditor.cli normalize lab/synthetic_ruleset.json`:
  exit 0; output tagged `offline_fixture`; TCP 3306 accept rule, input chain,
  default drop policy and original expressions preserved.
- No real VM connection, firewall modification, live traffic probe, nft syntax
  check on Linux, LLM request, GUI execution or rollback test was performed.

The tests cover conservative normalization, IPv4 prefixes/IPv6 addresses,
unknown constraints/sets/jumps, malformed JSON, invalid ports, host validation,
duplicate aliases, forbidden dispatch, malicious comments remaining data,
fixed SSH argv/host verification, timeout/error handling, stdout/stderr bounds,
and rejected arbitrary commands. SSH execution in local tests is mocked.

pytest is declared in `.[dev]`, and the unittest classes are pytest-compatible.
pytest is not installed in this environment; package download could not complete
because network access was unavailable. Therefore no pytest run is claimed.
No Python PDF library/Poppler was available: all 30 PDF pages were read through
a local text-stream extraction fallback; no visual PDF review is claimed.

## Review gate and known limitations

Phase 1 implementation and available local tests are complete. Real-VM acceptance
and user review remain pending. Follow `lab.md` to configure and verify the VM,
then enable the opt-in integration test. Do not start Phase 2 before review.

The parser intentionally does not evaluate effective packet flow, resolve named
sets or traverse chain control flow. `complete` describes the supported rule
normalization subset, not security assurance. Raw data and unsupported expressions
are preserved. Listener output is numeric text; process identity requires future
context tooling. `get_firewall_status` currently reports the nft executable
version, not an enabled/secure boolean. Host role/dependency metadata, bounded
connectivity probes and persistent audit storage belong to later phases.

The snapshots are sequential, and remote data is untrusted. The fixed binary
paths and OpenSSH options must be tested on the selected lab OS/client version.
The runtime trusts local configuration, code and installed executables. Full
mutation safety, approval binding, stale-state checks, target-local rollback,
tamper resistance and adversarial LLM testing are not implemented yet.

## Subsequent VirtualBox configuration

See `ubuntu-vm-inspection-results.md` for the latest pytest run and the failed
authentication/setup checks against the actual Ubuntu VM. The earlier results
above describe the original implementation run, not the new VM inspection.
