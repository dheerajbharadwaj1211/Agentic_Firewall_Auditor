# Architecture and implementation plan

## Source and scope

`project_requirements.pdf` was read in full (30 pages). The supplied follow-up
request makes PySide6, Python, structured LLM tool calls, nftables, approval for
every modification, and pytest explicit. It asks to implement Phase 1 only.
The PDF's suggested examples are requirements context, not instructions to run
commands against this computer. No local firewall is inspected or changed.

## Architecture in simple terms

1. The operator chooses a configured test VM and starts an audit in the desktop UI.
2. A Python controller gives an LLM a high-level goal and structured tool schemas.
3. A deterministic policy gate validates tool name, host, parameters and permission.
4. Trusted tools perform specific SSH operations, returning untrusted observations.
5. An nftables adapter preserves rule order, chain policies, handles and expressions.
6. Findings cite rule evidence, listeners, operator-declared roles/dependencies,
   and explicit connectivity observations; a missing source selector alone does
   not prove Internet reachability.
7. A proposed change is bound to a ruleset version and exact diff. A human approves
   that change; deterministic code validates it again immediately before applying.
8. Independent probes verify unwanted traffic is blocked and legitimate traffic
   still works. A target-local rollback timer must restore the previous state if
   the agent loses SSH access or cannot complete verification.
9. An append-only application audit history records observable activity, policy
   decisions, approvals and outcomes. It does not expose private model reasoning.

The Phase 1 tool enum and host registry are the first read-only boundary, not a
claim that the full Phase 3 policy/approval/rollback system already exists.

## Required MVP

One Linux host firewall using nftables; one supported lab topology; Python and a
small PySide6 UI; autonomous structured inspection; context-aware findings for
public SSH, MySQL/PostgreSQL, ANY-to-ANY, broad sources, management exposure and
poor segmentation; explicit approval for each change; verification and rollback;
audit records; reproducible unit, integration and adversarial tests.

Nice-to-have: RDP findings on Linux rules, stale-rule investigation, richer UI.
Out of scope this month: Windows adapter, multiple firewall parsers, enterprise
routing, unrestricted shell access, web server, REST, React, Angular, FastAPI,
LangChain/LangGraph, microservices and generalized autonomous administration.

## Four-week delivery plan

| Week | Work | Exit criterion |
| --- | --- | --- |
| 1 | SSH, read-only tools, nft JSON normalization, lab fixtures and tests | Unit checks pass; operator reviews a real-VM snapshot |
| 2 | LLM provider adapter, controller budgets, tool schemas, context and findings | Agent independently gathers evidence; HTTPS control is not falsely flagged |
| 3 | Deterministic mutation policy, exact approvals, logs, transactional change, two-source probes and rollback timer | Unsafe actions rejected; lost SSH and failed legitimate probe restore configuration |
| 4 | PySide6 worker-thread UI, integration/adversarial evaluation, report and demo | Repeatable 5-10 minute real-VM demonstration |

Do not start Phase 2 until Phase 1 is tested and reviewed. GUI/network operations
will run off the UI thread. Maintain modest tool/time/token budgets and stop on
ambiguous state rather than inventing findings.

## Dependencies

Phase 1: Python >=3.11; OpenSSH client; Linux OpenSSH server, nftables, iproute2,
sudo. pytest is a development dependency. The fixed commands assume Ubuntu/Debian
binary locations; verify them on the chosen VM. `ss` returns numeric listeners
without privileged process metadata. `uname` returns OS/kernel information.

Later: PySide6; one chosen LLM provider's official SDK with structured tool calls;
stdlib SQLite for audit records. API credentials must come from environment
variables and never enter tool output, prompts, snapshots or logs. Phase 1 does
not need API keys. SSH private keys remain local paths passed to OpenSSH and are
never read by Python or sent to an LLM.

## Security risks and controls

| Risk | Control / limitation |
| --- | --- |
| SSH MITM | Verified known-hosts file, strict checking, no automatic enrollment |
| Command injection | Literal IP, restricted account name, fixed command enum, no shell=True or user-supplied remote command |
| Ambient SSH configuration | Ignore user config, disable proxy commands, agents, forwards and multiplexing |
| Excess privilege | Non-root SSH account; exact read-only nft sudo command; no wildcard sudo |
| Prompt injection | Remote comments stay untrusted evidence; no LLM or mutation capability in Phase 1 |
| Misread rules | Preserve raw expressions and rule order; flag unsupported semantics; no reachability inference |
| Hanging/large results | Connection/process deadlines, capped stdout and stderr; fail on errors |
| SSH lockout | Phase 1 cannot change rules; Phase 3 requires target-local timed rollback and management-path tests |
| Stale evidence | Snapshots are sequential, not atomic; re-read and compare handles/hash before future changes |
| Secret/network leakage | No raw SSH stderr in results; snapshots still contain sensitive network data; secure local storage required |
| Local compromise | Local config, Python code, OpenSSH binary and operator account are trusted; this is not an OS sandbox |

No normalization subset is sufficient to evaluate all nftables semantics. Named
sets/maps, verdict maps, NAT, jumps/gotos, connection tracking, interval sets and
multiple base-chain priorities must be modeled or explicitly refused before any
future automatic remediation. IPv4 and IPv6 are both collected. Installed nft
version and ruleset presence do not establish that traffic is protected.

## Decisions still needed

- VM OS/version, IPs, SSH account, verified host key and dedicated key path.
- One nftables owner: avoid concurrent UFW/firewalld/Docker changes for the MVP.
- LLM provider/model, API access, privacy policy and tool/time/token budget.
- Operator-specified host role, allowed clients, required management traffic and
  network reachability; these are not inferred from hostile host descriptions.
- Exact supported remediation subset, IPv6 behavior, review/approval identity,
  expiry and stale-state detection.
- Probe locations (attacker and legitimate APP01) and target-local rollback service.
- Log location, retention/access policy and handling of disk/write failures.

Phase 1 chooses OpenSSH rather than adding Paramiko: mature host-key checking and
no runtime Python dependencies. Changing this later must preserve the boundary.
The VirtualBox configuration explicitly enables a local SSH agent for an encrypted
key; forwarding remains disabled and other hosts default to no agent.

## Evaluation and demo

Use known cases: exposed DB, exposed SSH, legitimate public HTTPS, ANY-to-ANY,
malicious comments, forbidden mutation, and remediation that breaks APP01 access.
Measure finding precision/recall on labeled scenarios, tool calls, failed policy
requests, verification outcomes and rollback time. Distinguish synthetic from
real evidence in every report.

A final demo shows attacker and APP01 connectivity before an audit, evidence and
the proposed restricted DB rule, explicit approval, attacker blocked and APP01
still connected, then an injection rejection or rollback. A host-only attacker VM
represents an unauthorized source; it is not evidence of real Internet exposure.

Reference: nftables command behavior and base-chain hooks/policies are documented
in the upstream manual: https://netfilter.org/projects/nftables/manpage.html .
