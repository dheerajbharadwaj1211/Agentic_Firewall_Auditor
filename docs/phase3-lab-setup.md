> Updated operator-supplied topology: APP02 is viper@192.168.56.10, ATTACKER
> is labuser@192.168.56.20, and target data IP is 192.168.56.30. The target SSH
> profile remains viper@127.0.0.1:2222. Profiles and verification plan are saved,
> but native SSH/address validation is pending. Earlier one-VM notes below are history.

# Phase 3 lab: current resources and next setup

The user confirmed that only the original Ubuntu VM currently exists. Keep it as
the target. No additional VMs, adapters, addresses or firewall rules were created
or changed by this implementation.

The current Phase 3 implementation supports verification through separately
configured SSH source hosts. To test legitimate and unauthorized clients with
that implementation, prepare two small source VMs on an isolated VirtualBox
host-only network alongside a host-only adapter on the target. Keep the target's
existing NAT adapter and 127.0.0.1:2222 SSH forwarding for Windows management.

Proposed example addresses (not observed or assigned):

- Target: 192.168.56.30
- APP01: 192.168.56.10
- Attacker: 192.168.56.20

Before choosing these values, inspect the actual VirtualBox host-only subnet and
DHCP allocation to avoid conflicts. If it differs, use addresses from the actual
subnet and update every example consistently. Do not use bridged/public networking
for an intentionally permissive database test. Ensure cloned guests, if used,
have unique MAC addresses, machine identities and SSH host keys; otherwise source
identity and host-key checks are unreliable. Fresh minimal source guests avoid
inheriting the target's privileged setup.

Each source needs OpenSSH server, Python 3, a named non-root user and your dedicated
public key installed. Verify each SSH host fingerprint from its own VM console.
No private key needs to be copied into any VM, and no root sudo access is required
for source TCP probes. Run the client in normal Windows PowerShell with your
existing SSH agent. Use the host-only IP on port 22 for each source profile.

Once you know the actual source IPs and usernames, merge those profiles into
config/hosts.local.json (lab/phase3/hosts.example.json is a template). Keep the
existing ubuntu-vm profile intact. Update the verification plan and reviewed
root helper policy with actual data addresses; do not merely copy example values.

Only then review/install the disabled helper using docs/phase3.md. The lab firewall
fixture is a separate explicit firewall change, not part of installation. Its
application requires operator review, a VM snapshot and console access. A fresh
snapshot and exact rule handle are required before the interactive remediation
approval. No default policy on the existing target is tightened automatically.

One Linux VM can also emulate independent clients using network namespaces, but
this code does not yet implement a namespace-aware, root-allowlisted probe and
firewall target backend. Running the current host probes twice under different
aliases is not equivalent. That would need a separately implemented/tested lab
extension, not an undocumented workaround.

Current status: 94 local tests passed; live Phase 3 deployment, traffic verification
and actual watchdog/rollback acceptance remain pending. See phase3-validation.md.
