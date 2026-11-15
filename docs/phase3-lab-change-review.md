# First live lab setup ? APPROVED, application not yet verified

The user reported successful installed-helper status: helper_version=1,
no pending changes, enabled=false, exclusive_firewall_owner=false, host_alias
ubuntu-vm, target data address 192.168.56.30, permitted source 192.168.56.10/32
on TCP 3306, permitted chain ip:fwa_lab:input. This is helper readiness, not
permission to change the firewall or proof of Phase 3 acceptance.

## Exact proposed service-only setup

Use lab/phase3/service-only-database.nft instead of the earlier general-drop
isolated-database.nft fixture. It creates a NEW ip/fwa_lab input chain with
priority 10 and policy drop. Explicit rules accept loopback, non-TCP traffic,
and TCP traffic to ports other than 3306. The intended new restriction is for
non-loopback IPv4 TCP 3306: permit 192.168.56.0/24 and drop other sources.
Other existing firewall chains still apply. IPv6 is not evaluated/changed.

This new fixture does not flush or edit existing tables or nftables.conf.
It fails if the fwa_lab table already exists. It has NOT been run or syntax-
checked against the actual Linux nft binary. That check must succeed before
application, from the target console with a VM snapshot available.

Before remediation, APP02 192.168.56.10 and ATTACKER 192.168.56.20 should both
reach target 192.168.56.30:3306. The future approved remediation narrows only
that one source selector from /24 to 192.168.56.10/32. It requires a separate
fresh, exact-hash approval through the Phase 3 console.

The unprivileged lab/phase3/tcp_lab_service.py binds only the target host-only
address and returns a fixed banner. It serves no files, runs no shell commands,
and is NOT MySQL. No HTTP server from a home/project directory is necessary.

Initial fixture creation is a firewall modification outside the helper's
restriction-only scope. It requires explicit operator approval first. Keep
root mutation policy disabled until the setup is reviewed and verified. No
VM-side installation commands for this fixture have been executed by Codex.

Fixture SHA-256: 9e3c1ec5aa23185216af8508c9013a6561b972ed21d52e83466d72783029b538

The user explicitly approved this initial setup in chat. That approval is
recorded as lab_setup_approved in the local audit ledger. It does not authorize
the later /24-to-/32 remediation or root mutation-policy enablement.
