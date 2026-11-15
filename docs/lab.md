# Reproducible isolated Linux VM lab

These are operator instructions, not actions performed by the application.
Use a disposable Ubuntu/Debian VM on a host-only/internal network with a console
and hypervisor snapshot. Do not expose intentionally insecure scenarios on a
bridged/public network. Final verification needs a second legitimate-client VM
and a separate unauthorized-source VM. Phase 1 only reads the target.

## Prepare the target from its console

```sh
sudo apt-get update
sudo apt-get install openssh-server nftables iproute2 sudo
sudo adduser --disabled-password --gecos '' auditor
command -v nft ip ss uname
```

This implementation expects `/usr/sbin/nft`, `/usr/sbin/ip`, `/usr/bin/ss` and
`/usr/bin/uname`. Verify these paths. Install a dedicated public key in
`/home/auditor/.ssh/authorized_keys` with directory mode 700, file mode 600 and
auditor ownership. For the lab key use the `restrict` authorized_keys option to
disable forwarding and PTY. Do not copy the private key into this repository.
An encrypted private key requires an authentication arrangement compatible with
BatchMode and disabled agent; this MVP expects a dedicated protected lab key
that OpenSSH can use noninteractively. Do not weaken production key handling.

Using `visudo -f /etc/sudoers.d/firewall-auditor-read`, add ONLY:

```sudoers
auditor ALL=(root) NOPASSWD: /usr/sbin/nft -j list ruleset
```

Set the sudoers file to root ownership and mode 0440; validate with `visudo -c`.
Never grant `nft *`, all commands, a root shell or passwordless general sudo.
This permits ruleset inspection only. No sudo permission is needed for the other
inspection commands. Confirm `sudo -n /usr/sbin/nft -j list ruleset` works as auditor.

The server account still has normal unprivileged shell access for this lab.
The application never exposes arbitrary SSH commands to callers or an LLM.
A future server-side forced-command wrapper can further confine the key.

## Verify host identity and configure the client

Obtain the VM SSH host-key fingerprint through the trusted VM console, e.g.:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Enroll the corresponding host key in a dedicated client known_hosts file after
comparing fingerprints through that channel. `ssh-keyscan` alone does not verify
identity. Use `[IP]:port` known-host syntax for a nondefault SSH port.

Copy `config/hosts.example.json` to `config/hosts.local.json`. Replace all paths,
the example documentation IP, and username with your actual lab configuration.
`test_vm: true` is the operator's explicit designation of a test target, not an
automatic safety guarantee. The key and known-hosts files must already exist.
No host is enabled by default; no automatic host discovery is implemented.

Run the read-only snapshot:

```powershell
$env:PYTHONPATH = (Resolve-Path src).Path
python -m firewall_auditor.cli inspect --hosts config/hosts.local.json --host db01
```

Expected: seven timestamped observations (rules, nft version, listeners,
interfaces, IPv4 routes, IPv6 routes, OS information), tagged as untrusted data.
A nonzero SSH exit, unknown host key, denied sudo, malformed JSON, timeout or
oversized result must fail the operation. No fallback accepts an unknown key.

Compare the raw nft JSON against a console capture. Handles/order, chain hook,
policy, and TCP 3306 must agree. Version output only confirms the nft executable
is present; it does not prove the firewall is enabled or effective.

## Synthetic versus real scenarios

`lab/synthetic_ruleset.json` is hand-authored synthetic data for offline parsing.
`lab/vulnerable.nft` is a deliberately insecure scenario to apply manually ONLY
on the isolated disposable target, with console access and a hypervisor snapshot.
It allows SSH, a simulated database listener and HTTPS from every source. The
application does not execute this file.

On a fresh VM without another firewall owner, inspect and syntax-check before
manually applying it from the console:

```sh
sudo /usr/sbin/nft -c -f lab/vulnerable.nft
sudo /usr/sbin/nft -f lab/vulnerable.nft
python3 -m http.server 3306 --bind 0.0.0.0
```

The HTTP listener simulates a TCP database endpoint; it is NOT a MySQL service.
Use a real database later if process/service-specific findings are demonstrated.
The scenario expects the named table not to exist. Revert the hypervisor snapshot
between runs; never append this to a production ruleset. Existing chains can
still affect reachability, so use a clean lab target. The input chain permits
ICMP/ICMPv6 to avoid breaking basic network control traffic.

## Opt-in live integration test

```powershell
$env:FWA_RUN_VM_TESTS = '1'
$env:FWA_HOSTS_FILE = (Resolve-Path config/hosts.local.json).Path
$env:FWA_HOST = 'db01'
python -m pytest -q tests/test_vm_integration.py
# Alternative if pytest is unavailable:
python -m unittest discover -s tests -p test_vm_integration.py -v
Remove-Item Env:FWA_RUN_VM_TESTS
```

This checks real inspection only, not detection accuracy, traffic blocking,
remediation or rollback. Record the OS/nft/OpenSSH versions, VM topology and
snapshot output when it is executed. Do not label fixture results as VM tests.

In later phases, test TCP from actual independent unauthorized and allowed
sources. A connection timeout alone cannot prove firewall blocking: compare
listener health, routing and successful allowed-source control probes. Test
lost SSH and client failure with the rollback timer, including agent crashes.
