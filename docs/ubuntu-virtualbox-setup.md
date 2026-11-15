# Ubuntu VirtualBox VM: Phase 1 connection setup

Project: `D:\codex\firewall\firewall-auditor`.
Target alias: `ubuntu-vm`; SSH: `viper@127.0.0.1:2222`.
VirtualBox forwards Windows port 2222 to the guest SSH port 22. Firewall
rules inside the guest refer to guest ports, not the Windows forwarding port.
Do not expose the forwarding rule on all host interfaces; keep 127.0.0.1.

The existing code was updated in place. No firewall modification tool exists.
`config/hosts.local.json` stores connection metadata and key paths, never passwords
or private-key material. It is gitignored. Public host keys already exist in the
Windows known_hosts file; strict checking remains enabled. No new host key was
silently trusted or enrolled.

## One-time key authentication setup

In normal Windows PowerShell, generate a dedicated key and choose a passphrase:

```powershell
ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\id_ed25519_firewall" -C "firewall-auditor"
```

Do not overwrite an existing key. The private key stays outside the project,
protected by its passphrase and Windows account permissions.

In PowerShell as Administrator, enable the Windows OpenSSH authentication agent:

```powershell
Set-Service ssh-agent -StartupType Manual
Start-Service ssh-agent
```

In normal PowerShell, load the key (enter its passphrase locally), then append
ONLY the public key to the VM account (enter the VM password locally):

```powershell
ssh-add "$env:USERPROFILE\.ssh\id_ed25519_firewall"
Get-Content "$env:USERPROFILE\.ssh\id_ed25519_firewall.pub" |
  ssh -p 2222 viper@127.0.0.1 'umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys'
```

If host verification fails, stop and compare its fingerprint against the VM
console; do not disable checking. For a new VM, the console command is
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.

Test key-only authentication:

```powershell
ssh -F none -o BatchMode=yes -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -i "$env:USERPROFILE\.ssh\id_ed25519_firewall" -p 2222 viper@127.0.0.1 /usr/bin/uname -srm
```

The project explicitly opts in to the agent with `use_agent: true`; other host
configurations default to no agent. Agent forwarding remains disabled, and
IdentitiesOnly limits authentication to the configured identity. Do not paste
passwords, private keys or passphrases into chat, source, logs or JSON.

## Narrow read-only sudo access

On the VM console or an interactive SSH session, inspect the installed nft path:

```sh
command -v nft
sudo visudo -f /etc/sudoers.d/firewall-auditor-read
```

For `/usr/sbin/nft`, put exactly:

```sudoers
viper ALL=(root) NOPASSWD: /usr/sbin/nft -j list ruleset
```

Then validate the sudoers configuration and test noninteractive reading:

```sh
sudo chmod 0440 /etc/sudoers.d/firewall-auditor-read
sudo visudo -c
sudo -n /usr/sbin/nft -j list ruleset
```

Use root ownership for this file. This grants one exact read-only command,
not `nft *`, an arbitrary command, a root shell, or unrestricted NOPASSWD sudo.
The application uses `sudo -n` so it fails rather than hanging on a prompt.
Only the user should make this authentication/permission setup change; no
firewall changes are required. If nft lives elsewhere, update both the trusted
fixed command and sudo rule consistently after verifying the actual path.

`ss -lntup` runs as viper. Linux may hide process names/PIDs belonging to other
users; this is recorded as incomplete process metadata rather than requesting
unrestricted root access. Listener addresses and numeric ports are still usable.

## Run read-only inspection and tests

```powershell
Set-Location 'D:\codex\firewall\firewall-auditor'
$env:PYTHONPATH = "$PWD\src;D:\codex\firewall\work\python_libs"
python -m firewall_auditor.cli inspect --hosts config/hosts.local.json --host ubuntu-vm
python -m pytest -q
$env:FWA_RUN_VM_TESTS = '1'
$env:FWA_HOSTS_FILE = "$PWD\config\hosts.local.json"
$env:FWA_HOST = 'ubuntu-vm'
python -m pytest -q tests/test_vm_integration.py
Remove-Item Env:FWA_RUN_VM_TESTS
```

Fixed commands now include `sudo -n /usr/sbin/nft -j list ruleset`,
`/usr/bin/ss -lntup`, `/usr/sbin/ip -j addr`, `/usr/sbin/ip -j route`,
IPv6 routing and OS/nft version checks. The IPv4 command returns the default
routing table as requested; other policy routing tables are not collected.
All observations remain untrusted. Rules and listeners are normalized, and
interfaces/routes use the native iproute2 JSON structure. Source data is retained.

Authentication failure blocks all remote results. No firewall state or normalized
real result may be claimed until an authenticated read succeeds. Phase 2 stays
blocked until the full real-VM inspection passes.
