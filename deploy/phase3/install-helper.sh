#!/bin/sh
# REVIEW: installs root helper, exact sudo rule and recovery service.
# Does NOT change nftables rules. Run only on the explicit TEST VM.
set -eu
if [ "$(id -u)" -ne 0 ]; then echo 'Run from a root console or sudo on the TEST VM only.' >&2; exit 1; fi
if [ "$#" -ne 2 ] || [ "$1" != '--ack-test-vm' ]; then
    echo 'Usage: sudo sh install-helper.sh --ack-test-vm SSH_USERNAME' >&2; exit 1
fi
operator_user=$2
case "$operator_user" in ''|root|*[!a-z0-9_-]*) echo 'Use a named non-root account.' >&2; exit 1;; esac
id "$operator_user" >/dev/null
if [ "$(id -u "$operator_user")" -eq 0 ]; then echo 'The operator must not be UID 0.' >&2; exit 1; fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
for binary in /usr/bin/python3 /usr/sbin/nft /usr/bin/systemd-run /usr/bin/systemctl /usr/sbin/visudo; do
    [ -x "$binary" ] || { echo "Missing required executable: $binary" >&2; exit 1; }
done
/usr/bin/python3 -I - <<'PY'
import json,stat
from pathlib import Path
p=Path('/var/lib/firewall-auditor')
if p.exists():
    info=p.lstat()
    if stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:
        raise SystemExit('Existing state is not trusted/private; review before installation.')
    for item in p.glob('*.json'):
        if json.loads(item.read_text()).get('phase') in {'armed','applied'}:
            raise SystemExit('Unconfirmed change exists. Recover before upgrading helper.')
PY
install -d -o root -g root -m 0755 /usr/local/libexec /usr/local/lib/firewall-auditor /usr/local/lib/firewall-auditor/firewall_auditor /etc/firewall-auditor
install -d -o root -g root -m 0700 /var/lib/firewall-auditor
for module in __init__.py phase3_policy.py phase3_helper.py; do
    install -o root -g root -m 0644 "$project_dir/src/firewall_auditor/$module" "/usr/local/lib/firewall-auditor/firewall_auditor/$module"
done
install -o root -g root -m 0755 "$script_dir/firewall-auditor-helper" /usr/local/libexec/firewall-auditor-helper
if [ ! -e /etc/firewall-auditor/policy.json ]; then
    install -o root -g root -m 0600 "$script_dir/policy.example.json" /etc/firewall-auditor/policy.json
else
    echo 'Preserving existing root policy. Review its allowlist before apply.'
fi
sudo_tmp=$(mktemp /etc/sudoers.d/.firewall-auditor.XXXXXX)
trap 'rm -f -- "$sudo_tmp"' EXIT HUP INT TERM
printf '%s ALL=(root) NOPASSWD: /usr/local/libexec/firewall-auditor-helper ""\n' "$operator_user" > "$sudo_tmp"
chmod 0440 "$sudo_tmp"
/usr/sbin/visudo -cf "$sudo_tmp"
if [ -e /etc/sudoers.d/firewall-auditor-helper ] && ! cmp -s "$sudo_tmp" /etc/sudoers.d/firewall-auditor-helper; then
    echo 'Existing helper sudo rule differs; refusing to overwrite it.' >&2; exit 1
fi
install -o root -g root -m 0440 "$sudo_tmp" /etc/sudoers.d/firewall-auditor-helper
/usr/sbin/visudo -c
install -o root -g root -m 0644 "$script_dir/firewall-auditor-recover.service" /etc/systemd/system/firewall-auditor-recover.service
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl enable firewall-auditor-recover.service
printf '%s\n' 'Helper installed. New installations have mutations DISABLED.' 'No nftables rules were changed. Review /etc/firewall-auditor/policy.json and the lab guide.'
