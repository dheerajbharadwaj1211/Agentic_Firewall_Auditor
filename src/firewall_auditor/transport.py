"""Fixed-command OpenSSH transport. No caller-supplied shell commands."""
from dataclasses import dataclass
from enum import Enum
import ipaddress
import json
from pathlib import Path
import re
import subprocess


class InspectionError(RuntimeError):
    pass


class Operation(str, Enum):
    RULES = "get_firewall_rules"
    VERSION = "get_firewall_status"
    SERVICES = "get_listening_services"
    INTERFACES = "get_network_interfaces"
    ROUTES = "get_routes"
    ROUTES6 = "get_ipv6_routes"
    HOST = "get_host_information"


COMMANDS = {
    Operation.RULES: "sudo -n /usr/sbin/nft -j list ruleset",
    Operation.VERSION: "/usr/sbin/nft --version",
    Operation.SERVICES: "/usr/bin/ss -lntup",
    Operation.INTERFACES: "/usr/sbin/ip -j addr",
    Operation.ROUTES: "/usr/sbin/ip -j route",
    Operation.ROUTES6: "/usr/sbin/ip -6 -j route show table all",
    Operation.HOST: "/usr/bin/uname -srm",
}
MAX_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class Host:
    name: str
    address: str
    username: str
    identity_file: str
    known_hosts_file: str
    port: int = 22
    test_vm: bool = False
    use_agent: bool = False

    def validate(self):
        if type(self.use_agent) is not bool:
            raise ValueError("use_agent must be a boolean")
        if self.test_vm is not True:
            raise ValueError("Host must be explicitly designated a test VM")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.name):
            raise ValueError("Invalid host alias")
        ipaddress.ip_address(self.address)  # Literal IP only; no SSH aliases/options.
        if "%" in self.address:
            raise ValueError("Scoped IPv6 addresses are not supported")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.username) or self.username == "root":
            raise ValueError("Use a named non-root account")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("Invalid SSH port")
        for p in (self.identity_file, self.known_hosts_file):
            if not isinstance(p, str) or any(c in p for c in '\r\n\x00"') or not Path(p).is_file():
                raise ValueError("Identity and known-hosts files must exist and have safe paths")


def load_hosts(path: str) -> dict[str, Host]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list) or not data:
        raise ValueError("Expected a nonempty array of hosts")
    result = {}
    for entry in data:
        host = Host(**entry)
        host.validate()
        if host.name in result:
            raise ValueError("Duplicate host alias")
        result[host.name] = host
    return result


class SSHTransport:
    def __init__(self, timeout: int = 15):
        if type(timeout) is not int or not 1 <= timeout <= 120:
            raise ValueError("Timeout must be 1..120 seconds")
        self.timeout = timeout

    def read(self, host: Host, operation: Operation) -> str:
        host.validate()
        if not isinstance(operation, Operation):
            raise ValueError("Only enumerated inspection operations are allowed")
        # Ignore ambient SSH config. Agent use requires explicit operator opt-in.
        # IdentitiesOnly binds agent authentication to the configured key; -a
        # prevents forwarding the agent to the remote host.
        argv = ["ssh", "-F", "none", "-T", "-a", "-x", "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes",
                "-o", "ClearAllForwardings=yes",
                "-o", "ControlMaster=no", "-o", "ControlPath=none",
                "-o", "PermitLocalCommand=no", "-o", "ProxyCommand=none",
                "-o", "GlobalKnownHostsFile=none", "-o", "UpdateHostKeys=no",
                "-o", f'UserKnownHostsFile="{Path(host.known_hosts_file).resolve()}"',
                "-o", f"ConnectTimeout={self.timeout}", "-i", str(Path(host.identity_file).resolve()),
                "-p", str(host.port), "-l", host.username, host.address, COMMANDS[operation]]
        if not host.use_agent:
            argv[3:3] = ["-o", "IdentityAgent=none"]
        # Read incrementally: remote output cannot fill RAM or an unbounded temp file.
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, shell=False)
            import threading
            exceeded = threading.Event()
            chunks = []
            def drain(stream, collect):
                count = 0
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        return
                    count += len(chunk)
                    if count > MAX_BYTES:
                        exceeded.set()
                        proc.kill()
                        return
                    if collect:
                        chunks.append(chunk)
            readers = [threading.Thread(target=drain, args=(proc.stdout, True), daemon=True),
                       threading.Thread(target=drain, args=(proc.stderr, False), daemon=True)]
            for reader in readers:
                reader.start()
            try:
                proc.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired as exc:
                proc.kill()
                proc.wait()
                raise InspectionError("SSH inspection timed out") from exc
            finally:
                for reader in readers:
                    reader.join(timeout=2)
                proc.stdout.close()
                proc.stderr.close()
            if exceeded.is_set():
                raise InspectionError("SSH result exceeds size limit")
            if proc.returncode:
                # Remote stderr is untrusted and may include sensitive details.
                raise InspectionError(f"SSH inspection failed (exit {proc.returncode}); check host key, key access and sudo rights")
            return b"".join(chunks).decode("utf-8", errors="strict")
        except (OSError, UnicodeError) as exc:
            raise InspectionError("SSH executable unavailable or invalid UTF-8 output") from exc
