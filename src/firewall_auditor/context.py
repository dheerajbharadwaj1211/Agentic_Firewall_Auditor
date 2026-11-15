"""Operator-supplied context, separate from untrusted VM metadata."""
from dataclasses import asdict, dataclass, field
import ipaddress
import json
from pathlib import Path


@dataclass(frozen=True)
class HostContext:
    role: str = "unknown"
    network_boundary: str = "unknown"
    allowed_clients: dict[str, list[str]] = field(default_factory=dict)
    public_services: list[int] = field(default_factory=list)
    management_ports: list[int] = field(default_factory=lambda: [22, 3389, 2375, 6443, 8006])
    user_subnets: list[str] = field(default_factory=list)

    def validate(self):
        if self.role not in {"unknown", "web", "application", "database", "mixed"}:
            raise ValueError("Unsupported host role")
        if self.network_boundary not in {"unknown", "virtualbox_nat", "internal", "public"}:
            raise ValueError("Unsupported network boundary")
        for ports in (self.public_services, self.management_ports):
            if not isinstance(ports, list) or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
                raise ValueError("Invalid service ports")
        if not isinstance(self.allowed_clients, dict):
            raise ValueError("allowed_clients must map port strings to CIDR lists")
        networks = list(self.user_subnets)
        for port, clients in self.allowed_clients.items():
            if not isinstance(port, str) or not port.isdecimal() or not 1 <= int(port) <= 65535 or not isinstance(clients, list):
                raise ValueError("Invalid allowed clients")
            networks.extend(clients)
        if any(not isinstance(n, str) for n in networks):
            raise ValueError("Networks must be CIDR strings")
        for n in networks:
            ipaddress.ip_network(n, strict=True)
        return self

    def to_dict(self):
        return asdict(self)


def load_context(path: str | None, host: str) -> HostContext:
    if path is None:
        return HostContext()
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or host not in data or not isinstance(data[host], dict):
        raise ValueError("Context must contain the selected host")
    return HostContext(**data[host]).validate()
