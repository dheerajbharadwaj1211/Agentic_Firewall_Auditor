"""Host allowlist and read-only tool dispatch; remote content stays untrusted."""
from dataclasses import asdict
from datetime import datetime, timezone
import json
from .services import parse_listeners
from .nftables import parse_ruleset, NftParseError
from .transport import Host, Operation, SSHTransport, InspectionError


class Inspector:
    def __init__(self, hosts: dict[str, Host], transport=None):
        self._hosts = dict(hosts)
        self._transport = transport or SSHTransport()

    def call(self, tool: str, host: str) -> dict:
        if not isinstance(tool, str) or not isinstance(host, str) or host not in self._hosts:
            raise ValueError("Unconfigured target or invalid tool")
        operation = Operation(tool)  # Mutation names fail closed.
        text = self._transport.read(self._hosts[host], operation)
        if operation == Operation.RULES:
            try:
                value = asdict(parse_ruleset(text))
            except NftParseError as exc:
                raise InspectionError("Invalid nftables inspection JSON") from exc
        elif operation == Operation.SERVICES:
            value = {"listeners": parse_listeners(text), "text": text,
                     "process_metadata_may_be_incomplete": True}
        elif operation in {Operation.INTERFACES, Operation.ROUTES, Operation.ROUTES6}:
            try:
                value = json.loads(text)
                if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
                    raise ValueError("Expected array")
            except (ValueError, RecursionError) as exc:
                raise InspectionError("Invalid network inspection JSON") from exc
        else:
            value = {"text": text}
        return {"host": host, "tool": tool, "observed_at": datetime.now(timezone.utc).isoformat(),
                "untrusted_observation": True, "data": value}

    def snapshot(self, host: str) -> dict:
        # Errors abort rather than representing missing observations as empty/safe.
        return {"mode": "real_vm_read_only", "observations": [self.call(op.value, host) for op in Operation]}
