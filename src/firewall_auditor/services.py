"""Parse numeric ss -lntup output; retain the raw output alongside it."""
from .transport import InspectionError


def endpoint(value: str) -> dict:
    try:
        address, port = value.rsplit(":", 1)
        if address.startswith("[") and address.endswith("]"):
            address = address[1:-1]
        number = None if port == "*" else int(port)
        if number is not None and not 0 <= number <= 65535:
            raise ValueError("Invalid port")
        return {"address": address, "port": number}
    except (ValueError, TypeError) as exc:
        raise InspectionError("Invalid ss endpoint") from exc


def parse_listeners(text: str) -> list[dict]:
    results = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("Netid "):
            continue
        fields = line.split(maxsplit=6)
        if len(fields) < 6 or fields[0] not in {"tcp", "udp"}:
            raise InspectionError("Unexpected ss listener row")
        try:
            recv_q, send_q = int(fields[2]), int(fields[3])
        except ValueError as exc:
            raise InspectionError("Invalid ss queue counts") from exc
        results.append({"protocol": fields[0], "state": fields[1],
                        "recv_q": recv_q, "send_q": send_q,
                        "local": endpoint(fields[4]), "peer": endpoint(fields[5]),
                        "process_metadata": fields[6] if len(fields) == 7 else None})
    return results
