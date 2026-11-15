"""Conservative nft JSON normalization, not a firewall evaluation engine.

Missing selectors mean no explicit selector, NOT proof of public access.
Sets, jumps, connection tracking, NAT and unfamiliar expressions stay in raw
evidence and mark normalization incomplete. Rule order is preserved.
"""
import json
import ipaddress
from .models import Chain, Rule, Ruleset


class NftParseError(ValueError):
    pass


def parse_ruleset(text: str) -> Ruleset:
    try:
        raw = json.loads(text)
        if not isinstance(raw, dict) or not isinstance(raw.get("nftables"), list):
            raise ValueError("Expected an nftables array")
        chains = []
        for item in raw["nftables"]:
            if not isinstance(item, dict):
                raise ValueError("Invalid nftables entry")
            if "chain" in item:
                c = item["chain"]
                chains.append(Chain(c["family"], c["table"], c["name"],
                                    c.get("hook"), c.get("policy"), c.get("prio")))
        index = {(c.family, c.table, c.name): c for c in chains}
        rules = []
        warnings = []
        for item in raw["nftables"]:
            if "rule" not in item:
                if not set(item) <= {"chain", "table", "metainfo"}:
                    warnings.append("Non-rule objects retained only in raw ruleset")
                continue
            r = item["rule"]
            key = (r["family"], r["table"], r["chain"])
            if type(r["handle"]) is not int or r["handle"] < 0:
                raise ValueError("Invalid rule handle")
            expr = r["expr"]
            if not isinstance(expr, list) or any(not isinstance(e, dict) for e in expr):
                raise ValueError("Invalid expression array")
            c = index.get(key)
            direction = {"input": "inbound", "output": "outbound", "forward": "forward"}.get(
                c.hook if c else None, "unknown")
            selectors = {}
            unsupported = []
            action = "unknown"
            for e in expr:
                if len(e) != 1:
                    unsupported.append(e)
                    continue
                kind, value = next(iter(e.items()))
                if kind in {"accept", "drop", "reject"}:
                    if action != "unknown":
                        unsupported.append(e)
                    action = kind
                elif kind == "counter":
                    continue
                elif kind == "match" and isinstance(value, dict):
                    left = value.get("left", {})
                    right = value.get("right")
                    if not isinstance(left, dict) or value.get("op") != "==":
                        unsupported.append(e)
                        continue
                    field = None
                    protocol = None
                    if set(left) == {"payload"} and isinstance(left["payload"], dict):
                        p = left["payload"]
                        protocol = p.get("protocol")
                        field = {("ip", "saddr"): "source", ("ip6", "saddr"): "source",
                                 ("ip", "daddr"): "destination", ("ip6", "daddr"): "destination",
                                 ("tcp", "dport"): "destination_port",
                                 ("udp", "dport"): "destination_port"}.get((protocol, p.get("field")))
                    elif left == {"meta": {"key": "l4proto"}}:
                        field = "protocol"
                    if field in {"source", "destination"}:
                        try:
                            if isinstance(right, dict) and set(right) == {"prefix"}:
                                prefix = right["prefix"]
                                if set(prefix) != {"addr", "len"} or type(prefix["len"]) is not int:
                                    raise ValueError("Invalid prefix")
                                right = str(ipaddress.ip_network(f'{prefix["addr"]}/{prefix["len"]}', strict=True))
                            elif isinstance(right, str):
                                right = str(ipaddress.ip_network(right, strict=True)) if "/" in right else str(ipaddress.ip_address(right))
                            else:
                                raise ValueError("Unsupported address expression")
                            address = ipaddress.ip_network(right, strict=True)
                            if address.version != (6 if protocol == "ip6" else 4):
                                raise ValueError("Address family mismatch")
                        except (ValueError, KeyError, TypeError):
                            unsupported.append(e)
                            continue
                    # Other complex RHS values remain raw: no silent set/range expansion.
                    if field is None or not isinstance(right, (str, int)) or isinstance(right, bool) or field in selectors:
                        unsupported.append(e)
                        continue
                    if field == "destination_port" and (type(right) is not int or not 1 <= right <= 65535):
                        unsupported.append(e)
                        continue
                    if field == "destination_port":
                        if selectors.get("protocol", protocol) != protocol:
                            unsupported.append(e)
                        selectors["protocol"] = protocol
                    selectors[field] = right
                else:
                    unsupported.append(e)
            complete = not unsupported and c is not None and action != "unknown"
            rules.append(Rule(*key, r["handle"], direction, selectors.get("protocol"),
                              selectors.get("source"), selectors.get("destination"),
                              selectors.get("destination_port"), action, complete,
                              expr, unsupported, r.get("comment")))
        if any(not r.complete for r in rules):
            warnings.append("Incomplete normalization: do not infer effective reachability")
        return Ruleset(chains, rules, raw, warnings)
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise NftParseError("Invalid or unsupported nftables JSON structure") from exc
