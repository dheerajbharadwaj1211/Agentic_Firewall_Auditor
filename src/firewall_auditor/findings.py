"""Evidence-grounded candidate findings; not an nft packet-flow simulator.

Only supported explicit accept rules or empty accept-policy input chains provide
candidate paths. Earlier drops, additional chains, NAT and external boundaries
can still prevent traffic. Every finding explicitly retains that uncertainty.
"""
import hashlib
import ipaddress
import json
from .context import HostContext


def _network(source, family):
    if source is None:
        return ipaddress.ip_network("::/0" if family == "ip6" else "0.0.0.0/0")
    try:
        return ipaddress.ip_network(source, strict=True)
    except (ValueError, TypeError):
        return None


def _nonlocal_listener(listener):
    address = listener["local"]["address"].split("%", 1)[0]
    if address == "*":
        return True
    try:
        ip = ipaddress.ip_address(address)
        return not ip.is_loopback and not ip.is_link_local
    except ValueError:
        return False


def analyze(host: str, observations: dict, context: HostContext) -> dict:
    context.validate()
    required = {"get_firewall_rules", "get_listening_services", "get_network_interfaces",
                "get_routes", "get_ipv6_routes", "get_host_information", "get_firewall_status"}
    missing = sorted(required - observations.keys())
    if missing:
        raise ValueError("Collect all required observations before analysis: " + ", ".join(missing))
    firewall = observations["get_firewall_rules"]["data"]
    listeners = observations["get_listening_services"]["data"]["listeners"]
    findings = []
    warnings = list(firewall.get("warnings", []))
    warnings.append("Configuration analysis only: external reachability and effective packet flow are not tested.")
    if context.role == "unknown":
        warnings.append("Host role and required application dependencies need operator confirmation.")
    if context.network_boundary == "virtualbox_nat":
        warnings.append("VirtualBox NAT is a separate boundary; broad guest rules do not prove Internet exposure.")

    def evidence(tool, pointer):
        return {"observation_id": observations[tool]["evidence_id"], "pointer": pointer}

    def add(category, title, severity, refs, rule_ids, impact, recommendation, port=None):
        identity = json.dumps([category, rule_ids, refs, port], sort_keys=True)
        findings.append({"id": "F-" + hashlib.sha256(identity.encode()).hexdigest()[:12],
                         "host": host, "category": category, "title": title,
                         "severity": severity, "confidence": "configuration_candidate",
                         "affected_rules": rule_ids, "port": port, "evidence": refs,
                         "impact": impact, "recommendation": recommendation,
                         "verification_plan": ["Confirm listener, route, chain order and external network boundaries.",
                             "From a configured unauthorized client, test that unwanted traffic is blocked.",
                             "From an approved client, test that required application and SSH traffic still works."],
                         "internet_reachability": "not_tested", "remediation_applied": False})

    chains = firewall["chains"]
    rules = firewall["rules"]
    candidates = []
    if not any(c["hook"] == "input" and c["family"] in {"ip", "ip6", "inet"} for c in chains):
        add("missing_input_filter", "No nftables input base chain observed", "HIGH",
            [evidence("get_firewall_rules", "/data/chains")], [],
            "No nftables input hook is present in the observed ruleset. Other firewall implementations or external controls may still exist.",
            "Confirm the intended firewall owner and establish an approved input policy in a later change phase.")
    for ci, chain in enumerate(chains):
        if chain["hook"] != "input" or chain["family"] not in {"ip", "ip6", "inet"}:
            continue
        key = (chain["family"], chain["table"], chain["name"])
        members = [(i, r) for i, r in enumerate(rules) if (r["family"], r["table"], r["chain"]) == key]
        if chain["policy"] == "accept" and not members:
            ref = evidence("get_firewall_rules", f"/data/chains/{ci}")
            add("permissive_input_policy", "Empty input chain defaults to accept", "HIGH", [ref], [],
                "This input chain provides no packet restrictions; other chains or network boundaries may still filter traffic.",
                "Define an approved least-privilege input policy while preserving management and required services.")
            candidates.append((None, chain["family"], None, None, [ref], []))
    for ri, rule in enumerate(rules):
        if rule["direction"] != "inbound" or rule["action"] != "accept" or not rule["complete"]:
            continue
        if rule["family"] not in {"ip", "ip6", "inet"}:
            continue
        net = _network(rule["source"], rule["family"])
        if net is None:
            warnings.append("Unresolved source address; candidate skipped.")
            continue
        rid = f'{rule["family"]}/{rule["table"]}/{rule["chain"]}#{rule["handle"]}'
        refs = [evidence("get_firewall_rules", f"/data/rules/{ri}")]
        if net.prefixlen == 0 and rule["destination"] is None and rule["destination_port"] is None and rule["protocol"] is None:
            add("any_to_any", "Unrestricted inbound accept rule", "HIGH", refs, [rid],
                "This rule accepts unrestricted inbound traffic if reached in rule evaluation.",
                "Replace this rule with explicitly approved protocols, destinations and client ranges.")
        candidate_family = rule["family"]
        if candidate_family == "inet" and rule["source"] is not None:
            candidate_family = "ip6" if net.version == 6 else "ip"
        candidates.append((net, candidate_family, rule["protocol"], rule["destination_port"], refs, [rid]))

    seen = set()
    for li, listener in enumerate(listeners):
        if not _nonlocal_listener(listener):
            continue
        port = listener["local"]["port"]
        if port is None:
            continue
        local_address = listener["local"]["address"].split("%", 1)[0]
        local_version = None if local_address == "*" else ipaddress.ip_address(local_address).version
        for net, family, protocol, rule_port, refs, rule_ids in candidates:
            if family == "ip" and local_version == 6 or family == "ip6" and local_version == 4:
                continue
            if net is not None and local_version is not None and net.version != local_version:
                # An inet rule with no source applies to both versions.
                if not (family == "inet" and net.prefixlen == 0 and net.version == 4):
                    continue
            if protocol is not None and protocol != listener["protocol"] or rule_port is not None and rule_port != port:
                continue
            # A destination-constrained rule may not match this particular listener.
            if rule_ids:
                matching = next(r for r in rules if f'{r["family"]}/{r["table"]}/{r["chain"]}#{r["handle"]}' == rule_ids[0])
                if matching["destination"] is not None:
                    warnings.append("Destination-constrained rule requires manual path evaluation.")
                    continue
            lref = refs + [evidence("get_listening_services", f"/data/listeners/{li}")]
            broad = net is None or net.prefixlen == 0
            category = None
            title = None
            if broad and port in {3306, 5432} and listener["protocol"] == "tcp" and port not in context.public_services:
                category, title = "database_exposure", "Broad database-port permission with a non-loopback listener"
            elif broad and port == 22 and listener["protocol"] == "tcp" and port not in context.public_services:
                category, title = "ssh_exposure", "Broad SSH permission with a non-loopback listener"
            elif broad and port in context.management_ports and port not in context.public_services:
                category, title = "management_exposure", "Broad management-port permission with a non-loopback listener"
            if category and (category, port, tuple(rule_ids)) not in seen:
                seen.add((category, port, tuple(rule_ids)))
                add(category, title, "HIGH", lref, rule_ids,
                    "A supported accept path and listening socket create a configuration risk; actual unauthorized reachability is unconfirmed.",
                    "Restrict this service to operator-approved clients after validating dependencies.", port)
            clients = [ipaddress.ip_network(n) for n in context.allowed_clients.get(str(port), [])]
            if net is not None and clients and any(n.version == net.version for n in clients):
                collapsed = list(ipaddress.collapse_addresses(n for n in clients if n.version == net.version))
                authorized = any(net.subnet_of(n) for n in collapsed)
                if not authorized and ("broad_source", port, tuple(rule_ids)) not in seen:
                    seen.add(("broad_source", port, tuple(rule_ids)))
                    add("broad_source", "Source range exceeds declared service clients", "MEDIUM", lref, rule_ids,
                        "This rule's source is not contained within any declared allowed-client range.",
                        "Review the source range against operator-declared service clients; use a scoped proposal in Phase 3.", port)
            if context.role == "database" and port in {3306, 5432}:
                users = [ipaddress.ip_network(n) for n in context.user_subnets]
                overlap = bool(users) if net is None else any(n.version == net.version and n.overlaps(net) for n in users)
                if overlap and ("segmentation", port, tuple(rule_ids)) not in seen:
                    seen.add(("segmentation", port, tuple(rule_ids)))
                    add("segmentation", "Declared user subnet overlaps database accept path", "HIGH", lref, rule_ids,
                        "The configured source overlaps an operator-declared user network; other rules may still block that traffic.",
                        "Review segmentation so only declared application clients can reach the database.", port)
    return {"findings": findings, "coverage_notes": sorted(set(warnings)),
            "context": context.to_dict(), "connectivity_tested": False,
            "effective_packet_flow_evaluated": False}
