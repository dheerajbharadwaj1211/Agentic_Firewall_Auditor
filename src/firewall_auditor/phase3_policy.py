"""Shared deterministic policy installed root-owned on the VM as well as locally.

Scope: narrow one supported IPv4/IPv6 input TCP accept rule. Never modify SSH,
chain policy, tables, other ports, sets, jumps, or arbitrary command strings.
"""
from copy import deepcopy
import hashlib
import ipaddress
import json
import re
import time
import uuid


class ChangeDenied(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def fingerprint(ruleset):
    """Ignore export metadata and changing packet/byte counters, not rule semantics."""
    def clean(value):
        if isinstance(value,list): return [clean(v) for v in value]
        if isinstance(value,dict):
            result={}
            for key,item in value.items():
                if key=='metainfo':continue
                if key=='counter' and isinstance(item,dict):
                    item={k:v for k,v in item.items() if k not in {'packets','bytes'}}
                result[key]=clean(item)
            return result
        return value
    if not isinstance(ruleset,dict) or not isinstance(ruleset.get('nftables'),list):
        raise ChangeDenied('Invalid nft ruleset')
    entries=[clean(e) for e in ruleset['nftables'] if not isinstance(e,dict) or 'metainfo' not in e]
    return digest({'nftables':entries})


def valid_id(value):
    if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{32}',value):
        raise ChangeDenied('Invalid change ID')
    return value


def validate_probe_plan(plan, port, new_source):
    if not isinstance(plan,dict) or set(plan)!={'destination','port','source_nat','checks'}:
        raise ChangeDenied('Invalid verification plan fields')
    if plan['source_nat'] is not False or type(plan['port']) is not int or plan['port']!=port:
        raise ChangeDenied('Verification requires the exact service port and explicitly no source NAT')
    try:
        dest=ipaddress.ip_address(plan['destination'])
    except ValueError as exc:raise ChangeDenied('Invalid probe destination') from exc
    if dest.is_loopback or dest.is_unspecified or dest.is_multicast:
        raise ChangeDenied('Probe destination must be the real unicast guest address')
    net=ipaddress.ip_network(new_source,strict=True)
    if dest.version!=net.version:raise ChangeDenied('Probe family must match restricted source family')
    checks=plan['checks']
    if not isinstance(checks,list) or not 2<=len(checks)<=8:
        raise ChangeDenied('Require 2..8 configured verification sources')
    aliases=set();addresses=set();kinds=set()
    for check in checks:
        if not isinstance(check,dict) or set(check)!={'host','source_ip','expect'}:
            raise ChangeDenied('Invalid verification source fields')
        if not isinstance(check['host'],str) or not re.fullmatch('[A-Za-z0-9_-]{1,64}',check['host']):
            raise ChangeDenied('Invalid probe host alias')
        try:address=ipaddress.ip_address(check['source_ip'])
        except ValueError as exc:raise ChangeDenied('Invalid probe source address') from exc
        if address.version!=net.version or address.is_unspecified or address.is_loopback or address.is_multicast:
            raise ChangeDenied('Invalid probe source family or scope')
        if check['host'] in aliases or str(address) in addresses:
            raise ChangeDenied('Verification sources must be distinct')
        if check['expect'] not in {'allowed','denied'}:
            raise ChangeDenied('Invalid verification expectation')
        if (address in net)!=(check['expect']=='allowed'):
            raise ChangeDenied('Allowed/denied sources must agree with proposed restriction')
        aliases.add(check['host']);addresses.add(str(address));kinds.add(check['expect'])
    if kinds!={'allowed','denied'}:raise ChangeDenied('Require both legitimate and unauthorized source probes')
    return deepcopy(plan)


def locate(ruleset, target):
    if not isinstance(target,dict) or set(target)!={'family','table','chain','handle'}:
        raise ChangeDenied('Invalid target rule locator')
    if target['family'] not in {'ip','ip6'}:
        raise ChangeDenied('Initial remediation requires an explicit ip or ip6 family; inet is analysis-only')
    for key in ('table','chain'):
        if not isinstance(target[key],str) or not re.fullmatch('[A-Za-z_][A-Za-z0-9_-]{0,63}',target[key]):
            raise ChangeDenied('Unsupported nft table/chain name')
    if type(target['handle']) is not int or target['handle']<=0:
        raise ChangeDenied('Invalid rule handle')
    matching=[];chains=[]
    for entry in ruleset['nftables']:
        if not isinstance(entry,dict):raise ChangeDenied('Invalid nft entry')
        rule=entry.get('rule')
        if rule and all(rule.get(k)==v for k,v in target.items()):matching.append(rule)
        chain=entry.get('chain')
        if chain and chain.get('family')==target['family'] and chain.get('table')==target['table'] and chain.get('name')==target['chain']:
            chains.append(chain)
    if len(matching)!=1 or len(chains)!=1 or chains[0].get('hook')!='input' or chains[0].get('type')!='filter' or chains[0].get('policy')!='drop':
        raise ChangeDenied('Target must be a unique rule in a default-drop input filter base chain')
    return deepcopy(matching[0])


def restricted_rule(old, new_source):
    try:net=ipaddress.ip_network(new_source,strict=True)
    except (ValueError,TypeError) as exc:raise ChangeDenied('New source must be canonical CIDR') from exc
    version=6 if old['family']=='ip6' else 4
    if net.version!=version or net.prefixlen==0 or net.network_address.is_loopback or net.is_multicast:
        raise ChangeDenied('New source must be a scoped unicast range of the same address family')
    if not set(old)<={'family','table','chain','handle','expr','comment'}:
        raise ChangeDenied('Unsupported top-level rule attributes')
    expressions=old.get('expr')
    if not isinstance(expressions,list) or not 2<=len(expressions)<=6:
        raise ChangeDenied('Unsupported target expressions')
    port=None;source=None;source_index=None;accepts=0;counter_seen=False;protocol_seen=False
    for i,expression in enumerate(expressions):
        if not isinstance(expression,dict) or len(expression)!=1:
            raise ChangeDenied('Unsupported expression')
        kind,value=next(iter(expression.items()))
        if kind=='accept' and value is None and i==len(expressions)-1:
            accepts+=1;continue
        if kind=='counter' and not counter_seen and (value is None or isinstance(value,dict) and set(value)<={'packets','bytes'}):
            counter_seen=True;continue
        if kind!='match' or not isinstance(value,dict) or set(value)!={'op','left','right'} or value['op']!='==':
            raise ChangeDenied('Unsupported rule constraint or verdict')
        left=value['left'];right=value['right']
        if left=={'meta':{'key':'l4proto'}} and right=='tcp' and not protocol_seen:
            protocol_seen=True;continue
        if left=={'payload':{'protocol':'tcp','field':'dport'}} and port is None and type(right) is int and 1<=right<=65535:
            port=right;continue
        if left=={'payload':{'protocol':old['family'],'field':'saddr'}} and source is None:
            try:
                if isinstance(right,str):source=ipaddress.ip_network(right,strict=True)
                elif isinstance(right,dict) and set(right)=={'prefix'} and set(right['prefix'])=={'addr','len'} and type(right['prefix']['len']) is int:
                    source=ipaddress.ip_network(str(right['prefix']['addr'])+'/'+str(right['prefix']['len']),strict=True)
                else:raise ValueError('Unsupported source')
            except (ValueError,TypeError,KeyError) as exc:raise ChangeDenied('Unsupported source expression') from exc
            source_index=i;continue
        raise ChangeDenied('Rule contains unsupported selectors, sets or control flow')
    if accepts!=1 or port is None or port in {22,3389}:
        raise ChangeDenied('Require a single explicit TCP port accept rule; SSH/RDP mutation is prohibited')
    if source is None:source=ipaddress.ip_network('::/0' if version==6 else '0.0.0.0/0')
    if source.version!=version or not net.subnet_of(source) or net==source:
        raise ChangeDenied('New source must be strictly narrower than the original source')
    new=deepcopy(old)
    if net.prefixlen==net.max_prefixlen:right=str(net.network_address)
    else:right={'prefix':{'addr':str(net.network_address),'len':net.prefixlen}}
    constraint={'match':{'op':'==','left':{'payload':{'protocol':old['family'],'field':'saddr'}},'right':right}}
    if source_index is None:new['expr'].insert(0,constraint)
    else:new['expr'][source_index]=constraint
    return new,port,str(source)


def replace_in_snapshot(raw, target, replacement):
    result=deepcopy(raw)
    found=False
    for item in result['nftables']:
        rule=item.get('rule')
        if rule and all(rule.get(k)==v for k,v in target.items()):
            if found:raise ChangeDenied('Duplicate target rule')
            item['rule']=deepcopy(replacement);found=True
    if not found:raise ChangeDenied('Target rule disappeared')
    return result


def make_proposal(raw, host, target, new_source, verification, now=None, baseline=None):
    now=time.time() if now is None else now
    if not isinstance(host,str) or not re.fullmatch('[A-Za-z0-9_-]{1,64}',host):raise ChangeDenied('Invalid target host')
    old=locate(raw,target)
    new,port,old_source=restricted_rule(old,new_source)
    plan=validate_probe_plan(verification,port,new_source)
    if host in {c['host'] for c in plan['checks']}:raise ChangeDenied('Probes must run on independent source VMs')
    proposal={'schema_version':1,'change_id':uuid.uuid4().hex,'host':host,'target':deepcopy(target),
              'before_fingerprint':fingerprint(raw),'before_rule':old,'after_rule':new,
              'old_source':old_source,'new_source':str(ipaddress.ip_network(new_source,strict=True)),
              'port':port,'verification':plan,'created_at':now,'expires_at':now+600,
              'operation':'restrict_source','baseline':deepcopy(baseline)}
    return proposal


def validate_proposal(raw, proposal, policy=None, now=None, require_baseline=True):
    fields={'schema_version','change_id','host','target','before_fingerprint','before_rule','after_rule','old_source',
            'new_source','port','verification','created_at','expires_at','operation','baseline'}
    now=time.time() if now is None else now
    if not isinstance(proposal,dict) or set(proposal)!=fields or proposal['schema_version']!=1 or proposal['operation']!='restrict_source':
        raise ChangeDenied('Invalid proposal schema or forbidden operation')
    valid_id(proposal['change_id'])
    if type(proposal['created_at']) not in {int,float} or type(proposal['expires_at']) not in {int,float} or not proposal['created_at']<=now<proposal['expires_at']<=proposal['created_at']+600:
        raise ChangeDenied('Proposal expired or has invalid lifetime')
    if fingerprint(raw)!=proposal['before_fingerprint']:
        raise ChangeDenied('Ruleset changed since proposal; fresh review required')
    old=locate(raw,proposal['target']);new,port,old_source=restricted_rule(old,proposal['new_source'])
    if fingerprint({'nftables':[{'rule':old}]})!=fingerprint({'nftables':[{'rule':proposal['before_rule']}]}) or fingerprint({'nftables':[{'rule':new}]})!=fingerprint({'nftables':[{'rule':proposal['after_rule']}]}) or port!=proposal['port'] or old_source!=proposal['old_source']:
        raise ChangeDenied('Proposal differs from deterministic permitted replacement')
    validate_probe_plan(proposal['verification'],port,proposal['new_source'])
    if require_baseline:validate_results(proposal['verification'],proposal['baseline'],before=True)
    if proposal['host'] in {c['host'] for c in proposal['verification']['checks']}:
        raise ChangeDenied('Verification cannot originate on the target')
    if policy is not None:
        if policy.get('enabled') is not True or policy.get('test_vm') is not True or policy.get('exclusive_firewall_owner') is not True:
            raise ChangeDenied('Root policy does not authorize this test VM for mutation')
        if proposal['host']!=policy.get('host_alias'):
            raise ChangeDenied('Proposal host differs from root-owned target identity')
        key=proposal['target']['family']+':'+proposal['target']['table']+':'+proposal['target']['chain']
        if key not in policy.get('allowed_chains',[]):raise ChangeDenied('Chain is outside root-owned allowlist')
        if proposal['verification']['destination'] not in policy.get('target_addresses',[]):
            raise ChangeDenied('Probe destination differs from root-owned target addresses')
        networks=policy.get('allowed_sources',{}).get(str(port),[])
        net=ipaddress.ip_network(proposal['new_source'])
        if not any(net.version==n.version and net.subnet_of(n) for n in map(ipaddress.ip_network,networks)):
            raise ChangeDenied('Source/port combination is outside root-owned allowlist')
    return new


def nft_replace(rule):
    # Only fields valid for a replacement are emitted; comments stay data, never shell.
    result={k:deepcopy(v) for k,v in rule.items() if k in {'family','table','chain','handle','expr','comment'}}
    return {'nftables':[{'replace':{'rule':result}}]}


def validate_results(plan, result, before=False):
    if not isinstance(result,dict) or set(result)!={'management_ssh','checks'} or result['management_ssh'] is not True:
        raise ChangeDenied('Management SSH must be verified successfully')
    checks=result['checks']
    if not isinstance(checks,list) or len(checks)!=len(plan['checks']):
        raise ChangeDenied('Missing verification source results')
    indexed={}
    for row in checks:
        if not isinstance(row,dict) or set(row)!={'host','source_ip','destination','port','status'} or row['host'] in indexed:
            raise ChangeDenied('Invalid or duplicate verification result')
        indexed[row['host']]=row
    for check in plan['checks']:
        row=indexed.get(check['host'])
        if row is None or row['destination']!=plan['destination'] or row['port']!=plan['port']:
            raise ChangeDenied('Verification result does not match the approved endpoint')
        try:source=ipaddress.ip_address(row['source_ip'])
        except (ValueError,TypeError) as exc:raise ChangeDenied('Unknown probe source identity') from exc
        if source!=ipaddress.ip_address(check['source_ip']):raise ChangeDenied('Probe source differs from trusted topology')
        accepted={'connected'} if before or check['expect']=='allowed' else {'timeout','refused'}
        if row['status'] not in accepted:
            raise ChangeDenied('Connectivity verification failed or was inconclusive')
    return True
