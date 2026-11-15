"""Fixed-command SSH channel for the approved helper and configured TCP probes.

The Gemini tool registry does not expose this channel. No caller can provide a
shell command or a Python program; the probe program is generated here only.
"""
import ipaddress
import json
import subprocess
import threading
from .phase3_policy import canonical, ChangeDenied
from .transport import Host, SSHTransport, Operation, InspectionError

HELPER='sudo -n /usr/local/libexec/firewall-auditor-helper'
PROBE='/usr/bin/python3 -I -'


def ssh_arguments(host,command):
    host.validate()
    from pathlib import Path
    argv=['ssh','-F','none','-T','-a','-x','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
          '-o','IdentitiesOnly=yes','-o','ClearAllForwardings=yes','-o','ControlMaster=no','-o','ControlPath=none',
          '-o','PermitLocalCommand=no','-o','ProxyCommand=none','-o','GlobalKnownHostsFile=none','-o','UpdateHostKeys=no',
          '-o',f'UserKnownHostsFile="{Path(host.known_hosts_file).resolve()}"','-o','ConnectTimeout=10',
          '-i',str(Path(host.identity_file).resolve()),'-p',str(host.port),'-l',host.username,host.address,command]
    if not host.use_agent:argv[3:3]=['-o','IdentityAgent=none']
    return argv


class ControlSSH:
    def exchange(self,host,kind,payload):
        if kind not in {'helper','probe'} or not isinstance(payload,bytes) or len(payload)>65536:
            raise ChangeDenied('Invalid control request')
        argv=ssh_arguments(host,HELPER if kind=='helper' else PROBE)
        proc=None
        try:
            proc=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False)
            chunks=[];errors=[];too_large=threading.Event()
            def drain(stream,collect):
                total=0
                try:
                    while True:
                        chunk=stream.read(65536)
                        if not chunk:return
                        total+=len(chunk)
                        if total>4*1024*1024:
                            too_large.set();proc.kill();return
                        if collect:chunks.append(chunk)
                except Exception:errors.append(True)
            def send():
                try:proc.stdin.write(payload);proc.stdin.close()
                except Exception:errors.append(True)
            threads=[threading.Thread(target=drain,args=(proc.stdout,True),daemon=True),
                     threading.Thread(target=drain,args=(proc.stderr,False),daemon=True),
                     threading.Thread(target=send,daemon=True)]
            for thread in threads:thread.start()
            try:proc.wait(timeout=45)
            except subprocess.TimeoutExpired as exc:
                proc.kill();proc.wait();raise InspectionError('Control SSH timed out; mutation outcome may be unknown') from exc
            finally:
                for thread in threads:thread.join(timeout=2)
                for stream in (proc.stdin,proc.stdout,proc.stderr):
                    if stream and not stream.closed:stream.close()
            if too_large.is_set() or errors or any(t.is_alive() for t in threads):raise InspectionError('Control SSH I/O failed')
            raw=b''.join(chunks).decode('utf-8')
            if proc.returncode:raise InspectionError('Controlled helper/probe failed; check installed helper, policy, SSH agent and sudo rights')
            value=json.loads(raw)
            if not isinstance(value,dict):raise InspectionError('Invalid control result')
            return value
        except (OSError,ValueError,UnicodeError) as exc:
            raise InspectionError('Invalid or unavailable control SSH result') from exc


def probe_program(destination,port):
    address=ipaddress.ip_address(destination)
    if type(port) is not int or not 1<=port<=65535 or address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ChangeDenied('Invalid configured TCP endpoint')
    # Literals come from validated IP/numeric values, never model-supplied code.
    parameters=repr(canonical({'destination':str(address),'port':port}))
    return ("import socket,json,errno\n"
        "p=json.loads("+parameters+")\n"
        "family=socket.AF_INET6 if ':' in p['destination'] else socket.AF_INET\n"
        "route=socket.socket(family,socket.SOCK_DGRAM)\n"
        "try:\n route.connect((p['destination'],p['port']));source=route.getsockname()[0]\n"
        "except OSError:\n print(json.dumps(dict(p,source_ip='',status='inconclusive')));raise SystemExit(0)\n"
        "finally:\n route.close()\n"
        "s=socket.socket(family,socket.SOCK_STREAM);s.bind((source,0))\n"
        "s.settimeout(3)\n"
        "status='error'\n"
        "try:\n s.connect((p['destination'],p['port']));status='connected'\n"
        "except socket.timeout:\n status='timeout'\n"
        "except OSError as e:\n status='refused' if e.errno==errno.ECONNREFUSED else ('timeout' if e.errno==errno.ETIMEDOUT else 'inconclusive')\n"
        "try:\n source=s.getsockname()[0]\n"
        "except OSError:\n source=''\n"
        "s.close()\n"
        "print(json.dumps(dict(p,source_ip=source,status=status)))\n").encode()


class SSHChangeBackend:
    def __init__(self,hosts,target,plan,channel=None):
        from copy import deepcopy
        if target not in hosts:raise ChangeDenied('Unconfigured target VM')
        self.hosts=dict(hosts);self.target=target;self.plan=deepcopy(plan);self.channel=channel or ControlSSH()
        for check in self.plan['checks']:
            if check['host'] not in hosts or check['host']==target:raise ChangeDenied('Verification sources must be separate configured test VMs')
            hosts[check['host']].validate()
        hosts[target].validate()

    def snapshot(self):
        return json.loads(SSHTransport().read(self.hosts[self.target],Operation.RULES))

    def helper(self,request):
        result=self.channel.exchange(self.hosts[self.target],'helper',canonical(request).encode())
        if result.get('ok') is not True or not isinstance(result.get('result'),dict):raise InspectionError('Helper denied the requested operation')
        return result['result']

    def prepare(self,proposal):return self.helper({'operation':'prepare','proposal':proposal})
    def status(self):return self.helper({'operation':'status'})
    def apply(self,change,approval_digest):
        return self.helper({'operation':'apply','change_id':change['change_id'],'nonce':change['nonce'],'approval_digest':approval_digest})
    def confirm(self,change,verification):
        return self.helper({'operation':'confirm','change_id':change['change_id'],'nonce':change['nonce'],'verification':verification})
    def rollback(self,change):
        return self.helper({'operation':'rollback','change_id':change['change_id'],'nonce':change['nonce']})

    def management(self):
        try:
            SSHTransport().read(self.hosts[self.target],Operation.HOST);return True
        except InspectionError:return False

    def probe(self,check,plan):
        if canonical(plan)!=canonical(self.plan) or check not in self.plan['checks']:
            raise ChangeDenied('Probe is outside configured verification scope')
        value=self.channel.exchange(self.hosts[check['host']],'probe',probe_program(plan['destination'],plan['port']))
        if set(value)!={'source_ip','destination','port','status'} or value['destination']!=plan['destination'] or value['port']!=plan['port']:
            raise InspectionError('Probe result does not match configured endpoint')
        return dict(value,host=check['host'])
