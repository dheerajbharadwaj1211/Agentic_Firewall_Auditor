"""Root-owned Linux helper. No shell parsing and no arbitrary nft input API.

Install only the documented wrapper + this module + phase3_policy + __init__
into a root-owned bundle. Local unit tests inject a fake system backend.
"""
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from .phase3_policy import (ChangeDenied, canonical, digest, fingerprint, locate,
    nft_replace, replace_in_snapshot, valid_id, validate_proposal, validate_results)

STATE=Path('/var/lib/firewall-auditor')
CONFIG=Path('/etc/firewall-auditor/policy.json')
WRAPPER='/usr/local/libexec/firewall-auditor-helper'


def write_durable(path,data):
    path=Path(path)
    temporary=path.with_name('.'+path.name+'.'+secrets.token_hex(8))
    fd=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            stream.write(canonical(data));stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
        if os.name!='nt':
            directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(directory)
            finally:os.close(directory)
    finally:
        if temporary.exists():temporary.unlink()


@contextmanager
def file_lock(path):
    import fcntl
    with open(path,'a') as stream:
        deadline=time.monotonic()+5
        while True:
            try:fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError:
                if time.monotonic()>deadline:raise ChangeDenied('Helper busy; retry without assuming any change succeeded')
                time.sleep(0.1)
        try:yield
        finally:fcntl.flock(stream,fcntl.LOCK_UN)


class LinuxSystem:
    def __init__(self,state=STATE):self.state=Path(state)

    def run(self,argv,payload=None):
        with tempfile.TemporaryFile(dir=self.state) as out,tempfile.TemporaryFile(dir=self.state) as err:
            completed=subprocess.run(argv,input=None if payload is None else canonical(payload).encode(),
                stdout=out,stderr=err,timeout=25,check=False,shell=False,cwd='/',
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'},umask=0o077)
            if completed.returncode:raise ChangeDenied('Trusted helper system operation failed')
            if out.tell()>4*1024*1024 or err.tell()>4*1024*1024:raise ChangeDenied('System result exceeds helper limit')
            out.seek(0);return out.read().decode('utf-8')

    def boot_id(self):return Path('/proc/sys/kernel/random/boot_id').read_text().strip()

    def snapshot(self):return json.loads(self.run(['/usr/sbin/nft','-j','list','ruleset']))
    def check(self,command):self.run(['/usr/sbin/nft','-j','-c','-f','-'],command)
    def apply(self,command):self.run(['/usr/sbin/nft','-j','-f','-'],command)

    def arm(self,change_id,seconds):
        valid_id(change_id)
        self.run(['/usr/bin/systemctl','is-enabled','--quiet','firewall-auditor-recover.service'])
        self.run(['/usr/bin/systemd-run','--unit=fwa-rollback-'+change_id,
            '--on-active='+str(seconds)+'s','--timer-property=AccuracySec=1s',
            '--property=Restart=on-failure','--property=RestartSec=5s',
            WRAPPER,'--rollback',change_id])
        self.run(['/usr/bin/systemctl','is-active','--quiet','fwa-rollback-'+change_id+'.timer'])

    def cancel(self,change_id):
        valid_id(change_id)
        self.run(['/usr/bin/systemctl','stop','fwa-rollback-'+change_id+'.timer'])


class RootHelper:
    def __init__(self,system,policy,state=STATE,lock_factory=None):
        self.system=system;self.policy=deepcopy(policy);self.state=Path(state)
        self.state.mkdir(parents=True,exist_ok=True)
        self.lock_factory=lock_factory or (lambda:file_lock(self.state/'lock'))

    def audit(self,kind,data):
        path=self.state/'audit.jsonl'
        previous='0'*64
        if path.exists():
            with path.open(encoding='utf-8') as stream:
                for line in stream:
                    row=json.loads(line);saved=row.pop('hash')
                    if row.get('previous')!=previous or digest(row)!=saved:raise ChangeDenied('Root audit integrity failed')
                    previous=saved
        row={'at':time.time(),'kind':kind,'data':data,'previous':previous}
        row['hash']=digest(row)
        flags=os.O_WRONLY|os.O_CREAT|os.O_APPEND|getattr(os,'O_NOFOLLOW',0)
        fd=os.open(path,flags,0o600)
        with os.fdopen(fd,'a',encoding='utf-8') as stream:
            stream.write(canonical(row)+'\n');stream.flush();os.fsync(stream.fileno())

    def path(self,change_id):return self.state/(valid_id(change_id)+'.json')
    def load(self,change_id):return json.loads(self.path(change_id).read_text(encoding='utf-8'))
    def save(self,record):write_durable(self.path(record['proposal']['change_id']),record)

    def _authorized_record(self,request):
        record=self.load(request['change_id'])
        nonce=request.get('nonce')
        if not isinstance(nonce,str) or not secrets.compare_digest(nonce,record['nonce']):
            raise ChangeDenied('Invalid change capability')
        return record

    def handle(self,request):
        try:return self._handle(request)
        except Exception as exc:
            operation=request.get('operation') if isinstance(request,dict) else None
            if not isinstance(operation,str) or operation not in {'status','prepare','apply','confirm','rollback'}:operation='unknown'
            try:
                with self.lock_factory():self.audit('request_rejected',{'operation':operation,'error_type':type(exc).__name__})
            except Exception:pass
            raise

    def _handle(self,request):
        if not isinstance(request,dict) or not isinstance(request.get('operation'),str):raise ChangeDenied('Invalid helper request')
        schemas={'status':{'operation'},'prepare':{'operation','proposal'},
                 'apply':{'operation','change_id','nonce','approval_digest'},
                 'confirm':{'operation','change_id','nonce','verification'},
                 'rollback':{'operation','change_id','nonce'}}
        op=request['operation']
        if op not in schemas or set(request)!=schemas[op]:raise ChangeDenied('Forbidden helper operation or parameters')
        with self.lock_factory():
            if op=='status':
                return {'helper_version':1,'policy':self.policy,
                        'current_fingerprint':fingerprint(self.system.snapshot()),
                        'pending':[p.stem for p in self.state.glob('*.json')
                            if json.loads(p.read_text()).get('phase') in {'armed','applied'}]}
            if self.policy.get('enabled') is not True or self.policy.get('test_vm') is not True:
                raise ChangeDenied('Root-owned mutation policy is disabled')
            if op=='prepare':return self.prepare(request['proposal'])
            record=self._authorized_record(request)
            if op=='apply':return self.apply(record,request['approval_digest'])
            if op=='confirm':return self.confirm(record,request['verification'])
            return self.rollback(record)

    def prepare(self,proposal):
        raw=self.system.snapshot()
        validate_proposal(raw,proposal,self.policy)
        if self.path(proposal['change_id']).exists():raise ChangeDenied('Change ID already exists')
        for path in self.state.glob('*.json'):
            old=json.loads(path.read_text())
            if old.get('phase') in {'armed','applied'}:raise ChangeDenied('Another change is pending verification/rollback')
        self.system.check(nft_replace(proposal['after_rule']))
        record={'proposal':deepcopy(proposal),'proposal_hash':digest(proposal),'phase':'prepared',
                'nonce':secrets.token_hex(32),'before':raw,'after_fingerprint':fingerprint(
                    replace_in_snapshot(raw,proposal['target'],proposal['after_rule']))}
        self.audit('prepared',{'change_id':proposal['change_id'],'proposal_hash':record['proposal_hash']})
        self.save(record)
        return {'change_id':proposal['change_id'],'nonce':record['nonce'],'proposal_hash':record['proposal_hash'],'phase':'prepared'}

    def apply(self,record,approval_digest):
        if record['phase']!='prepared' or approval_digest!=record['proposal_hash']:
            raise ChangeDenied('Exact human approval digest is required and a change can only apply once')
        raw=self.system.snapshot()
        new=validate_proposal(raw,record['proposal'],self.policy)
        self.system.check(nft_replace(new))
        record['before']=raw
        record['after_fingerprint']=fingerprint(replace_in_snapshot(raw,record['proposal']['target'],new))
        record['phase']='armed';record['deadline']=time.time()+120
        record['deadline_monotonic']=time.monotonic()+120;record['boot_id']=self.system.boot_id()
        self.audit('apply_authorized',{'change_id':record['proposal']['change_id'],'proposal_hash':record['proposal_hash']})
        self.save(record)  # Durable backup BEFORE timer and mutation.
        try:
            self.system.arm(record['proposal']['change_id'],120)
            self.audit('rollback_armed',{'change_id':record['proposal']['change_id'],'deadline':record['deadline']})
            self.system.apply(nft_replace(new))
            if fingerprint(self.system.snapshot())!=record['after_fingerprint']:
                raise ChangeDenied('Post-apply ruleset does not match approved change')
            record['phase']='applied';self.save(record)
            self.audit('applied',{'change_id':record['proposal']['change_id'],'after_fingerprint':record['after_fingerprint']})
            return {'phase':'applied','after_fingerprint':record['after_fingerprint'],'deadline':record['deadline']}
        except BaseException:
            try:self.rollback(record)
            except Exception:pass  # The independent timer/recovery retains durable state.
            raise

    def confirm(self,record,verification):
        if record['phase']!='applied':raise ChangeDenied('Only an applied change can be confirmed')
        if time.time()>=record['deadline'] or time.monotonic()>=record['deadline_monotonic'] or self.system.boot_id()!=record['boot_id']:
            self.rollback(record);raise ChangeDenied('Verification lease expired; rolled back')
        try:
            validate_results(record['proposal']['verification'],verification)
            if fingerprint(self.system.snapshot())!=record['after_fingerprint']:
                raise ChangeDenied('Ruleset changed before confirmation')
        except Exception:
            self.rollback(record);raise
        self.audit('verification_passed',{'change_id':record['proposal']['change_id'],'verification':verification})
        record['phase']='confirmed';self.save(record)
        try:self.system.cancel(record['proposal']['change_id'])
        except Exception:pass  # A late timer sees confirmed and performs no mutation.
        self.audit('confirmed',{'change_id':record['proposal']['change_id']})
        return {'phase':'confirmed'}

    def rollback_audit(self,kind,data):
        try:self.audit(kind,data)
        except Exception:pass  # Never let a full/broken log prevent an already-approved safety rollback.

    def rollback(self,record):
        if record['phase']=='rolled_back':return {'phase':'rolled_back','rule_restored':True,'replacement_applied':record.get('rollback_replaced',False)}
        if record['phase'] not in {'armed','applied','confirmed','prepared'}:raise ChangeDenied('Unsupported rollback state')
        if record['phase']=='confirmed' and (time.time()>record.get('deadline',0) or time.monotonic()>record.get('deadline_monotonic',0) or self.system.boot_id()!=record.get('boot_id')):
            raise ChangeDenied('Committed change requires a fresh approval after its original lease')
        raw=self.system.snapshot();target=record['proposal']['target']
        actual=locate(raw,target)
        original=locate(record['before'],target)
        expected=record['proposal']['after_rule']
        rulehash=lambda r:fingerprint({'nftables':[{'rule':r}]})
        replaced=False
        if rulehash(actual)==rulehash(original):
            restored=True
        elif rulehash(actual)==rulehash(expected):
            # Restore only this exact rule; never flush unrelated rules or chains.
            self.rollback_audit('rollback_requested',{'change_id':record['proposal']['change_id']})
            self.system.check(nft_replace(original));self.system.apply(nft_replace(original));replaced=True
            restored=rulehash(locate(self.system.snapshot(),target))==rulehash(original)
        else:
            self.rollback_audit('rollback_conflict',{'change_id':record['proposal']['change_id']})
            raise ChangeDenied('Target changed independently; refusing to overwrite it')
        if not restored:raise ChangeDenied('Rollback could not be verified')
        record['phase']='rolled_back';record['rollback_replaced']=replaced;self.save(record)
        self.rollback_audit('rolled_back',{'change_id':record['proposal']['change_id'],'rule_restored':True})
        try:self.system.cancel(record['proposal']['change_id'])
        except Exception:pass
        return {'phase':'rolled_back','rule_restored':True,'replacement_applied':replaced,
                'ruleset_matches_before':fingerprint(self.system.snapshot())==fingerprint(record['before'])}

    def timed_rollback(self,change_id):
        with self.lock_factory():
            record=self.load(change_id)
            if record['phase'] in {'armed','applied'}:return self.rollback(record)
            return {'phase':record['phase']}

    def recover(self):
        results=[]
        with self.lock_factory():
            for path in self.state.glob('*.json'):
                record=json.loads(path.read_text())
                if record.get('phase') in {'armed','applied'}:results.append(self.rollback(record))
        return results


def trusted(path,directory=False):
    info=Path(path).lstat()
    if stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
        raise ChangeDenied('Helper code, configuration and state must be root-owned and not group/world writable')
    if directory!=stat.S_ISDIR(info.st_mode):raise ChangeDenied('Invalid trusted path type')


def main():
    try:
        if not hasattr(os,'geteuid') or os.geteuid()!=0:raise ChangeDenied('Helper must run as root through the exact sudo rule')
        for path in (STATE,CONFIG.parent,Path('/usr/local/lib/firewall-auditor'),Path('/usr/local/lib/firewall-auditor/firewall_auditor')):trusted(path,True)
        for path in (CONFIG,Path(WRAPPER),Path(__file__),Path(__file__).with_name('phase3_policy.py'),Path(__file__).with_name('__init__.py')):trusted(path)
        policy=json.loads(CONFIG.read_text())
        helper=RootHelper(LinuxSystem(),policy)
        if len(sys.argv)==3 and sys.argv[1]=='--rollback':result=helper.timed_rollback(valid_id(sys.argv[2]))
        elif len(sys.argv)==2 and sys.argv[1]=='--recover':result=helper.recover()
        elif len(sys.argv)==1:
            data=sys.stdin.buffer.read(65537)
            if len(data)>65536:raise ChangeDenied('Helper request exceeds size limit')
            result=helper.handle(json.loads(data))
        else:raise ChangeDenied('Unsupported helper arguments')
        print(canonical({'ok':True,'result':result}));return 0
    except BaseException as exc:
        # No raw external command output, comments or credentials in public errors.
        print(canonical({'ok':False,'error':'Helper rejected or failed the operation','error_type':type(exc).__name__}));return 1


if __name__=='__main__':raise SystemExit(main())
