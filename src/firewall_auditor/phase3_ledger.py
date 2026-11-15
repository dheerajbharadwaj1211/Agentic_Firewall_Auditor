"""Append-only hash-chained audit events and one-use human approvals.

SQLite triggers prevent application UPDATE/DELETE on audit rows. This detects
accidental/partial tampering, not a malicious local administrator rewriting the
whole database. Root-side logs provide a separately protected record.
"""
import hashlib
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from .phase3_policy import canonical, digest, ChangeDenied


class AuditFailure(RuntimeError):
    pass


class Ledger:
    def __init__(self,path):
        self.path=Path(path)
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY,at REAL NOT NULL,kind TEXT NOT NULL,
                    payload TEXT NOT NULL,previous TEXT NOT NULL,hash TEXT NOT NULL);
                CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN
                    SELECT RAISE(ABORT,'Audit events cannot be deleted'); END;
                CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN
                    SELECT RAISE(ABORT,'Audit events cannot be changed'); END;
                CREATE TABLE IF NOT EXISTS approvals(token_hash TEXT PRIMARY KEY,proposal_hash TEXT NOT NULL,
                    actor TEXT NOT NULL,expires REAL NOT NULL,consumed INTEGER NOT NULL DEFAULT 0);
            """)
        self.verify()

    @contextmanager
    def connect(self):
        db=sqlite3.connect(self.path,timeout=5)
        try:
            db.execute('PRAGMA synchronous=FULL')
            with db:yield db
        finally:db.close()

    def _verify(self,db):
        previous='0'*64
        for seq,at,kind,payload,prior,stored in db.execute('SELECT seq,at,kind,payload,previous,hash FROM events ORDER BY seq'):
            if prior!=previous or stored!=digest({'seq':seq,'at':at,'kind':kind,'payload':payload,'previous':prior}):
                raise AuditFailure('Audit integrity verification failed')
            previous=stored
        return previous

    def verify(self):
        try:
            with self.connect() as db:self._verify(db)
        except sqlite3.Error as exc:raise AuditFailure('Audit database is unavailable or corrupt') from exc
        return True

    def _append(self,db,kind,payload):
        if not isinstance(kind,str) or not 1<=len(kind)<=80:raise AuditFailure('Invalid audit event kind')
        # Do not log credential fields or known API secret values.
        def redact(value):
            if isinstance(value,dict):return {k:('[REDACTED]' if any(s in k.lower() for s in ('password','passphrase','api_key','private_key','nonce','token')) else redact(v)) for k,v in value.items()}
            if isinstance(value,list):return [redact(v) for v in value]
            if isinstance(value,str):
                for key in ('GEMINI_API_KEY','GOOGLE_API_KEY','OPENAI_API_KEY'):
                    secret=os.environ.get(key)
                    if secret:value=value.replace(secret,'[REDACTED]')
            return value
        text=canonical(redact(payload))
        if len(text.encode())>1024*1024:raise AuditFailure('Audit event too large')
        previous=self._verify(db)
        seq=db.execute('SELECT COALESCE(MAX(seq),0)+1 FROM events').fetchone()[0]
        at=time.time()
        hashed=digest({'seq':seq,'at':at,'kind':kind,'payload':text,'previous':previous})
        db.execute('INSERT INTO events VALUES(?,?,?,?,?,?)',(seq,at,kind,text,previous,hashed))
        return seq

    def append(self,kind,payload):
        try:
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                return self._append(db,kind,payload)
        except sqlite3.Error as exc:raise AuditFailure('Could not persist audit event') from exc

    def approve(self,proposal,actor,ttl=300):
        if not isinstance(actor,str) or not actor.strip() or len(actor)>128 or type(ttl) is not int or not 1<=ttl<=300:
            raise ChangeDenied('Invalid operator identity or approval lifetime')
        proposal_hash=digest(proposal)
        now=time.time()
        expiry=min(now+ttl,proposal['expires_at'])
        if expiry<=now:raise ChangeDenied('Proposal expired')
        token=secrets.token_hex(32)
        try:
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                db.execute('INSERT INTO approvals VALUES(?,?,?,?,0)',(hashlib.sha256(token.encode()).hexdigest(),proposal_hash,actor,expiry))
                self._append(db,'human_approval',{'proposal_hash':proposal_hash,'change_id':proposal['change_id'],'actor':actor,'expires':expiry})
        except sqlite3.Error as exc:raise AuditFailure('Could not persist approval') from exc
        return token

    def reject(self,proposal,actor):
        self.append('human_rejection',{'proposal_hash':digest(proposal),'change_id':proposal['change_id'],'actor':actor})

    def consume(self,proposal,token):
        if not isinstance(token,str) or len(token)!=64:raise ChangeDenied('A recorded human approval is required')
        try:
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                key=hashlib.sha256(token.encode()).hexdigest()
                row=db.execute('SELECT proposal_hash,actor,expires,consumed FROM approvals WHERE token_hash=?',(key,)).fetchone()
                if row is None or row[0]!=digest(proposal) or row[2]<=time.time() or row[3]!=0:
                    raise ChangeDenied('Approval is missing, expired, changed or already consumed')
                db.execute('UPDATE approvals SET consumed=1 WHERE token_hash=?',(key,))
                self._append(db,'approval_consumed',{'proposal_hash':row[0],'change_id':proposal['change_id'],'actor':row[1]})
        except sqlite3.Error as exc:raise AuditFailure('Could not consume approval safely') from exc
        return row[1]

    def events(self):
        self.verify()
        with self.connect() as db:
            return [{'sequence':seq,'at':at,'kind':kind,'payload':json.loads(data),'hash':hashed}
                    for seq,at,kind,data,hashed in db.execute('SELECT seq,at,kind,payload,hash FROM events ORDER BY seq')]
