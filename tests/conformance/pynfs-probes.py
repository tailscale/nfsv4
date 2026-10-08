#!/usr/bin/python3
"""Read-only adaptations and additional probes using the pinned pynfs codec."""
import sys, os, json, time, traceback, argparse
sys.path.insert(0, os.path.join(os.environ['PYNFS_ROOT'], 'nfs4.1'))
import use_local
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from server41tests.environment import use_obj, open_file, close_file, read_file
import nfs4client, nfs4lib, nfs_ops
from rpc.security import AuthSys, AuthNone
op = nfs_ops.NFS4ops()
p = argparse.ArgumentParser()
p.add_argument('--minorversion', type=int, required=True)
p.add_argument('--security', choices=['sys','none'], default='sys')
p.add_argument('--output', required=True)
a = p.parse_args()
c = nfs4client.NFS4Client(os.environ.get('PYNFS_HOST', '127.0.0.1'), int(os.environ.get('PYNFS_PORT', '22049')), a.minorversion)
c.set_cred(AuthSys().init_cred(uid=os.getuid(),gid=os.getgid(),name=b'pynfs-probes') if a.security=='sys' else AuthNone().init_cred())
s = c.new_client_session(('adapted-%d-%s-%d' % (a.minorversion,a.security,time.time_ns())).encode())
results=[]

def record(code, res, expected=NFS4_OK, predicate=None):
    expected = expected if isinstance(expected,list) else [expected]
    try:
        ok = res.status in expected and (predicate is None or predicate(res))
    except Exception as exc:
        print('Predicate error:', exc, flush=True)
        ok = False
    results.append(dict(code=code, result='PASS' if ok else 'FAIL', status=nfsstat4[res.status], expected=[nfsstat4[x] for x in expected], response=repr(res)))
    print(code,results[-1]['result'],results[-1]['status'],flush=True)
    return res

def run(code, ops, expected=NFS4_OK, predicate=None, **kwargs):
    kwargs.setdefault('checks', False)
    return record(code,s.compound(ops,**kwargs),expected,predicate)

file=[b'tree',b'file']; link=[b'tree',b'link']; directory=[b'tree',b'dir']
f=use_obj(file); l=use_obj(link); d=use_obj(directory)
s.compound([op.reclaim_complete(False)])
# Adapt SEC1 and SEC2: use an existing object instead of creating one.
run('AD-SEC1',use_obj([b'tree'])+[op.secinfo(b'file')],predicate=lambda r: any(x.flavor==AUTH_SYS for x in r.resarray[-1].switch.switch))
run('AD-SEC2',use_obj([b'tree'])+[op.secinfo(b'file'),op.getfh()],NFS4ERR_NOFILEHANDLE)
run('SEC-NOENT',use_obj([b'tree'])+[op.secinfo(b'missing')],NFS4ERR_NOENT)
run('SEC-EMPTY',d+[op.secinfo(b'')],NFS4ERR_INVAL)
run('SEC-NOFH',[op.secinfo(b'file')],NFS4ERR_NOFILEHANDLE)
run('SECNN-INVAL',d+[op.secinfo_no_name(9)],NFS4ERR_INVAL)
run('SECNN-NOFH',[op.secinfo_no_name(0)],NFS4ERR_NOFILEHANDLE)
# Active st_lookup is not registered by upstream __init__.py.
for code,ops,expected in [('LOOK1',[op.lookup(b'x')],NFS4ERR_NOFILEHANDLE),('LOOK2',d+[op.lookup(b'missing')],NFS4ERR_NOENT),('LOOK3',[op.putrootfh(),op.lookup(b'')],NFS4ERR_INVAL),('LOOK4',[op.putrootfh(),op.lookup(b'abc'*512)],NFS4ERR_NAMETOOLONG)]: run('AD-'+code,ops,expected)
run('LOOK-FILE',f+[op.lookup(b'x')],NFS4ERR_NOTDIR)
run('LOOK-LINK',l+[op.lookup(b'x')],[NFS4ERR_SYMLINK,NFS4ERR_NOTDIR])
run('LOOK-DOT',d+[op.lookup(b'.')],[NFS4ERR_BADNAME,NFS4ERR_NOENT])
run('LOOK-DOTDOT',d+[op.lookup(b'..')],[NFS4ERR_BADNAME,NFS4ERR_NOENT])
run('LOOK-SLASH',d+[op.lookup(b'a/b')],[NFS4ERR_BADCHAR,NFS4ERR_BADNAME,NFS4ERR_INVAL])
run('GETATTR-NOFH',[op.getattr(1<<FATTR4_TYPE)],NFS4ERR_NOFILEHANDLE)
run('GETATTR-UNSUPPORTED-WRITEONLY',f+[op.getattr(1<<FATTR4_TIME_ACCESS_SET)],predicate=lambda r:not r.resarray[-1].obj_attributes)
run('GETATTR-UNSUPPORTED',f+[op.getattr(1<<FATTR4_ACL)],predicate=lambda r: not r.resarray[-1].obj_attributes)
r=run('GETATTR-MANDATORY',f+[op.getattr(nfs4lib.list2bitmap([0,1,2,3,4,5,6,7,8,9,10,19]))],predicate=lambda r: all(x in r.resarray[-1].obj_attributes for x in [0,1,2,3,4,5,6,7,8,9,10,19]))
run('VERIFY-TYPE',f+[op.verify({FATTR4_TYPE:NF4REG})])
run('NVERIFY-SAME',f+[op.nverify({FATTR4_TYPE:NF4REG})],NFS4ERR_SAME)
run('VERIFY-DIFFERENT',f+[op.verify({FATTR4_TYPE:NF4DIR})],NFS4ERR_NOT_SAME)
run('NVERIFY-DIFFERENT',f+[op.nverify({FATTR4_TYPE:NF4DIR})])
run('VERIFY-UNSUPPORTED-WRITEONLY',f+[op.verify({FATTR4_TIME_ACCESS_SET:settime4(SET_TO_SERVER_TIME4)})],[NFS4ERR_ATTRNOTSUPP,NFS4ERR_INVAL])
run('VERIFY-RDATTR',f+[op.verify({FATTR4_RDATTR_ERROR:NFS4_OK})],NFS4ERR_INVAL)
run('VERIFY-UNSUPPORTED',f+[op.verify({FATTR4_ARCHIVE:False})],NFS4ERR_ATTRNOTSUPP)
run('READLINK',l+[op.readlink()],predicate=lambda r:r.resarray[-1].link==b'/etc/X11')
run('READLINK-FILE',f+[op.readlink()],NFS4ERR_INVAL)
run('READLINK-NOFH',[op.readlink()],NFS4ERR_NOFILEHANDLE)
run('ACCESS-READONLY',f+[op.access(63)],predicate=lambda r:r.resarray[-1].access & (ACCESS4_MODIFY|ACCESS4_EXTEND|ACCESS4_DELETE)==0)
run('ACCESS-NOFH',[op.access(63)],NFS4ERR_NOFILEHANDLE)
run('GETFH-NOFH',[op.getfh()],NFS4ERR_NOFILEHANDLE)
run('SAVEFH-NOFH',[op.savefh()],NFS4ERR_NOFILEHANDLE)
run('RESTOREFH-NOSAVE',[op.restorefh()],NFS4ERR_RESTOREFH)
run('SAVE-RESTORE',f+[op.savefh(),op.putrootfh(),op.restorefh(),op.getattr(1<<FATTR4_TYPE)],predicate=lambda r:r.resarray[-1].obj_attributes[FATTR4_TYPE]==NF4REG)
run('PUTFH-EMPTY',[op.putfh(b'')],NFS4ERR_BADHANDLE)
run('PUTFH-INVALID-GETATTR',[op.putfh(b'abc'),op.getattr(1<<FATTR4_TYPE)],[NFS4ERR_BADHANDLE,NFS4ERR_STALE])
run('READ-ANON',f+[op.read(nfs4lib.state00,0,100)],predicate=lambda r:r.resarray[-1].data==b'This is the file test data.' and r.resarray[-1].eof)
run('READ-BEYOND-EOF',f+[op.read(nfs4lib.state00,1000,100)],predicate=lambda r:r.resarray[-1].data==b'' and r.resarray[-1].eof)
run('READ-ZERO',f+[op.read(nfs4lib.state00,0,0)],predicate=lambda r:r.resarray[-1].data==b'')
run('READ-DIR',d+[op.read(nfs4lib.state00,0,100)],NFS4ERR_ISDIR)
run('READ-NOFH',[op.read(nfs4lib.state00,0,100)],NFS4ERR_NOFILEHANDLE)
# The server accepts unknown stateids for the macOS restart workaround.
# This check records the policy, not protocol compliance.
run('READ-BADSTATE',f+[op.read(stateid4(123,b'invalidstate'),0,100)],predicate=lambda r:r.resarray[-1].data==b'This is the file test data.' and r.resarray[-1].eof)
run('READDIR-EMPTY',d+[op.readdir(0,b'\0'*8,4096,4096,1<<FATTR4_TYPE)],predicate=lambda r:r.resarray[-1].reply.eof)
run('READDIR-FILE',f+[op.readdir(0,b'\0'*8,4096,4096,0)],NFS4ERR_NOTDIR)
run('READDIR-NOFH',[op.readdir(0,b'\0'*8,4096,4096,0)],NFS4ERR_NOFILEHANDLE)
run('READDIR-TINY',use_obj([b'tree'])+[op.readdir(0,b'\0'*8,1,1,0)],NFS4ERR_TOOSMALL)
# Adapt OPEN1, OPEN8, OPEN7: OPEN4_NOCREATE and READ only.
r=record('AD-OPEN1',open_file(s,b'owner',file))
if r.status==NFS4_OK:
    fh=r.resarray[-1].object; sid=r.resarray[-2].stateid
    run('READ-OPENSTATE',[op.putfh(fh),op.read(sid,0,100)])
    run('TESTSTATE-OPEN',[op.test_stateid([sid])],predicate=lambda r:r.resarray[-1].tsr_status_codes==[NFS4_OK])
    run('AD-OPEN2',f+[op.open(0,OPEN4_SHARE_ACCESS_READ,OPEN4_SHARE_DENY_NONE,open_owner4(0,b'owner'),openflag4(OPEN4_NOCREATE),open_claim4(CLAIM_NULL,b'file'))],[NFS4ERR_NOTDIR])
    sid.seqid=0
    record('AD-OPEN8',close_file(s,fh,sid))
run('AD-OPEN7',f+[op.open(0,OPEN4_SHARE_ACCESS_READ,OPEN4_SHARE_DENY_NONE,open_owner4(0,b'fhowner'),openflag4(OPEN4_NOCREATE),open_claim4(CLAIM_FH))])
record('OPEN-DIR',open_file(s,b'dirowner',directory),NFS4ERR_ISDIR)
record('OPEN-LINK',open_file(s,b'linkowner',link),NFS4ERR_SYMLINK)
record('OPEN-WRITE',open_file(s,b'writeowner',file,access=OPEN4_SHARE_ACCESS_WRITE),NFS4ERR_ROFS)
run('CLOSE-BADSTATE',f+[op.close(0,stateid4(123,b'invalidstate'))],NFS4ERR_BAD_STATEID)
run('FREE-BADSTATE',[op.free_stateid(stateid4(123,b'invalidstate'))],NFS4ERR_BAD_STATEID)
# Adapt DSESS1 and SEQ9b/10b: session state and rejected write, not a new file.
r=run('AD-SEQ9b',f+[op.write(nfs4lib.state00,0,FILE_SYNC4,b'no')],NFS4ERR_ROFS,cache_this=True)
r2=run('AD-SEQ9b-REPLAY',f+[op.write(nfs4lib.state00,0,FILE_SYNC4,b'no')],NFS4ERR_ROFS,predicate=lambda replay:repr(replay)==repr(r),cache_this=True,seq_delta=0)
run('AD-SEQ10b',f+[op.write(nfs4lib.state00,0,FILE_SYNC4,b'no')],NFS4ERR_ROFS,cache_this=False)
# SessionRecord removes successful SEQUENCE from the returned array.
# The first operation after SEQUENCE must carry RETRY_UNCACHED_REP.
run('AD-SEQ10b-REPLAY',f+[op.write(nfs4lib.state00,0,FILE_SYNC4,b'no')],NFS4ERR_RETRY_UNCACHED_REP,predicate=lambda r:len(r.resarray)==1 and r.resarray[0].resop==OP_PUTROOTFH and r.resarray[0].status==NFS4ERR_RETRY_UNCACHED_REP,cache_this=False,seq_delta=0)
run('BIND-NOTONLY',[op.bind_conn_to_session(s.sessionid,CDFC4_FORE,False)],NFS4ERR_NOT_ONLY_OP)
other=c.new_client_session(('other-%d'%time.time_ns()).encode())
run('DESTROY-OTHERCLIENT-BOUND',[op.destroy_session(other.sessionid)])
smallclient=c.new_client(('smallresponse-%d'%time.time_ns()).encode())
record('RESPONSE-NEGOTIATION-TOOSMALL',smallclient._create_session(fore_attrs=channel_attrs4(0,8192,70,70,128,8,[])),NFS4ERR_TOOSMALL)
usableclient=c.new_client(('usableresponse-%d'%time.time_ns()).encode())
negotiation=usableclient._create_session(fore_attrs=channel_attrs4(0,8192,88,88,128,8,[]))
if negotiation.status==NFS4_OK:
    small=usableclient._add_session(negotiation.resarray[0])
    record('RESPONSE-RPC-HEADERS',c.compound([op.sequence(small.sessionid,1,0,0,False)],tag=b'123456789012'),NFS4ERR_REP_TOO_BIG,predicate=lambda r:len(r.resarray)==1 and r.resarray[0].resop==OP_SEQUENCE)
else:
    record('RESPONSE-RPC-HEADERS',negotiation,NFS4_OK)
record('BIND-SOLE',c.compound([op.bind_conn_to_session(s.sessionid,CDFC4_FORE,False)]))
identity_name=('identity-%d'%time.time_ns()).encode()
identity=c.new_client(identity_name)
identity_session=identity.create_session()
foreign=AuthSys().init_cred(uid=1111,gid=37,name=b'shampoo')
identity_owner=client_owner4(c.verifier,identity_name)
record('IDENTITY-COLLISION-LIVE',c.compound([op.exchange_id(identity_owner,0,state_protect4_a(SP4_NONE),[])],foreign),NFS4ERR_CLID_INUSE)
record('IDENTITY-UPDATE-FOREIGN',c.compound([op.exchange_id(identity_owner,EXCHGID4_FLAG_UPD_CONFIRMED_REC_A,state_protect4_a(SP4_NONE),[])],foreign),NFS4ERR_PERM)
# SEEK is supported only in minor version 2.
if a.minorversion==2:
    run('SEEK-DATA',f+[op.seek(nfs4lib.state00,0,NFS4_CONTENT_DATA)],predicate=lambda r:r.resarray[-1].sr_offset==0)
    run('SEEK-HOLE',f+[op.seek(nfs4lib.state00,0,NFS4_CONTENT_HOLE)],predicate=lambda r:r.resarray[-1].sr_offset==27)
    run('SEEK-EOF',f+[op.seek(nfs4lib.state00,27,NFS4_CONTENT_DATA)],NFS4ERR_NXIO)
record('AD-DSESS1-DESTROY',c.compound([op.destroy_session(s.sessionid)]))
run('AD-DSESS1-BADSESSION',[op.putrootfh()],NFS4ERR_BADSESSION)
json.dump(dict(label='adapted upstream and additional readonly probes; not unmodified upstream results',minorversion=a.minorversion,security=a.security,counts={k:sum(r['result']==k for r in results) for k in ['PASS','FAIL']},testcase=results),open(a.output,'w'),indent=2)
