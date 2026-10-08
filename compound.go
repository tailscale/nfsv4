// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4

import (
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/tailscale/nfsv4/internal/oncrpc"
	"github.com/tailscale/nfsv4/internal/xdr"
)

// maxCompoundOps bounds the number of operations in a COMPOUND, before a
// session's negotiated limit applies.
const maxCompoundOps = 128

// These limits include an AUTH_NONE RPC header and an empty COMPOUND tag.
// The request has one SEQUENCE operation. The reply has one successful
// SEQUENCE result. Neither limit includes a TCP record marker.
const (
	minSessionRequestSize  = 40 + 12 + 36
	minSessionResponseSize = 24 + 12 + 44
)

// compound is the execution state of one COMPOUND procedure.
type compound struct {
	s   *Server
	c   *conn
	m   *stateManager
	req Request

	minor  uint32
	numOps int
	opIdx  int
	reqLen int // size of the RPC call message

	// Session state, set by SEQUENCE.
	sess      *session
	cl        *client
	slot      *slot
	slotID    uint32
	seqID     uint32
	cacheThis bool
	replay    []byte // cached reply to send instead, for a replayed request

	// maxResp is the maximum size of the COMPOUND reply without its RPC
	// header. replyStart is the reply's offset in the reply encoder.
	maxResp        int
	replyStart     int
	replyHeaderLen int // RPC reply header, without the TCP record marker

	curFH, savedFH FileHandle
	curSID         *stateID
	savedSID       *stateID

	// curAttrs caches the attributes of curFH, if known. curAttrsWant is
	// the want mask they were fetched with, and curAttrsEpoch the
	// stateManager's invalidation epoch from before they were fetched.
	curAttrs      *Attrs
	curAttrsWant  AttrMask
	curAttrsEpoch uint64

	// grants are delegations granted by this compound. Their replySent
	// flag is set once the reply is sent.
	grants []*delegState
}

func newCompound(c *conn, cred Cred, reqLen int) *compound {
	cp := &compound{
		s:       c.srv,
		c:       c,
		m:       c.srv.state,
		reqLen:  reqLen,
		maxResp: c.srv.maxRecordSize(),
	}
	cp.req = Request{
		ctx:        c.ctx,
		Cred:       cred,
		RemoteAddr: c.nc.RemoteAddr(),
		LocalAddr:  c.nc.LocalAddr(),
	}
	return cp
}

// opHandler executes one operation, decoding its arguments from d and
// encoding its results (after the status, which the caller encodes) to e.
// If it returns a status other than OK, anything it encoded is discarded.
type opHandler func(cp *compound, d *xdr.Decoder, e *xdr.Encoder) Status

var opHandlers map[Op]opHandler

func init() {
	opHandlers = map[Op]opHandler{
		OpExchangeID:        (*compound).opExchangeID,
		OpCreateSession:     (*compound).opCreateSession,
		OpDestroySession:    (*compound).opDestroySession,
		OpDestroyClientID:   (*compound).opDestroyClientID,
		OpBindConnToSession: (*compound).opBindConnToSession,
		OpSequence:          (*compound).opSequence,
		OpReclaimComplete:   (*compound).opReclaimComplete,

		OpPutRootFH:     (*compound).opPutRootFH,
		OpPutPubFH:      (*compound).opPutRootFH,
		OpPutFH:         (*compound).opPutFH,
		OpGetFH:         (*compound).opGetFH,
		OpSaveFH:        (*compound).opSaveFH,
		OpRestoreFH:     (*compound).opRestoreFH,
		OpLookup:        (*compound).opLookup,
		OpLookupp:       (*compound).opLookupp,
		OpGetAttr:       (*compound).opGetAttr,
		OpVerify:        (*compound).opVerify,
		OpNVerify:       (*compound).opNVerify,
		OpAccess:        (*compound).opAccess,
		OpReadLink:      (*compound).opReadLink,
		OpReadDir:       (*compound).opReadDir,
		OpRead:          (*compound).opRead,
		OpSecInfo:       (*compound).opSecInfo,
		OpSecInfoNoName: (*compound).opSecInfoNoName,
		OpSeek:          (*compound).opSeek,

		OpOpen:          (*compound).opOpen,
		OpClose:         (*compound).opClose,
		OpOpenDowngrade: (*compound).opOpenDowngrade,
		OpLock:          (*compound).opLock,
		OpLockT:         (*compound).opLockT,
		OpLockU:         (*compound).opLockU,
		OpTestStateID:   (*compound).opTestStateID,
		OpFreeStateID:   (*compound).opFreeStateID,

		OpDelegReturn:      (*compound).opDelegReturn,
		OpGetDirDelegation: (*compound).opGetDirDelegation,
	}
	for _, op := range []Op{
		OpCommit, OpCreate, OpLink, OpRemove, OpRename, OpSetAttr,
		OpWrite, OpAllocate, OpDeallocate, OpCopy, OpClone,
		OpWriteSame, OpSetXattr, OpRemoveXattr,
	} {
		opHandlers[op] = (*compound).opReadOnly
	}
	for _, op := range []Op{
		OpDelegPurge, OpOpenAttr, OpBackchannelCtl, OpGetDeviceInfo,
		OpGetDeviceList, OpLayoutCommit, OpLayoutGet, OpLayoutReturn,
		OpSetSSV, OpWantDelegation, OpCopyNotify, OpIOAdvise,
		OpLayoutError, OpLayoutStats, OpOffloadCancel, OpOffloadStatus,
		OpReadPlus, OpGetXattr, OpListXattrs,
	} {
		opHandlers[op] = (*compound).opNotSupp
	}
	// NFSv4.0-only operations are illegal in NFSv4.1 (OpenConfirm,
	// Renew, SetClientID, SetClientIDConfirm, ReleaseLockOwner) and
	// get NFS4ERR_NOTSUPP per RFC 8881 section 18.
	for _, op := range []Op{OpOpenConfirm, OpRenew, OpSetClientID, OpSetClientIDConfirm, OpReleaseLockOwner} {
		opHandlers[op] = (*compound).opNotSupp
	}
}

// sessionlessOps may be the first (and then only) operation of a COMPOUND
// without a SEQUENCE.
var sessionlessOps = map[Op]bool{
	OpExchangeID:        true,
	OpCreateSession:     true,
	OpDestroySession:    true,
	OpDestroyClientID:   true,
	OpBindConnToSession: true,
}

// ops42 are the operations new in NFSv4.2.
func isOp42(op Op) bool { return op >= OpAllocate && op <= OpRemoveXattr }

// run executes the COMPOUND whose arguments are args, appending the
// COMPOUND4res to e.
func (cp *compound) run(args []byte, e *xdr.Encoder) {
	start := e.Len()
	cp.replyStart = start
	cp.replyHeaderLen = start - oncrpc.RecordHeaderLen
	cp.maxResp -= cp.replyHeaderLen
	d := xdr.NewDecoder(args)
	tag := d.Opaque(maxOpaque)
	cp.minor = d.Uint32()
	numOps := d.ArrayLen(1<<20, 4)

	statusOff := e.Reserve(4)
	e.Opaque(tag)
	countOff := e.Reserve(4)

	if err := d.Err(); err != nil {
		e.PutUint32At(statusOff, uint32(ErrBadXDR))
		return
	}
	cp.s.stats.compounds.Add(1)
	if cp.minor != 1 && cp.minor != 2 {
		e.PutUint32At(statusOff, uint32(ErrMinorVersMismatch))
		return
	}
	cp.req.MinorVersion = cp.minor
	cp.numOps = numOps
	if numOps > maxCompoundOps {
		// Report it on the first operation, as servers commonly do.
		numOps = 1
	}

	defer cp.finishSlot()

	var status Status
	nres := 0
	for i := range numOps {
		cp.opIdx = i
		op := Op(d.Uint32())
		if d.Err() != nil {
			status = ErrBadXDR
			break
		}
		resStart := e.Len()
		e.Uint32(uint32(op))
		stOff := e.Reserve(4)
		bodyStart := e.Len()
		nres++

		status = cp.dispatch(op, d, e)
		if cp.replay != nil {
			e.Truncate(start)
			e.FixedOpaque(cp.replay)
			return
		}
		if status == OK && cp.numOps > maxCompoundOps {
			status = ErrTooManyOps
		}
		replySize := e.Len() - start
		if i+1 < numOps {
			// Leave room for the next operation's error result.
			replySize += 8
		}
		if status == OK && replySize > cp.maxResp {
			status = ErrRepTooBig
		}
		if status == OK && cp.cacheThis && cp.sess != nil && replySize+cp.replyHeaderLen > int(cp.sess.fore.maxResponseCached) {
			status = ErrRepTooBigToCache
		}
		if op == OpIllegal || opHandlers[op] == nil || (cp.minor < 2 && isOp42(op)) {
			// The result of an unknown operation is reported as
			// OP_ILLEGAL.
			e.PutUint32At(resStart, uint32(OpIllegal))
		}
		e.PutUint32At(stOff, uint32(status))
		if status != OK {
			e.Truncate(bodyStart)
		}
		cp.s.debugf("nfsv4: %v op %d/%d %v: %v", cp.c.nc.RemoteAddr(), i+1, cp.numOps, op, status)
		if status != OK {
			break
		}
	}
	e.PutUint32At(statusOff, uint32(status))
	e.PutUint32At(countOff, uint32(nres))

	if cp.slot != nil && cp.cacheThis {
		reply := e.Bytes()[start:]
		cp.m.mu.Lock()
		if cp.slot.seqid == cp.seqID && len(reply)+cp.replyHeaderLen <= int(cp.sess.fore.maxResponseCached) {
			cp.slot.reply = append([]byte(nil), reply...)
		}
		cp.m.mu.Unlock()
	}
}

// dispatch runs one operation, recovering from panics in FS code.
func (cp *compound) dispatch(op Op, d *xdr.Decoder, e *xdr.Encoder) (status Status) {
	cp.s.countOp(op)
	h := opHandlers[op]
	if h == nil || op == OpIllegal {
		return ErrOpIllegal
	}
	if cp.minor < 2 && isOp42(op) {
		return ErrOpIllegal
	}
	if cp.opIdx == 0 {
		if op != OpSequence && !sessionlessOps[op] {
			return ErrOpNotInSession
		}
		if sessionlessOps[op] && cp.numOps > 1 {
			return ErrNotOnlyOp
		}
	} else if op == OpSequence {
		return ErrSequencePos
	}
	defer func() {
		if r := recover(); r != nil {
			cp.s.logf("nfsv4: panic in %v: %v\n%s", op, r, debug.Stack())
			status = ErrServerFault
		}
	}()
	return h(cp, d, e)
}

// finishSlot releases the session slot used by the compound, if any.
func (cp *compound) finishSlot() {
	if cp.slot == nil {
		return
	}
	cp.m.mu.Lock()
	if cp.slot.seqid == cp.seqID {
		cp.slot.inUse = false
	}
	cp.m.mu.Unlock()
}

// afterReplySent is called after the reply has been written to the
// connection.
func (cp *compound) afterReplySent() {
	if len(cp.grants) == 0 {
		return
	}
	cp.m.mu.Lock()
	defer cp.m.mu.Unlock()
	for _, d := range cp.grants {
		d.replySent = true
	}
}

// fsErr converts an error from the FS to a status, logging errors that
// don't map to a specific status.
func (cp *compound) fsErr(op string, err error) Status {
	st, ok := statusOf(err)
	if !ok {
		cp.s.logf("nfsv4: FS.%s: %v", op, err)
	}
	if st == OK {
		// Defensive: an error that maps to OK is a bug in the FS.
		cp.s.logf("nfsv4: FS.%s returned an error with status OK: %v", op, err)
		st = ErrServerFault
	}
	return st
}

// needFH returns ErrNoFileHandle if there's no current filehandle.
func (cp *compound) needFH() Status {
	if cp.curFH == nil {
		return ErrNoFileHandle
	}
	return OK
}

// setFH sets the current filehandle. attrs, if non-nil, are its known
// attributes, fetched after invalidation epoch attrsEpoch (see setFHEpoch).
func (cp *compound) setFH(fh FileHandle, attrs *Attrs) {
	cp.setFHEpoch(fh, attrs, 0)
}

// setFHEpoch is like setFH, with the invalidation epoch from before attrs
// were fetched.
func (cp *compound) setFHEpoch(fh FileHandle, attrs *Attrs, attrsEpoch uint64) {
	cp.curAttrsEpoch = attrsEpoch
	cp.curFH = fh
	cp.curSID = nil
	cp.curAttrs = attrs
	if attrs != nil {
		cp.curAttrsWant = allAttrs
	} else {
		cp.curAttrsWant = AttrMask{}
	}
}

// basicAttrs are the attributes always included in the want mask passed to
// FS.GetAttr, so that the attributes fetched for one operation can be
// reused by the next ones in the same COMPOUND.
var basicAttrs = MakeAttrMask(
	AttrType,
	AttrChange,
	AttrSize,
	AttrFileID,
	AttrMode,
	AttrNumLinks,
	AttrOwner,
	AttrOwnerGroup,
	AttrTimeModify,
	AttrTimeMetadata,
	AttrTimeAccess,
)

var allAttrs = func() AttrMask {
	var m AttrMask
	for i := range m.w {
		m.w[i] = ^uint32(0)
	}
	return m
}()

// getAttrs returns the attributes of the current filehandle, using the
// cached copy if it was fetched with a superset of want.
func (cp *compound) getAttrs(want AttrMask) (*Attrs, Status) {
	if st := cp.needFH(); st != OK {
		return nil, st
	}
	want = want.AndNot(serverAttrs).Or(basicAttrs)
	if cp.curAttrs != nil && cp.curAttrsWant.ContainsAll(want) {
		return cp.curAttrs, OK
	}
	epoch := cp.m.invalEpochNow()
	a, err := cp.s.FS.GetAttr(&cp.req, cp.curFH, want)
	if err != nil {
		return nil, cp.fsErr("GetAttr", err)
	}
	if a == nil {
		cp.s.logf("nfsv4: FS.GetAttr returned nil attributes")
		return nil, ErrServerFault
	}
	cp.curAttrs = a
	cp.curAttrsWant = want
	cp.curAttrsEpoch = epoch
	return a, OK
}

// attrSource returns an attrSource for encoding the attributes of fh.
func (cp *compound) attrSource(fh FileHandle, a *Attrs, want AttrMask) (*attrSource, Status) {
	src := &attrSource{
		fs:    &cp.s.fsAttrs,
		minor: cp.minor,
		fh:    fh,
		attrs: a,
	}
	if !want.And(statfsAttrs).IsEmpty() {
		if sf, ok := cp.s.FS.(StatFSer); ok {
			st, err := sf.StatFS(&cp.req, fh)
			if err != nil {
				return nil, cp.fsErr("StatFS", err)
			}
			src.statfs = st
		}
	}
	return src, OK
}

func (cp *compound) opReadOnly(d *xdr.Decoder, e *xdr.Encoder) Status {
	return ErrROFS
}

func (cp *compound) opNotSupp(d *xdr.Decoder, e *xdr.Encoder) Status {
	return ErrNotSupp
}

// errBadXDR is a decoding error for semantic problems.
var errBadXDR = errors.New("bad XDR")

// decodeErr returns ErrBadXDR if d has an error.
func decodeErr(d *xdr.Decoder) Status {
	if d.Err() != nil {
		return ErrBadXDR
	}
	return OK
}

func (cp *compound) String() string {
	return fmt.Sprintf("compound(%v)", cp.c.nc.RemoteAddr())
}
