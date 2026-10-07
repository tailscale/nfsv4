// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4

import (
	"bytes"
	"slices"

	"github.com/tailscale/nfsv4/internal/xdr"
)

// ACE values for the permissions field of read delegations.
const (
	ace4AccessAllowed = 0
)

func (cp *compound) opOpen(d *xdr.Decoder, e *xdr.Encoder) Status {
	d.Uint32() // seqid; unused in NFSv4.1
	access := d.Uint32()
	deny := d.Uint32()
	d.Uint64() // open owner's client ID; the session's is used instead
	owner := d.Opaque(maxOpaque)
	openType := d.Uint32()
	var createMode uint32
	switch openType {
	case opentypeNoCreate:
	case opentypeCreate:
		createMode = d.Uint32()
		switch createMode {
		case createUnchecked, createGuarded:
			decodeBitmap(d)
			d.Opaque(1 << 16)
		case createExclusive:
			d.FixedOpaque(verifierSize)
		case createExclusive4:
			d.FixedOpaque(verifierSize)
			decodeBitmap(d)
			d.Opaque(1 << 16)
		default:
			d.SetErr(errBadXDR)
		}
	default:
		d.SetErr(errBadXDR)
	}
	claimType := d.Uint32()
	var (
		name     string
		delegSID stateID
	)
	switch claimType {
	case claimNull, claimDelegatePrev:
		name = d.String(maxOpaque)
	case claimPrevious:
		// After a server restart, the client reclaims its opens. Opens
		// can't conflict on a read-only server, so reclaims are always
		// accepted. If the client is reclaiming a delegation, the
		// policy decides afresh whether it gets one.
		d.Uint32() // delegation type being reclaimed
	case claimDelegateCur:
		delegSID = decodeStateID(d)
		name = d.String(maxOpaque)
	case claimFH, claimDelegPrevFH:
	case claimDelegCurFH:
		delegSID = decodeStateID(d)
	default:
		d.SetErr(errBadXDR)
	}
	if st := decodeErr(d); st != OK {
		return st
	}
	if st := cp.needFH(); st != OK {
		return st
	}

	want := access & shareAccessWantDelegMask
	access &^= shareAccessWantDelegMask | shareAccessWantFlagsMask
	if access == 0 || access > shareAccessBoth || deny > shareAccessBoth {
		return ErrInval
	}
	if access&shareAccessWrite != 0 {
		return ErrROFS
	}
	switch claimType {
	case claimDelegatePrev, claimDelegPrevFH:
		// Reclaiming delegations across a client restart isn't
		// supported (and not used by Linux or macOS).
		return ErrNotSupp
	}

	byName := claimType == claimNull || claimType == claimDelegateCur
	if openType == opentypeCreate && claimType != claimNull {
		return ErrInval
	}

	epoch := cp.m.invalEpochNow()
	var (
		fh    FileHandle
		attrs *Attrs
		dirFH FileHandle
	)
	if byName {
		if st := cp.checkName(name); st != OK {
			return st
		}
		dirFH = cp.curFH
		var err error
		fh, attrs, err = cp.s.FS.Lookup(&cp.req, dirFH, name)
		if err != nil {
			st := cp.fsErr("Lookup", err)
			if st == ErrNoEnt && openType == opentypeCreate {
				return ErrROFS
			}
			return st
		}
		if openType == opentypeCreate && createMode != createUnchecked {
			return ErrExist
		}
	} else {
		fh = cp.curFH
		if cp.curAttrs != nil && cp.curAttrsWant.ContainsAll(openAttrsWant) {
			attrs = cp.curAttrs
			epoch = cp.curAttrsEpoch
		}
	}
	if attrs == nil {
		a, err := cp.s.FS.GetAttr(&cp.req, fh, openAttrsWant)
		if err != nil {
			return cp.fsErr("GetAttr", err)
		}
		if a == nil {
			return ErrServerFault
		}
		attrs = a
	}
	switch attrs.Type {
	case TypeReg:
	case TypeDir:
		return ErrIsDir
	case TypeSymlink:
		return ErrSymlink
	default:
		return ErrWrongType
	}

	// The change_info4 for the directory matters only when the client
	// asked to create the file: the Linux client then invalidates its
	// cached directory unless the before and after values match its
	// own.
	var cinfoAtomic bool
	var cinfoChange uint64
	if openType == opentypeCreate && dirFH != nil {
		if da, err := cp.s.FS.GetAttr(&cp.req, dirFH, MakeAttrMask(AttrChange)); err == nil && da != nil {
			cinfoAtomic = true
			cinfoChange = da.Change
		}
	}

	m := cp.m
	cl := cp.cl
	delegClaim := claimType == claimDelegateCur || claimType == claimDelegCurFH
	key := openKey{owner: string(owner), fh: string(fh)}
	m.mu.Lock()
	if delegClaim {
		// The client is converting opens it did locally under a
		// delegation into real opens, typically while returning the
		// delegation.
		st, status := m.lookupStateLocked(cl, delegSID, nil)
		if status != OK {
			m.mu.Unlock()
			return status
		}
		if ds, ok := st.(*delegState); !ok || !bytes.Equal(ds.fh, fh) {
			m.mu.Unlock()
			return ErrBadStateID
		}
	}
	_, isReopen := cl.opens[key]
	m.mu.Unlock()

	// Tell the Opener about new open states only, so its Open and Close
	// calls balance.
	opener, _ := cp.s.FS.(Opener)
	if opener != nil && !isReopen {
		if err := opener.Open(&cp.req, fh, attrs); err != nil {
			return cp.fsErr("Open", err)
		}
	}

	var policy Delegation
	dg, isDelegator := cp.s.FS.(Delegator)
	if isDelegator && !delegClaim && want != shareAccessWantNoDeleg && want != shareAccessWantCancel {
		policy = dg.Delegate(&cp.req, fh, attrs)
	}

	m.mu.Lock()
	o := cl.opens[key]
	if o == nil {
		o = &openState{
			other:  m.newOther(),
			client: cl,
			key:    key,
			fh:     slices.Clone(fh),
			locks:  make(map[*lockState]bool),
		}
		cl.opens[key] = o
		m.states[o.other] = o
	} else if opener != nil && !isReopen {
		// A concurrent OPEN by the same owner created it meanwhile.
		defer opener.Close(fh)
	}
	o.seqid++
	o.access |= access
	o.deny |= deny
	sid := stateID{seqid: o.seqid, other: o.other}

	var deleg *delegState
	var why uint32
	switch {
	case want == shareAccessWantCancel:
		why = wndCancelled
	case !isDelegator:
		why = wndNotSuppFtype
	default:
		why = wndNotWanted
	}
	if policy.Grant {
		deleg, why = cp.grantDelegLocked(fh, false, policy, epoch)
	}
	m.mu.Unlock()

	cp.setFHEpoch(fh, attrs, epoch)
	cp.curAttrsWant = openAttrsWant
	cp.curSID = &sid

	encodeStateID(e, sid)
	e.Bool(cinfoAtomic)
	e.Uint64(cinfoChange)
	e.Uint64(cinfoChange)
	e.Uint32(openResultLocktypePOSIX)
	encodeBitmap(e, AttrMask{}) // attrset
	switch {
	case deleg != nil:
		e.Uint32(delegRead)
		encodeStateID(e, deleg.stateID())
		e.Bool(false) // recall
		e.Uint32(ace4AccessAllowed)
		e.Uint32(0) // flag
		e.Uint32(0) // access mask: none implied; clients use ACCESS
		e.String("EVERYONE@")
	case want != 0 && cp.minor >= 1:
		e.Uint32(delegNoneExt)
		e.Uint32(why)
		if why == wndContention || why == wndResource {
			e.Bool(false) // server won't push or signal
		}
	default:
		e.Uint32(delegNone)
	}
	return OK
}

// openAttrsWant is the attribute mask used to fetch attributes for OPEN
// and delegation decisions.
var openAttrsWant = MakeAttrMask(AttrType, AttrChange, AttrSize, AttrFileID, AttrMode, AttrOwner, AttrOwnerGroup, AttrTimeModify)

// grantDelegLocked grants a read delegation on fh to the compound's
// client if possible. It returns the delegation, or nil and a
// why_no_delegation4 reason. epoch is the invalidation epoch from before
// the object's attributes were fetched.
func (cp *compound) grantDelegLocked(fh FileHandle, isDir bool, policy Delegation, epoch uint64) (*delegState, uint32) {
	m := cp.m
	cl := cp.cl
	if m.clientBackchannelLocked(cl) == nil {
		return nil, wndResource
	}
	key := string(fh)
	if m.recalling[key] > 0 || m.invalidatedSinceLocked(key, epoch) {
		return nil, wndContention
	}
	for d := range m.delegsByFH[key] {
		if d.client == cl {
			// Already delegated to this client.
			return nil, wndNotWanted
		}
	}
	d := &delegState{
		other:     m.newOther(),
		client:    cl,
		fh:        slices.Clone(fh),
		isDir:     isDir,
		grantSess: cp.sess.id,
		grantSlot: cp.slotID,
		grantSeq:  cp.seqID,
		done:      make(chan struct{}),
	}
	m.states[d.other] = d
	cl.delegs[d.other] = d
	set := m.delegsByFH[key]
	if set == nil {
		set = make(map[*delegState]bool)
		m.delegsByFH[key] = set
	}
	set[d] = true
	if policy.MaxAge > 0 {
		d.timer = timeAfterFunc(policy.MaxAge, func() { m.startRecall(d) })
	}
	cp.grants = append(cp.grants, d)
	return d, 0
}

func (cp *compound) opClose(d *xdr.Decoder, e *xdr.Encoder) Status {
	d.Uint32() // seqid
	sid := decodeStateID(d)
	if st := decodeErr(d); st != OK {
		return st
	}
	if st := cp.needFH(); st != OK {
		return st
	}
	m := cp.m
	m.mu.Lock()
	st, status := m.lookupStateLocked(cp.cl, sid, cp.curSID)
	if status != OK {
		m.mu.Unlock()
		return status
	}
	o, ok := st.(*openState)
	if !ok || !bytes.Equal(o.fh, cp.curFH) {
		m.mu.Unlock()
		return ErrBadStateID
	}
	m.removeOpenLocked(o)
	m.mu.Unlock()
	if op, ok := cp.s.FS.(Opener); ok {
		op.Close(o.fh)
	}
	cp.curSID = &invalidStateID
	encodeStateID(e, invalidStateID)
	return OK
}

func (m *stateManager) removeOpenLocked(o *openState) {
	for l := range o.locks {
		delete(m.states, l.other)
		delete(o.client.locks, l.key)
	}
	delete(m.states, o.other)
	delete(o.client.opens, o.key)
}

func (cp *compound) opOpenDowngrade(d *xdr.Decoder, e *xdr.Encoder) Status {
	sid := decodeStateID(d)
	d.Uint32() // seqid
	access := d.Uint32() &^ (shareAccessWantDelegMask | shareAccessWantFlagsMask)
	deny := d.Uint32()
	if st := decodeErr(d); st != OK {
		return st
	}
	if st := cp.needFH(); st != OK {
		return st
	}
	m := cp.m
	m.mu.Lock()
	defer m.mu.Unlock()
	st, status := m.lookupStateLocked(cp.cl, sid, cp.curSID)
	if status != OK {
		return status
	}
	o, ok := st.(*openState)
	if !ok || !bytes.Equal(o.fh, cp.curFH) {
		return ErrBadStateID
	}
	if access == 0 || access&^o.access != 0 || deny&^o.deny != 0 {
		return ErrInval
	}
	o.access = access
	o.deny = deny
	o.seqid++
	nsid := stateID{seqid: o.seqid, other: o.other}
	cp.curSID = &nsid
	encodeStateID(e, nsid)
	return OK
}

// checkLockRange validates a lock range.
func checkLockRange(off, length uint64) Status {
	if length == 0 {
		return ErrInval
	}
	if length != ^uint64(0) && off+length < off {
		return ErrInval
	}
	return OK
}

// opLock implements LOCK. All locks are read locks (files can't be opened
// for writing), which never conflict, so every lock is granted.
func (cp *compound) opLock(d *xdr.Decoder, e *xdr.Encoder) Status {
	lockType := d.Uint32()
	d.Bool() // reclaim
	off := d.Uint64()
	length := d.Uint64()
	newOwner := d.Bool()
	var (
		openSID, lockSID stateID
		lockOwner        []byte
	)
	if newOwner {
		d.Uint32() // open seqid
		openSID = decodeStateID(d)
		d.Uint32() // lock seqid
		d.Uint64() // lock owner's client ID
		lockOwner = d.Opaque(maxOpaque)
	} else {
		lockSID = decodeStateID(d)
		d.Uint32() // lock seqid
	}
	if st := decodeErr(d); st != OK {
		return st
	}
	if st := cp.needFH(); st != OK {
		return st
	}
	switch lockType {
	case lockTypeRead, lockTypeReadW:
	case lockTypeWrite, lockTypeWriteW:
		return ErrOpenMode
	default:
		return ErrInval
	}
	if st := checkLockRange(off, length); st != OK {
		return st
	}

	m := cp.m
	m.mu.Lock()
	defer m.mu.Unlock()
	cl := cp.cl
	var l *lockState
	if newOwner {
		st, status := m.lookupStateLocked(cl, openSID, cp.curSID)
		if status != OK {
			return status
		}
		o, ok := st.(*openState)
		if !ok || !bytes.Equal(o.fh, cp.curFH) {
			return ErrBadStateID
		}
		key := lockKey{owner: string(lockOwner), fh: o.key.fh}
		l = cl.locks[key]
		if l == nil {
			l = &lockState{
				other:  m.newOther(),
				client: cl,
				key:    key,
				open:   o,
			}
			cl.locks[key] = l
			m.states[l.other] = l
			o.locks[l] = true
		}
	} else {
		st, status := m.lookupStateLocked(cl, lockSID, cp.curSID)
		if status != OK {
			return status
		}
		var ok bool
		l, ok = st.(*lockState)
		if !ok || !bytes.Equal(l.open.fh, cp.curFH) {
			return ErrBadStateID
		}
	}
	l.seqid++
	nsid := stateID{seqid: l.seqid, other: l.other}
	cp.curSID = &nsid
	encodeStateID(e, nsid)
	return OK
}

func (cp *compound) opLockT(d *xdr.Decoder, e *xdr.Encoder) Status {
	lockType := d.Uint32()
	off := d.Uint64()
	length := d.Uint64()
	d.Uint64() // lock owner's client ID
	d.Opaque(maxOpaque)
	if st := decodeErr(d); st != OK {
		return st
	}
	if st := cp.needFH(); st != OK {
		return st
	}
	if lockType < lockTypeRead || lockType > lockTypeWriteW {
		return ErrInval
	}
	// Read locks never conflict. Conflicts between a hypothetical write
	// lock test and other owners' read locks aren't tracked.
	return checkLockRange(off, length)
}

func (cp *compound) opLockU(d *xdr.Decoder, e *xdr.Encoder) Status {
	d.Uint32() // lock type
	d.Uint32() // seqid
	sid := decodeStateID(d)
	off := d.Uint64()
	length := d.Uint64()
	if st := decodeErr(d); st != OK {
		return st
	}
	if st := cp.needFH(); st != OK {
		return st
	}
	if st := checkLockRange(off, length); st != OK {
		return st
	}
	m := cp.m
	m.mu.Lock()
	defer m.mu.Unlock()
	st, status := m.lookupStateLocked(cp.cl, sid, cp.curSID)
	if status != OK {
		return status
	}
	l, ok := st.(*lockState)
	if !ok || !bytes.Equal(l.open.fh, cp.curFH) {
		return ErrBadStateID
	}
	l.seqid++
	nsid := stateID{seqid: l.seqid, other: l.other}
	cp.curSID = &nsid
	encodeStateID(e, nsid)
	return OK
}

func (cp *compound) opTestStateID(d *xdr.Decoder, e *xdr.Encoder) Status {
	n := d.ArrayLen(1024, 16)
	sids := make([]stateID, n)
	for i := range sids {
		sids[i] = decodeStateID(d)
	}
	if st := decodeErr(d); st != OK {
		return st
	}
	m := cp.m
	m.mu.Lock()
	defer m.mu.Unlock()
	e.Uint32(uint32(n))
	for _, sid := range sids {
		var status Status
		if sid == anonStateID || sid == bypassStateID || sid == currentStateID {
			status = ErrBadStateID
		} else {
			_, status = m.lookupStateLocked(cp.cl, sid, nil)
		}
		e.Uint32(uint32(status))
	}
	return OK
}

func (cp *compound) opFreeStateID(d *xdr.Decoder, e *xdr.Encoder) Status {
	sid := decodeStateID(d)
	if st := decodeErr(d); st != OK {
		return st
	}
	m := cp.m
	m.mu.Lock()
	defer m.mu.Unlock()
	if sid == currentStateID && cp.curSID != nil {
		sid = *cp.curSID
	}
	st, ok := m.states[sid.other]
	if !ok {
		return ErrBadStateID
	}
	switch st := st.(type) {
	case *delegState:
		if st.client != cp.cl {
			return ErrBadStateID
		}
		if !st.revoked {
			return ErrLocksHeld
		}
		delete(m.states, st.other)
		delete(st.client.revoked, st.other)
	case *lockState:
		if st.client != cp.cl {
			return ErrBadStateID
		}
		delete(m.states, st.other)
		delete(st.client.locks, st.key)
		delete(st.open.locks, st)
	case *openState:
		if st.client != cp.cl {
			return ErrBadStateID
		}
		return ErrLocksHeld
	}
	return OK
}

func (cp *compound) opDelegReturn(d *xdr.Decoder, e *xdr.Encoder) Status {
	sid := decodeStateID(d)
	if st := decodeErr(d); st != OK {
		return st
	}
	if st := cp.needFH(); st != OK {
		return st
	}
	m := cp.m
	m.mu.Lock()
	defer m.mu.Unlock()
	st, status := m.lookupStateLocked(cp.cl, sid, cp.curSID)
	if status != OK {
		return status
	}
	ds, ok := st.(*delegState)
	if !ok || !bytes.Equal(ds.fh, cp.curFH) {
		return ErrBadStateID
	}
	m.removeDelegLocked(ds)
	return OK
}

// opGetDirDelegation implements GET_DIR_DELEGATION (RFC 8881 section
// 18.39). Notifications aren't supported: the delegation is simply recalled
// when the directory changes.
func (cp *compound) opGetDirDelegation(d *xdr.Decoder, e *xdr.Encoder) Status {
	d.Bool() // signal when available
	decodeBitmap(d)
	d.Int64() // child attr delay
	d.Uint32()
	d.Int64() // dir attr delay
	d.Uint32()
	decodeBitmap(d) // child attributes
	decodeBitmap(d) // dir attributes
	if st := decodeErr(d); st != OK {
		return st
	}
	if st := cp.needFH(); st != OK {
		return st
	}
	a, st := cp.getAttrs(openAttrsWant)
	if st != OK {
		return st
	}
	epoch := cp.curAttrsEpoch
	if a.Type != TypeDir {
		return ErrNotDir
	}
	var policy Delegation
	if dg, ok := cp.s.FS.(Delegator); ok {
		policy = dg.Delegate(&cp.req, cp.curFH, a)
	}
	var deleg *delegState
	if policy.Grant {
		cp.m.mu.Lock()
		deleg, _ = cp.grantDelegLocked(cp.curFH, true, policy, epoch)
		cp.m.mu.Unlock()
	}
	if deleg == nil {
		e.Uint32(gddUnavail)
		e.Bool(false) // won't signal availability
		return OK
	}
	e.Uint32(gddOK)
	e.Uint64(0) // cookie verifier
	encodeStateID(e, deleg.stateID())
	// The Linux client decodes these bitmaps into a single word, so
	// they must have exactly length 1 or 0.
	encodeOneWordBitmap(e, 0) // notifications
	encodeOneWordBitmap(e, 0) // child attributes
	encodeOneWordBitmap(e, 0) // dir attributes
	return OK
}

func encodeOneWordBitmap(e *xdr.Encoder, w uint32) {
	e.Uint32(1)
	e.Uint32(w)
}
