// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4

import (
	"bytes"
	"slices"
	"strings"

	"github.com/tailscale/nfsv4/internal/oncrpc"
	"github.com/tailscale/nfsv4/internal/xdr"
)

func (cp *compound) opPutRootFH(d *xdr.Decoder, e *xdr.Encoder) Status {
	fh, err := cp.s.FS.Root(&cp.req)
	if err != nil {
		return cp.fsErr("Root", err)
	}
	cp.setFH(fh, nil)
	return OK
}

func (cp *compound) opPutFH(d *xdr.Decoder, e *xdr.Encoder) Status {
	fh := d.Opaque(MaxFileHandleSize)
	if st := decodeErr(d); st != OK {
		return st
	}
	if len(fh) == 0 {
		return ErrBadHandle
	}
	epoch := cp.m.invalEpochNow()
	a, err := cp.s.FS.GetAttr(&cp.req, FileHandle(fh), basicAttrs)
	if err != nil {
		st := cp.fsErr("GetAttr", err)
		switch st {
		case ErrBadHandle, ErrStale, ErrDelay, ErrMoved, ErrWrongSec, ErrServerFault:
			return st
		default:
			// PUTFH cannot return other FS errors (RFC 8881, Section 15.2).
			// The arguments are decoded above; a backend BADXDR is not valid here.
			cp.s.logf("nfsv4: PUTFH: FS.GetAttr returned unsupported status %v: %v; returning NFS4ERR_SERVERFAULT", st, err)
			return ErrServerFault
		}
	}
	if a == nil {
		cp.s.logf("nfsv4: FS.GetAttr returned nil attributes")
		return ErrServerFault
	}
	cp.setFHEpoch(FileHandle(fh), a, epoch)
	cp.curAttrsWant = basicAttrs
	return OK
}

func (cp *compound) opGetFH(d *xdr.Decoder, e *xdr.Encoder) Status {
	if st := cp.needFH(); st != OK {
		return st
	}
	e.Opaque(cp.curFH)
	return OK
}

func (cp *compound) opSaveFH(d *xdr.Decoder, e *xdr.Encoder) Status {
	if st := cp.needFH(); st != OK {
		return st
	}
	cp.savedFH = cp.curFH
	cp.savedSID = cp.curSID
	return OK
}

func (cp *compound) opRestoreFH(d *xdr.Decoder, e *xdr.Encoder) Status {
	if cp.savedFH == nil {
		return ErrRestoreFH
	}
	cp.setFH(cp.savedFH, nil)
	cp.curSID = cp.savedSID
	return OK
}

// checkName validates a component name from a client.
func (cp *compound) checkName(name string) Status {
	switch {
	case name == "":
		return ErrInval
	case len(name) > int(cp.s.fsAttrs.maxName):
		return ErrNameTooLong
	case name == "." || name == "..":
		return ErrBadName
	case strings.ContainsAny(name, "/\x00"):
		return ErrBadChar
	}
	return OK
}

func (cp *compound) opLookup(d *xdr.Decoder, e *xdr.Encoder) Status {
	name := d.String(maxOpaque)
	if st := decodeErr(d); st != OK {
		return st
	}
	if st := cp.needFH(); st != OK {
		return st
	}
	if st := cp.checkName(name); st != OK {
		return st
	}
	epoch := cp.m.invalEpochNow()
	fh, attrs, err := cp.s.FS.Lookup(&cp.req, cp.curFH, name)
	if err != nil {
		return cp.fsErr("Lookup", err)
	}
	cp.setFHEpoch(fh, attrs, epoch)
	return OK
}

// isRoot reports whether fh is the root filehandle.
func (cp *compound) isRoot(fh FileHandle) (bool, Status) {
	root, err := cp.s.FS.Root(&cp.req)
	if err != nil {
		return false, cp.fsErr("Root", err)
	}
	return bytes.Equal(root, fh), OK
}

func (cp *compound) opLookupp(d *xdr.Decoder, e *xdr.Encoder) Status {
	if st := cp.needFH(); st != OK {
		return st
	}
	if isRoot, st := cp.isRoot(cp.curFH); st != OK {
		return st
	} else if isRoot {
		return ErrNoEnt
	}
	fh, err := cp.s.FS.LookupParent(&cp.req, cp.curFH)
	if err != nil {
		return cp.fsErr("LookupParent", err)
	}
	cp.setFH(fh, nil)
	return OK
}

// needsFSAttrs reports whether encoding the attributes in want requires
// asking the FS.
func needsFSAttrs(want AttrMask) bool {
	return !want.AndNot(serverAttrs).AndNot(statfsAttrs).IsEmpty()
}

func (cp *compound) opGetAttr(d *xdr.Decoder, e *xdr.Encoder) Status {
	want := decodeBitmap(d)
	if st := decodeErr(d); st != OK {
		return st
	}
	if st := cp.needFH(); st != OK {
		return st
	}
	var a *Attrs
	if needsFSAttrs(want) {
		var st Status
		a, st = cp.getAttrs(want)
		if st != OK {
			return st
		}
	}
	src, st := cp.attrSource(cp.curFH, a, want)
	if st != OK {
		return st
	}
	encodeFattr(e, src, want)
	return OK
}

func (cp *compound) opVerify(d *xdr.Decoder, e *xdr.Encoder) Status {
	return cp.verify(d, false)
}

func (cp *compound) opNVerify(d *xdr.Decoder, e *xdr.Encoder) Status {
	return cp.verify(d, true)
}

func (cp *compound) verify(d *xdr.Decoder, negate bool) Status {
	mask := decodeBitmap(d)
	vals := d.Opaque(1 << 20)
	if st := decodeErr(d); st != OK {
		return st
	}
	if st := cp.needFH(); st != OK {
		return st
	}
	var a *Attrs
	if needsFSAttrs(mask) {
		var st Status
		a, st = cp.getAttrs(mask)
		if st != OK {
			return st
		}
	}
	src, st := cp.attrSource(cp.curFH, a, mask)
	if st != OK {
		return st
	}
	same, st := fattrEqual(src, mask, vals)
	if st != OK {
		return st
	}
	switch {
	case negate && same:
		return ErrSame
	case !negate && !same:
		return ErrNotSame
	}
	return OK
}

const supportedAccess = AccessRead | AccessLookup | AccessModify | AccessExtend | AccessDelete | AccessExecute

func (cp *compound) opAccess(d *xdr.Decoder, e *xdr.Encoder) Status {
	req := d.Uint32()
	if st := decodeErr(d); st != OK {
		return st
	}
	a, st := cp.getAttrs(MakeAttrMask(AttrType, AttrMode, AttrOwner, AttrOwnerGroup))
	if st != OK {
		return st
	}
	supported := req & supportedAccess
	var allowed uint32
	if ac, ok := cp.s.FS.(Accesser); ok {
		var err error
		allowed, err = ac.Access(&cp.req, cp.curFH, a, supported)
		if err != nil {
			return cp.fsErr("Access", err)
		}
	} else {
		allowed = defaultAccess(a, &cp.req.Cred)
	}
	e.Uint32(supported)
	e.Uint32(allowed & supported)
	return OK
}

// defaultAccess computes the access a read-only server allows to an
// object with attributes a for the given credential, based on its mode
// bits.
func defaultAccess(a *Attrs, cred *Cred) uint32 {
	var perm uint32 // rwx
	switch {
	case cred.Flavor == oncrpc.AuthSys && cred.UID == 0:
		perm = 0o6
		if a.Type == TypeDir || a.Mode&0o111 != 0 {
			perm |= 0o1
		}
	case cred.Flavor == oncrpc.AuthSys && cred.UID == a.UID:
		perm = (a.Mode >> 6) & 7
	case cred.Flavor == oncrpc.AuthSys && (cred.GID == a.GID || slices.Contains(cred.GIDs, a.GID)):
		perm = (a.Mode >> 3) & 7
	default:
		perm = a.Mode & 7
	}
	var allowed uint32
	if perm&0o4 != 0 {
		allowed |= AccessRead
	}
	if perm&0o1 != 0 {
		if a.Type == TypeDir {
			allowed |= AccessLookup | AccessExecute
		} else {
			allowed |= AccessExecute
		}
	}
	return allowed
}

func (cp *compound) opReadLink(d *xdr.Decoder, e *xdr.Encoder) Status {
	if st := cp.needFH(); st != OK {
		return st
	}
	target, err := cp.s.FS.ReadLink(&cp.req, cp.curFH)
	if err != nil {
		return cp.fsErr("ReadLink", err)
	}
	e.String(target)
	return OK
}

func (cp *compound) opReadDir(d *xdr.Decoder, e *xdr.Encoder) Status {
	cookie := d.Uint64()
	verf := d.Uint64()
	dirCount := d.Uint32()
	maxCount := d.Uint32()
	want := decodeBitmap(d)
	if st := decodeErr(d); st != OK {
		return st
	}
	if st := cp.needFH(); st != OK {
		return st
	}
	if cookie == 1 || cookie == 2 {
		return ErrBadCookie
	}
	if cookie == 0 && verf != 0 {
		// RFC 8881 requires a zero verifier with a zero cookie, but
		// clients aren't consistent about it; ignore it.
		verf = 0
	}

	resStart := e.Len()
	// Leave room for the rest of the compound reply (at least the
	// final "no more entries" and eof words).
	limit := int(maxCount)
	if avail := cp.maxResp - (resStart - cp.replyStart) - 64; limit > avail {
		limit = avail
	}
	verfOff := e.Reserve(8)

	needFS := needsFSAttrs(want)
	wantFH := want.Has(AttrFileHandle)
	var (
		n         int
		dirBytes  int
		full      bool
		entryErr  Status
		rdattrErr = want.Has(AttrRdAttrError)
	)
	emit := func(ent DirEntry) bool {
		if full || entryErr != OK {
			return false
		}
		if ent.Cookie < 3 {
			cp.s.logf("nfsv4: FS.ReadDir returned reserved cookie %d for %q", ent.Cookie, ent.Name)
			entryErr = ErrServerFault
			return false
		}
		entStart := e.Len()
		e.Uint32(1) // value follows
		e.Uint64(ent.Cookie)
		e.String(ent.Name)

		attrs := ent.Attrs
		var st Status
		if (needFS || wantFH) && ent.Handle == nil {
			cp.s.logf("nfsv4: FS.ReadDir returned entry %q without a filehandle", ent.Name)
			st = ErrServerFault
		} else if needFS && attrs == nil {
			a, err := cp.s.FS.GetAttr(&cp.req, ent.Handle, want.AndNot(serverAttrs))
			if err != nil {
				st = cp.fsErr("GetAttr", err)
			} else if a == nil {
				st = ErrServerFault
			}
			attrs = a
		}
		if st == OK && !want.And(statfsAttrs).IsEmpty() {
			// Rare; let attrSource fetch them.
			var src *attrSource
			src, st = cp.attrSource(ent.Handle, attrs, want)
			if st == OK {
				encodeFattr(e, src, want)
			}
		} else if st == OK {
			encodeFattr(e, &attrSource{fs: &cp.s.fsAttrs, minor: cp.minor, fh: ent.Handle, attrs: attrs}, want)
		}
		if st != OK {
			if !rdattrErr {
				e.Truncate(entStart)
				entryErr = st
				return false
			}
			e.Truncate(entStart)
			e.Uint32(1)
			e.Uint64(ent.Cookie)
			e.String(ent.Name)
			encodeFattr(e, &attrSource{fs: &cp.s.fsAttrs, minor: cp.minor, fh: ent.Handle, rdErr: st}, MakeAttrMask(AttrRdAttrError))
		}

		entDirBytes := 8 + 4 + len(ent.Name) + xdr.Pad(len(ent.Name))
		if e.Len()-resStart+8 > limit || (n > 0 && dirCount > 0 && dirBytes+entDirBytes > int(dirCount)) {
			e.Truncate(entStart)
			full = true
			return false
		}
		dirBytes += entDirBytes
		n++
		return true
	}
	fsWant := want.AndNot(serverAttrs)
	if wantFH {
		fsWant.Set(AttrFileHandle)
	}
	res, err := cp.s.FS.ReadDir(&cp.req, cp.curFH, ReadDirArgs{
		Cookie:   cookie,
		Verifier: verf,
		Want:     fsWant,
	}, emit)
	if err != nil {
		return cp.fsErr("ReadDir", err)
	}
	if entryErr != OK {
		return entryErr
	}
	if full && n == 0 {
		return ErrTooSmall
	}
	e.PutUint32At(verfOff, uint32(res.Verifier>>32))
	e.PutUint32At(verfOff+4, uint32(res.Verifier))
	e.Uint32(0) // no more entries
	e.Bool(!full)
	return OK
}

func (cp *compound) opRead(d *xdr.Decoder, e *xdr.Encoder) Status {
	sid := decodeStateID(d)
	off := d.Uint64()
	count := d.Uint32()
	if st := decodeErr(d); st != OK {
		return st
	}
	if st := cp.needFH(); st != OK {
		return st
	}
	if st := cp.checkReadStateID(sid); st != OK {
		return st
	}
	n := min(int(count), cp.s.MaxIO)
	if avail := cp.maxResp - (e.Len() - cp.replyStart) - 64; n > avail {
		n = max(avail, 0)
	}
	eofOff := e.Reserve(4)
	lenOff := e.Reserve(4)
	dataOff, p := e.Grow(n)
	got, eof, err := cp.s.FS.Read(&cp.req, cp.curFH, off, p)
	if err != nil {
		return cp.fsErr("Read", err)
	}
	if got < 0 || got > n {
		cp.s.logf("nfsv4: FS.Read returned invalid count %d for buffer of %d", got, n)
		return ErrServerFault
	}
	e.Truncate(dataOff + got)
	e.Reserve(xdr.Pad(got))
	e.PutUint32At(eofOff, boolWord(eof))
	e.PutUint32At(lenOff, uint32(got))
	return OK
}

func boolWord(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// checkReadStateID validates a stateid used for reading the current file.
//
// Unknown and outdated stateids are accepted, as if they were the
// anonymous stateid. On a read-only server, stateids don't affect what a
// READ may do, and the macOS client (as of macOS 26) retries a READ
// interrupted by a server restart with its pre-restart stateid even after
// successfully reclaiming its open state, looping forever if the READ is
// refused. Stateids for other files and revoked delegations are still
// rejected, so clients learn about those.
func (cp *compound) checkReadStateID(sid stateID) Status {
	cp.m.mu.Lock()
	defer cp.m.mu.Unlock()
	st, status := cp.m.lookupStateLocked(cp.cl, sid, cp.curSID)
	switch status {
	case OK:
	case ErrBadStateID, ErrOldStateID:
		cp.s.debugf("nfsv4: client %#x used stateid %v for %x (%v); allowing the read", cp.cl.id, sid, cp.curFH, status)
		return OK
	default:
		return status
	}
	var fh FileHandle
	switch st := st.(type) {
	case nil:
		return OK // special stateid
	case *openState:
		fh = st.fh
	case *lockState:
		fh = st.open.fh
	case *delegState:
		fh = st.fh
	}
	if !bytes.Equal(fh, cp.curFH) {
		cp.s.debugf("nfsv4: client %#x used stateid %v for %x, but it's for %x", cp.cl.id, sid, cp.curFH, fh)
		return ErrBadStateID
	}
	return OK
}

func (cp *compound) opSecInfo(d *xdr.Decoder, e *xdr.Encoder) Status {
	name := d.String(maxOpaque)
	if st := decodeErr(d); st != OK {
		return st
	}
	if st := cp.needFH(); st != OK {
		return st
	}
	if st := cp.checkName(name); st != OK {
		return st
	}
	if _, _, err := cp.s.FS.Lookup(&cp.req, cp.curFH, name); err != nil {
		return cp.fsErr("Lookup", err)
	}
	encodeSecInfo(e)
	cp.setFH(nil, nil) // SECINFO consumes the current filehandle
	return OK
}

func (cp *compound) opSecInfoNoName(d *xdr.Decoder, e *xdr.Encoder) Status {
	style := d.Uint32()
	if st := decodeErr(d); st != OK {
		return st
	}
	if st := cp.needFH(); st != OK {
		return st
	}
	switch style {
	case secinfoStyleCurrentFH:
	case secinfoStyleParent:
		if isRoot, st := cp.isRoot(cp.curFH); st != OK {
			return st
		} else if isRoot {
			return ErrNoEnt
		}
	default:
		return ErrInval
	}
	encodeSecInfo(e)
	cp.setFH(nil, nil)
	return OK
}

// encodeSecInfo encodes the supported security flavors: just AUTH_SYS.
// (AUTH_NONE requests are accepted too.)
func encodeSecInfo(e *xdr.Encoder) {
	e.Uint32(1)
	e.Uint32(oncrpc.AuthSys)
}

func (cp *compound) opSeek(d *xdr.Decoder, e *xdr.Encoder) Status {
	sid := decodeStateID(d)
	off := d.Uint64()
	what := d.Uint32()
	if st := decodeErr(d); st != OK {
		return st
	}
	if st := cp.needFH(); st != OK {
		return st
	}
	if st := cp.checkReadStateID(sid); st != OK {
		return st
	}
	a, st := cp.getAttrs(MakeAttrMask(AttrType, AttrSize))
	if st != OK {
		return st
	}
	switch a.Type {
	case TypeReg:
	case TypeDir:
		return ErrIsDir
	default:
		return ErrInval
	}
	if off >= a.Size {
		return ErrNXIO
	}
	switch what {
	case seekData:
		e.Bool(false)
		e.Uint64(off)
	case seekHole:
		e.Bool(true)
		e.Uint64(a.Size)
	default:
		return ErrUnionNotSupp
	}
	return OK
}
