// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4

import (
	"slices"
	"time"

	"github.com/tailscale/nfsv4/internal/oncrpc"
	"github.com/tailscale/nfsv4/internal/xdr"
)

const (
	// maxSlots is the maximum number of fore channel slots per session.
	maxSlots = 64

	// maxCachedReply is the largest reply the server caches per slot
	// for replays.
	maxCachedReply = 64 << 10

	// maxSessionsPerClient and maxClients bound the state clients can
	// make the server keep.
	maxSessionsPerClient = 16
	maxClients           = 10000

	authGSS = 6 // RPCSEC_GSS
)

// opExchangeID implements EXCHANGE_ID (RFC 8881 section 18.35).
func (cp *compound) opExchangeID(d *xdr.Decoder, e *xdr.Encoder) Status {
	var verifier [verifierSize]byte
	copy(verifier[:], d.FixedOpaque(verifierSize))
	ownerID := d.Opaque(maxOpaque)
	flags := d.Uint32()
	spHow := d.Uint32()
	switch spHow {
	case sp4None:
	case 1: // SP4_MACH_CRED: we don't enforce it, and reply SP4_NONE.
		decodeBitmap(d)
		decodeBitmap(d)
	default:
		if d.Err() == nil {
			return ErrEncrAlgUnsupp
		}
	}
	var info ClientInfo
	if n := d.ArrayLen(1, 12); n == 1 {
		info.ImplDomain = d.String(maxOpaque)
		info.ImplName = d.String(maxOpaque)
		sec := d.Int64()
		nsec := d.Uint32()
		if sec != 0 || nsec != 0 {
			info.ImplDate = time.Unix(sec, int64(nsec))
		}
	}
	if st := decodeErr(d); st != OK {
		return st
	}
	const allowedFlags = exchgidSuppMovedRefer | exchgidSuppMovedMigr | exchgidBindPrincStateID | exchgidMaskPNFS | exchgidUpdConfirmedRecA
	if len(ownerID) == 0 || flags & ^uint32(allowedFlags) != 0 {
		return ErrInval
	}
	info.OwnerID = append([]byte(nil), ownerID...)

	m := cp.m
	m.mu.Lock()
	defer m.mu.Unlock()

	key := string(ownerID)
	or := m.byOwner[key]
	if or == nil {
		or = &ownerRecords{}
		m.byOwner[key] = or
	}
	now := time.Now()
	var cl *client
	if flags&exchgidUpdConfirmedRecA != 0 {
		// An update of an existing confirmed record.
		c := or.confirmed
		if c == nil {
			if or.unconfirmed == nil {
				delete(m.byOwner, key)
			}
			return ErrNoEnt
		}
		if c.verifier != verifier {
			return ErrNotSame
		}
		if !sameClientCred(c.cred, cp.req.Cred) {
			return ErrPerm
		}
		cl = c
	} else if c := or.confirmed; c != nil && c.verifier == verifier && sameClientCred(c.cred, cp.req.Cred) {
		// The client already has a confirmed client ID and is asking
		// again (for instance on a new connection, or to check for
		// a server restart).
		cl = c
	} else {
		if c := or.confirmed; c != nil && !sameClientCred(c.cred, cp.req.Cred) {
			// A different user can replace only idle or expired state.
			if c.hasStateLocked() && now.Sub(c.lastRenew) <= cp.s.LeaseTime {
				return ErrClidInUse
			}
			m.destroyClientLocked(c)
			or = m.byOwner[key]
			if or == nil {
				or = &ownerRecords{}
				m.byOwner[key] = or
			}
		}
		// A new client, or a client that restarted (new verifier).
		// Create a new unconfirmed record. A previous confirmed
		// record, if any, is kept until the new one is confirmed by
		// CREATE_SESSION.
		if old := or.unconfirmed; old != nil {
			m.destroyClientLocked(old)
			or = m.byOwner[key]
			if or == nil {
				or = &ownerRecords{}
				m.byOwner[key] = or
			}
		}
		if len(m.clients) >= maxClients {
			m.s.logf("nfsv4: too many clients (%d); refusing EXCHANGE_ID", len(m.clients))
			return ErrDelay
		}
		cl = newClient(m.newClientID())
		cl.ownerKey = key
		cl.verifier = verifier
		cl.cred = cp.req.Cred
		cl.cred.GIDs = slices.Clone(cp.req.Cred.GIDs)
		cl.lastRenew = now
		or.unconfirmed = cl
		m.clients[cl.id] = cl
	}
	if !cl.confirmed || flags&exchgidUpdConfirmedRecA != 0 {
		info.ID = cl.id
		cl.info = info
	}

	rflags := uint32(exchgidUseNonPNFS)
	if cl.confirmed {
		rflags |= exchgidConfirmedR
	}
	e.Uint64(cl.id)
	e.Uint32(cl.csSeq)
	e.Uint32(rflags)
	e.Uint32(sp4None)
	// server_owner4
	e.Uint64(0)
	e.String(cp.s.owner)
	// eir_server_scope
	e.String(cp.s.ServerScope)
	// eir_server_impl_id
	e.Uint32(1)
	e.String("tailscale.com")
	e.String("github.com/tailscale/nfsv4")
	e.Int64(0)
	e.Uint32(0)
	return OK
}

// opCreateSession implements CREATE_SESSION (RFC 8881 section 18.36).
func (cp *compound) opCreateSession(d *xdr.Decoder, e *xdr.Encoder) Status {
	clientID := d.Uint64()
	seq := d.Uint32()
	flags := d.Uint32()
	fore := decodeChannelAttrs(d)
	back := decodeChannelAttrs(d)
	cbProg := d.Uint32()
	var cbCred *oncrpc.OpaqueAuth
	nsec := d.ArrayLen(16, 4)
	for range nsec {
		switch flavor := d.Uint32(); flavor {
		case oncrpc.AuthNone:
			if cbCred == nil {
				cbCred = &oncrpc.OpaqueAuth{Flavor: oncrpc.AuthNone}
			}
		case oncrpc.AuthSys:
			var sc oncrpc.AuthSysCred
			sc.Stamp = d.Uint32()
			sc.MachineName = d.String(255)
			sc.UID = d.Uint32()
			sc.GID = d.Uint32()
			ng := d.ArrayLen(16, 4)
			for range ng {
				sc.GIDs = append(sc.GIDs, d.Uint32())
			}
			if cbCred == nil || cbCred.Flavor != oncrpc.AuthSys {
				cbCred = &oncrpc.OpaqueAuth{Flavor: oncrpc.AuthSys, Body: sc.Encode()}
			}
		case authGSS:
			d.Uint32()          // service
			d.Opaque(maxOpaque) // handle from server
			d.Opaque(maxOpaque) // handle from client
		default:
			// Unknown flavors can't be skipped.
			d.SetErr(errBadXDR)
		}
	}
	if st := decodeErr(d); st != OK {
		return st
	}

	m := cp.m
	m.mu.Lock()
	defer m.mu.Unlock()

	cl := m.clients[clientID]
	if cl == nil {
		return ErrStaleClientID
	}
	// SP4_NONE permits other users after client ID confirmation.
	if !cl.confirmed && !sameClientCred(cl.cred, cp.req.Cred) {
		return ErrClidInUse
	}
	if seq == cl.csSeq-1 && cl.csReply != nil {
		// A retransmission of the previous CREATE_SESSION.
		m.bindCreateReplyLocked(cl.csReply, cp.c)
		e.FixedOpaque(cl.csReply)
		return OK
	}
	if seq != cl.csSeq {
		return ErrSeqMisordered
	}
	if flags & ^uint32(createSessionPersist|createSessionConnBackChan|createSessionConnRDMA) != 0 {
		return ErrInval
	}
	if fore.maxRequestSize < minSessionRequestSize || fore.maxResponseSize < minSessionResponseSize {
		return ErrTooSmall
	}
	if fore.maxOperations < 2 || fore.maxRequests < 1 {
		return ErrInval
	}
	if len(cl.sessions) >= maxSessionsPerClient {
		return ErrNoSpc
	}

	if !cl.confirmed {
		or := m.byOwner[cl.ownerKey]
		if or != nil && or.confirmed != nil && or.confirmed != cl {
			// The client restarted; its old state is gone.
			m.destroyClientLocked(or.confirmed)
			or = m.byOwner[cl.ownerKey]
		}
		if or == nil {
			or = &ownerRecords{}
			m.byOwner[cl.ownerKey] = or
		}
		or.confirmed = cl
		or.unconfirmed = nil
		cl.confirmed = true
	}
	cl.lastRenew = time.Now()

	maxReq := uint32(cp.s.maxRecordSize())
	sess := &session{
		id:     m.newSessionID(),
		client: cl,
		cbProg: cbProg,
		minor:  cp.minor,
	}
	sess.fore = channelAttrs{
		maxRequestSize:    min(fore.maxRequestSize, maxReq),
		maxResponseSize:   min(fore.maxResponseSize, maxReq),
		maxResponseCached: min(fore.maxResponseCached, maxCachedReply),
		maxOperations:     min(fore.maxOperations, maxCompoundOps),
		maxRequests:       min(fore.maxRequests, maxSlots),
	}
	sess.slots = make([]*slot, sess.fore.maxRequests)
	for i := range sess.slots {
		sess.slots[i] = &slot{}
	}

	var rflags uint32
	if flags&createSessionConnBackChan != 0 && cbCred != nil && back.maxRequests >= 1 && back.maxOperations >= 2 {
		rflags |= createSessionConnBackChan
		sess.backGranted = true
		sess.cbCred = *cbCred
		sess.back = channelAttrs{
			maxRequestSize:    back.maxRequestSize,
			maxResponseSize:   back.maxResponseSize,
			maxResponseCached: 0,
			maxOperations:     min(back.maxOperations, 2),
			maxRequests:       1,
		}
		m.bindBackLocked(sess, cp.c)
	} else {
		sess.back = channelAttrs{
			maxRequestSize:  min(back.maxRequestSize, 4096),
			maxResponseSize: min(back.maxResponseSize, 4096),
			maxOperations:   min(back.maxOperations, 2),
			maxRequests:     min(back.maxRequests, 1),
		}
	}
	m.sessions[sess.id] = sess
	cl.sessions[sess.id] = sess
	m.bindForeLocked(sess, cp.c)
	cp.s.debugf("nfsv4: client %#x (%s) created session: flags %#x (granted %#x), %d slots, back chan %+v",
		cl.id, cl.info.ImplName, flags, rflags, len(sess.slots), back)

	start := e.Len()
	e.FixedOpaque(sess.id[:])
	e.Uint32(seq)
	e.Uint32(rflags)
	encodeChannelAttrs(e, sess.fore)
	encodeChannelAttrs(e, sess.back)
	cl.csReply = append([]byte(nil), e.Bytes()[start:]...)
	cl.csSeq++
	return OK
}

// opDestroySession implements DESTROY_SESSION (RFC 8881 section 18.37).
func (cp *compound) opDestroySession(d *xdr.Decoder, e *xdr.Encoder) Status {
	var sid sessionID
	copy(sid[:], d.FixedOpaque(sessionIDSize))
	if st := decodeErr(d); st != OK {
		return st
	}
	m := cp.m
	m.mu.Lock()
	defer m.mu.Unlock()
	sess := m.sessions[sid]
	if sess == nil {
		return ErrBadSession
	}
	if cp.sess == sess && cp.opIdx != cp.numOps-1 {
		return ErrNotOnlyOp
	}
	if !cp.c.foreFor[sess] && !cp.c.backFor[sess] {
		return ErrConnNotBoundToSession
	}
	m.destroySessionLocked(sess)
	return OK
}

// opDestroyClientID implements DESTROY_CLIENTID (RFC 8881 section 18.50).
func (cp *compound) opDestroyClientID(d *xdr.Decoder, e *xdr.Encoder) Status {
	id := d.Uint64()
	if st := decodeErr(d); st != OK {
		return st
	}
	m := cp.m
	m.mu.Lock()
	defer m.mu.Unlock()
	cl := m.clients[id]
	if cl == nil {
		return ErrStaleClientID
	}
	if len(cl.sessions) > 0 {
		return ErrClientIDBusy
	}
	m.destroyClientLocked(cl)
	return OK
}

// opBindConnToSession implements BIND_CONN_TO_SESSION (RFC 8881 section
// 18.34).
func (cp *compound) opBindConnToSession(d *xdr.Decoder, e *xdr.Encoder) Status {
	var sid sessionID
	copy(sid[:], d.FixedOpaque(sessionIDSize))
	dir := d.Uint32()
	d.Bool() // use_conn_in_rdma_mode
	if st := decodeErr(d); st != OK {
		return st
	}
	if cp.numOps != 1 {
		return ErrNotOnlyOp
	}
	m := cp.m
	m.mu.Lock()
	defer m.mu.Unlock()
	sess := m.sessions[sid]
	if sess == nil {
		return ErrBadSession
	}
	var rdir uint32
	switch dir {
	case cdfcFore:
		rdir = cdfsFore
	case cdfcBack:
		rdir = cdfsBack
	case cdfcForeOrBoth, cdfcBackOrBoth:
		rdir = cdfsBoth
	default:
		return ErrInval
	}
	if rdir&cdfsBack != 0 {
		if !sess.backGranted {
			if dir == cdfcBack || dir == cdfcBackOrBoth {
				return ErrInval
			}
			rdir = cdfsFore
		} else {
			m.bindBackLocked(sess, cp.c)
		}
	}
	if rdir&cdfsFore != 0 {
		m.bindForeLocked(sess, cp.c)
	}
	sess.client.lastRenew = time.Now()
	e.FixedOpaque(sid[:])
	e.Uint32(rdir)
	e.Bool(false)
	return OK
}

// opSequence implements SEQUENCE (RFC 8881 section 18.46).
func (cp *compound) opSequence(d *xdr.Decoder, e *xdr.Encoder) Status {
	var sid sessionID
	copy(sid[:], d.FixedOpaque(sessionIDSize))
	seq := d.Uint32()
	slotID := d.Uint32()
	d.Uint32() // sa_highest_slotid
	cacheThis := d.Bool()
	if st := decodeErr(d); st != OK {
		return st
	}

	m := cp.m
	m.mu.Lock()
	defer m.mu.Unlock()
	sess := m.sessions[sid]
	if sess == nil {
		return ErrBadSession
	}
	if slotID >= uint32(len(sess.slots)) {
		return ErrBadSlot
	}
	if cp.numOps > int(sess.fore.maxOperations) {
		return ErrTooManyOps
	}
	if cp.reqLen > int(sess.fore.maxRequestSize) {
		return ErrReqTooBig
	}
	m.bindForeLocked(sess, cp.c)
	sl := sess.slots[slotID]
	// A retry uses the stored reply, not the new tag or cache request.
	if seq != sl.seqid || sl.seqid == 0 {
		// Check the SEQUENCE reply before the slot state changes. Include the
		// RPC header and leave room for an error from the next operation.
		replySize := cp.replyHeaderLen + e.Len() - cp.replyStart + 36
		if cp.numOps > 1 {
			replySize += 8
		}
		if replySize > int(sess.fore.maxResponseSize) {
			return ErrRepTooBig
		}
		if cacheThis && replySize > int(sess.fore.maxResponseCached) {
			return ErrRepTooBigToCache
		}
	}
	switch {
	case seq == sl.seqid+1:
		// A new request.
		if sl.inUse {
			// The client hasn't seen the reply to the previous
			// request on this slot yet; it shouldn't reuse it.
			return ErrDelay
		}
	case seq == sl.seqid && sl.seqid == 0:
		return ErrSeqMisordered // never used
	case seq == sl.seqid:
		if sl.inUse {
			return ErrDelay
		}
		if sl.reply == nil {
			return ErrRetryUncachedRep
		}
		cp.replay = sl.reply
		return OK
	default:
		return ErrSeqMisordered
	}
	sl.seqid = seq
	sl.inUse = true
	sl.reply = nil

	cl := sess.client
	cl.lastRenew = time.Now()
	cp.sess = sess
	cp.cl = cl
	cp.slot = sl
	cp.slotID = slotID
	cp.seqID = seq
	cp.cacheThis = cacheThis
	cp.maxResp = int(sess.fore.maxResponseSize) - cp.replyHeaderLen
	info := cl.info // a copy, as EXCHANGE_ID may update it concurrently
	cp.req.Client = &info

	var flags uint32
	if sess.backGranted && len(sess.backConns) == 0 {
		flags |= seqStatusCBPathDown | seqStatusCBPathDownSession
	}
	if len(cl.revoked) > 0 {
		flags |= seqStatusRecallableStateRevoked
	}

	e.FixedOpaque(sid[:])
	e.Uint32(seq)
	e.Uint32(slotID)
	// Both the highest slot ID we'll accept and our target are the
	// whole table. (sr_highest_slotid is not an echo of
	// sa_highest_slotid; the Linux client shrinks its slot table to
	// it.)
	e.Uint32(uint32(len(sess.slots) - 1))
	e.Uint32(uint32(len(sess.slots) - 1))
	e.Uint32(flags)
	return OK
}

// opReclaimComplete implements RECLAIM_COMPLETE (RFC 8881 section 18.51).
func (cp *compound) opReclaimComplete(d *xdr.Decoder, e *xdr.Encoder) Status {
	oneFS := d.Bool()
	if st := decodeErr(d); st != OK {
		return st
	}
	if oneFS {
		return OK
	}
	m := cp.m
	m.mu.Lock()
	defer m.mu.Unlock()
	if cp.cl.reclaimComplete {
		return ErrCompleteAlready
	}
	cp.cl.reclaimComplete = true
	return OK
}
