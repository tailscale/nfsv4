// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tailscale/nfsv4/internal/xdr"
)

const (
	cbCompoundProc = 1
	cbVersion      = 1

	// cbCallTimeout bounds one callback round trip.
	cbCallTimeout = 15 * time.Second

	// recentInvalidations is how many recent Invalidate calls are
	// remembered, to avoid granting delegations based on attributes
	// fetched before an invalidation.
	recentInvalidations = 1024
)

// timeAfterFunc is time.AfterFunc, replaceable in tests.
var timeAfterFunc = time.AfterFunc

// Invalidate recalls all delegations granted for fh, which must be called
// after an object for which delegations were granted changes, so that
// clients stop trusting their cached copies.
//
// Invalidate returns once all delegations for fh have been returned by
// their clients, or revoked from clients that didn't return them within
// the lease time, or when ctx is done. Clients that held delegations then
// revalidate their caches using the change attribute, so the FS must
// report a new Attrs.Change for the changed object (for directories, also
// when entries are added or removed).
//
// While Invalidate runs, no new delegations are granted for fh, and
// requests that fetched fh's attributes before Invalidate was called don't
// get delegations either.
func (s *Server) Invalidate(ctx context.Context, fh FileHandle) error {
	s.init()
	m := s.state
	key := string(fh)
	m.mu.Lock()
	m.noteInvalidationLocked(key)
	m.recalling[key]++
	var ds []*delegState
	for d := range m.delegsByFH[key] {
		ds = append(ds, d)
	}
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		if m.recalling[key]--; m.recalling[key] <= 0 {
			delete(m.recalling, key)
		}
		m.mu.Unlock()
	}()

	for _, d := range ds {
		m.startRecall(d)
	}
	for _, d := range ds {
		select {
		case <-d.done:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ctx.Done():
			return ErrServerClosed
		}
	}
	return nil
}

func (m *stateManager) invalEpochNow() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.invalEpoch
}

func (m *stateManager) noteInvalidationLocked(key string) {
	m.invalEpoch++
	m.invalRing[m.invalEpoch%recentInvalidations] = invalRecord{epoch: m.invalEpoch, key: key}
}

// invalidatedSinceLocked reports whether key may have been invalidated
// after epoch.
func (m *stateManager) invalidatedSinceLocked(key string, epoch uint64) bool {
	if m.invalEpoch == epoch {
		return false
	}
	if m.invalEpoch-epoch >= recentInvalidations {
		return true // too many to check; be conservative
	}
	for e := epoch + 1; e <= m.invalEpoch; e++ {
		if r := m.invalRing[e%recentInvalidations]; r.epoch == e && r.key == key {
			return true
		}
	}
	return false
}

type invalRecord struct {
	epoch uint64
	key   string
}

// startRecall starts recalling d in the background, if it isn't already
// being recalled.
func (m *stateManager) startRecall(d *delegState) {
	m.mu.Lock()
	if d.recalling || d.revoked || isClosed(d.done) {
		m.mu.Unlock()
		return
	}
	d.recalling = true
	m.mu.Unlock()
	m.s.stats.recalls.Add(1)
	m.s.wg.Add(1)
	go func() {
		defer m.s.wg.Done()
		m.recall(d)
	}()
}

func isClosed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// recall sends CB_RECALL for d until the client acknowledges it, then
// waits for the client to return the delegation. If the client doesn't
// return it within the lease time, the delegation is revoked.
func (m *stateManager) recall(d *delegState) {
	s := m.s
	ctx := s.ctx
	deadline := time.Now().Add(s.LeaseTime)
	revoke := func(why string) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if !isClosed(d.done) {
			s.logf("nfsv4: revoking delegation from client %#x (%s): %s", d.client.id, d.client.info.ImplName, why)
			m.revokeDelegLocked(d)
		}
	}
	wait := func(dur time.Duration) bool {
		t := time.NewTimer(dur)
		defer t.Stop()
		select {
		case <-d.done:
			return false
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		}
	}

	for attempt := 0; ; attempt++ {
		if isClosed(d.done) || ctx.Err() != nil {
			return
		}
		if time.Now().After(deadline) {
			revoke("not returned within the lease time")
			return
		}
		m.mu.Lock()
		sess := m.clientBackchannelLocked(d.client)
		m.mu.Unlock()
		if sess == nil {
			// The client may reconnect and bind a new backchannel.
			if !wait(time.Second) {
				return
			}
			continue
		}
		st, err := m.sendRecall(ctx, sess, d)
		switch {
		case err != nil:
			s.debugf("nfsv4: CB_RECALL to client %#x: %v", d.client.id, err)
			if !wait(time.Second) {
				return
			}
		case st == OK:
			// Acknowledged. Wait for DELEGRETURN.
			if wait(time.Until(deadline)) {
				revoke("not returned after recall")
			}
			return
		case st == ErrDelay:
			if !wait(100 * time.Millisecond) {
				return
			}
		case st == ErrBadHandle || st == ErrBadStateID:
			// The client doesn't know about the delegation. Either
			// it hasn't processed the reply granting it yet, or
			// it already returned it and the DELEGRETURN is in
			// flight. Give it a moment either way.
			if !wait(250 * time.Millisecond) {
				return
			}
			m.mu.Lock()
			replySent := d.replySent
			m.mu.Unlock()
			if replySent && attempt >= 4 {
				revoke(fmt.Sprintf("client doesn't recognize it (%v)", st))
				return
			}
		default:
			s.debugf("nfsv4: CB_RECALL to client %#x: %v", d.client.id, st)
			if !wait(time.Second) {
				return
			}
		}
	}
}

// sendRecall sends one CB_COMPOUND with CB_SEQUENCE and CB_RECALL for d
// over sess's backchannel. It returns the status of the compound.
func (m *stateManager) sendRecall(ctx context.Context, sess *session, d *delegState) (Status, error) {
	c := m.backConn(sess)
	if c == nil {
		return 0, errConnClosed
	}
	sess.cbMu.Lock()
	defer sess.cbMu.Unlock()

	m.mu.Lock()
	replySent := d.replySent
	m.mu.Unlock()

	seq := sess.cbSeq + 1
	var e xdr.Encoder
	e.String("")         // tag
	e.Uint32(sess.minor) // minorversion
	e.Uint32(0)          // callback_ident (unused in 4.1)
	e.Uint32(2)          // two operations
	e.Uint32(uint32(CBOpSequence))
	e.FixedOpaque(sess.id[:])
	e.Uint32(seq)
	e.Uint32(0) // slot
	e.Uint32(0) // highest slot
	e.Bool(false)
	if !replySent {
		// The reply granting the delegation may not have reached
		// the client yet. Tell it which request to wait for.
		e.Uint32(1)
		e.FixedOpaque(d.grantSess[:])
		e.Uint32(1)
		e.Uint32(d.grantSeq)
		e.Uint32(d.grantSlot)
	} else {
		e.Uint32(0)
	}
	e.Uint32(uint32(CBOpRecall))
	encodeStateID(&e, d.stateID())
	e.Bool(false) // truncate
	e.Opaque(d.fh)

	cctx, cancel := context.WithTimeout(ctx, cbCallTimeout)
	defer cancel()
	res, err := c.call(cctx, sess.cbProg, cbVersion, cbCompoundProc, sess.cbCred, e.Bytes())
	if err != nil {
		return 0, err
	}
	rd := xdr.NewDecoder(res)
	status := Status(rd.Uint32())
	rd.Opaque(maxOpaque) // tag
	n := rd.Uint32()
	if err := rd.Err(); err != nil {
		return 0, err
	}
	if n == 0 {
		return status, nil
	}
	if op := CBOp(rd.Uint32()); op != CBOpSequence {
		return 0, fmt.Errorf("unexpected first callback result %v", op)
	}
	seqStatus := Status(rd.Uint32())
	switch seqStatus {
	case OK, ErrRetryUncachedRep, ErrSeqMisordered:
		// The slot's sequence ID advanced (or we lost track of it);
		// use the next one either way.
		sess.cbSeq = seq
	}
	if seqStatus != OK {
		if seqStatus == ErrRetryUncachedRep || seqStatus == ErrSeqMisordered {
			return ErrDelay, nil
		}
		return seqStatus, nil
	}
	if rd.Err() != nil {
		return 0, errors.New("short CB_SEQUENCE result")
	}
	return status, nil
}
