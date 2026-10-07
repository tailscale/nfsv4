// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/tailscale/nfsv4/internal/oncrpc"
	"github.com/tailscale/nfsv4/internal/xdr"
)

type sessionID [sessionIDSize]byte

type stateOther [stateOtherLen]byte

// stateID is an NFSv4 stateid4.
type stateID struct {
	seqid uint32
	other stateOther
}

func decodeStateID(d *xdr.Decoder) stateID {
	var sid stateID
	sid.seqid = d.Uint32()
	copy(sid.other[:], d.FixedOpaque(stateOtherLen))
	return sid
}

func encodeStateID(e *xdr.Encoder, sid stateID) {
	e.Uint32(sid.seqid)
	e.FixedOpaque(sid.other[:])
}

var (
	allOnesOther   = stateOther{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	anonStateID    = stateID{}                                       // all zeros: anonymous
	bypassStateID  = stateID{seqid: ^uint32(0), other: allOnesOther} // READ bypass
	currentStateID = stateID{seqid: 1}                               // "current stateid" (4.1)
	invalidStateID = stateID{seqid: ^uint32(0)}                      // special invalid stateid
)

// channelAttrs are a session channel's negotiated attributes.
type channelAttrs struct {
	headerPadSize     uint32
	maxRequestSize    uint32
	maxResponseSize   uint32
	maxResponseCached uint32
	maxOperations     uint32
	maxRequests       uint32
	rdmaIRD           []uint32
}

func decodeChannelAttrs(d *xdr.Decoder) channelAttrs {
	var ca channelAttrs
	ca.headerPadSize = d.Uint32()
	ca.maxRequestSize = d.Uint32()
	ca.maxResponseSize = d.Uint32()
	ca.maxResponseCached = d.Uint32()
	ca.maxOperations = d.Uint32()
	ca.maxRequests = d.Uint32()
	n := d.ArrayLen(1, 4)
	for range n {
		ca.rdmaIRD = append(ca.rdmaIRD, d.Uint32())
	}
	return ca
}

func encodeChannelAttrs(e *xdr.Encoder, ca channelAttrs) {
	e.Uint32(ca.headerPadSize)
	e.Uint32(ca.maxRequestSize)
	e.Uint32(ca.maxResponseSize)
	e.Uint32(ca.maxResponseCached)
	e.Uint32(ca.maxOperations)
	e.Uint32(ca.maxRequests)
	e.Uint32(0) // no RDMA
}

// client is a client ID's state.
type client struct {
	id        uint64
	info      ClientInfo
	ownerKey  string
	verifier  [verifierSize]byte
	confirmed bool

	// csSeq is the next expected CREATE_SESSION sequence ID, and
	// csReply is the cached reply to the previous CREATE_SESSION (with
	// sequence ID csSeq-1), for replays.
	csSeq   uint32
	csReply []byte

	lastRenew       time.Time
	reclaimComplete bool

	sessions map[sessionID]*session
	opens    map[openKey]*openState
	locks    map[lockKey]*lockState
	delegs   map[stateOther]*delegState
	revoked  map[stateOther]*delegState // revoked, awaiting FREE_STATEID
}

type openKey struct {
	owner string
	fh    string
}

type lockKey struct {
	owner string
	fh    string
}

type openState struct {
	other  stateOther
	seqid  uint32
	client *client
	key    openKey
	fh     FileHandle
	access uint32
	deny   uint32
	locks  map[*lockState]bool
}

type lockState struct {
	other  stateOther
	seqid  uint32
	client *client
	key    lockKey
	open   *openState
}

// delegState is a granted read delegation on a file or directory.
type delegState struct {
	other  stateOther
	client *client
	fh     FileHandle
	isDir  bool

	// grantSess, grantSlot, and grantSeq identify the request that
	// granted the delegation, for CB_SEQUENCE referring call lists.
	// replySent is whether that request's reply has been sent.
	grantSess sessionID
	grantSlot uint32
	grantSeq  uint32
	replySent bool

	recalling bool
	revoked   bool
	done      chan struct{} // closed when returned or revoked
	timer     *time.Timer   // MaxAge timer, if any
}

func (d *delegState) stateID() stateID { return stateID{seqid: 1, other: d.other} }

// session is an NFSv4.1 session.
type session struct {
	id     sessionID
	client *client
	fore   channelAttrs
	back   channelAttrs
	slots  []*slot

	// Backchannel parameters.
	backGranted bool
	cbProg      uint32
	cbCred      oncrpc.OpaqueAuth
	backConns   []*conn

	minor uint32 // minor version used to create the session

	cbMu  sync.Mutex // serializes callbacks; we use a single backchannel slot
	cbSeq uint32     // last CB_SEQUENCE sequence ID used; guarded by cbMu
}

type slot struct {
	seqid uint32
	inUse bool
	reply []byte // cached reply for seqid, if the client asked for caching
}

// stateManager holds all client state for a Server.
type stateManager struct {
	s *Server

	mu         sync.Mutex
	clients    map[uint64]*client
	byOwner    map[string]*ownerRecords
	sessions   map[sessionID]*session
	states     map[stateOther]any // *openState, *lockState, or *delegState
	delegsByFH map[string]map[*delegState]bool
	recalling  map[string]int // filehandle → number of in-progress recalls
	nextID     uint64

	invalEpoch uint64 // number of Recall starts and releases
	invalRing  [recentInvalidations]invalRecord
}

// ownerRecords are the client records for one client owner: the confirmed
// one, if any, and an unconfirmed one, if any.
type ownerRecords struct {
	confirmed   *client
	unconfirmed *client
}

func newStateManager(s *Server) *stateManager {
	return &stateManager{
		s:          s,
		clients:    make(map[uint64]*client),
		byOwner:    make(map[string]*ownerRecords),
		sessions:   make(map[sessionID]*session),
		states:     make(map[stateOther]any),
		delegsByFH: make(map[string]map[*delegState]bool),
		recalling:  make(map[string]int),
	}
}

// newClientID returns a new client ID. The high 32 bits are the server's
// boot epoch, so client IDs from previous server instances are recognized
// as stale.
func (m *stateManager) newClientID() uint64 {
	m.nextID++
	return uint64(m.s.epoch)<<32 | m.nextID&0xffffffff
}

func (m *stateManager) newOther() stateOther {
	m.nextID++
	var o stateOther
	binary.BigEndian.PutUint32(o[:4], m.s.epoch)
	binary.BigEndian.PutUint64(o[4:], m.nextID)
	return o
}

func (m *stateManager) newSessionID() sessionID {
	m.nextID++
	var id sessionID
	binary.BigEndian.PutUint32(id[:4], m.s.epoch)
	binary.BigEndian.PutUint64(id[4:12], m.nextID)
	rand.Read(id[12:])
	return id
}

func newClient(id uint64) *client {
	return &client{
		id:       id,
		csSeq:    1,
		sessions: make(map[sessionID]*session),
		opens:    make(map[openKey]*openState),
		locks:    make(map[lockKey]*lockState),
		delegs:   make(map[stateOther]*delegState),
		revoked:  make(map[stateOther]*delegState),
	}
}

// destroyClientLocked discards a client and all its state.
func (m *stateManager) destroyClientLocked(cl *client) {
	for _, sess := range cl.sessions {
		m.destroySessionLocked(sess)
	}
	var closed []FileHandle
	for _, o := range cl.opens {
		delete(m.states, o.other)
		closed = append(closed, o.fh)
	}
	for _, l := range cl.locks {
		delete(m.states, l.other)
	}
	for _, d := range cl.delegs {
		m.removeDelegLocked(d)
	}
	for _, d := range cl.revoked {
		delete(m.states, d.other)
	}
	delete(m.clients, cl.id)
	if or := m.byOwner[cl.ownerKey]; or != nil {
		if or.confirmed == cl {
			or.confirmed = nil
		}
		if or.unconfirmed == cl {
			or.unconfirmed = nil
		}
		if or.confirmed == nil && or.unconfirmed == nil {
			delete(m.byOwner, cl.ownerKey)
		}
	}
	if op, ok := m.s.FS.(Opener); ok && len(closed) > 0 {
		go func() {
			for _, fh := range closed {
				op.Close(fh)
			}
		}()
	}
}

func (m *stateManager) destroySessionLocked(sess *session) {
	delete(m.sessions, sess.id)
	delete(sess.client.sessions, sess.id)
	for _, c := range sess.backConns {
		delete(c.backFor, sess)
	}
	sess.backConns = nil
}

// bindBackLocked binds c as a backchannel connection for sess.
func (m *stateManager) bindBackLocked(sess *session, c *conn) {
	if c.gone || c.backFor[sess] {
		return
	}
	if c.backFor == nil {
		c.backFor = make(map[*session]bool)
	}
	c.backFor[sess] = true
	sess.backConns = append(sess.backConns, c)
}

func (m *stateManager) connClosed(c *conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for sess := range c.backFor {
		for i, bc := range sess.backConns {
			if bc == c {
				sess.backConns = append(sess.backConns[:i], sess.backConns[i+1:]...)
				break
			}
		}
	}
	c.backFor = nil
	c.gone = true
}

// backConn returns a live backchannel connection for sess, or nil.
func (m *stateManager) backConn(sess *session) *conn {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(sess.backConns) == 0 {
		return nil
	}
	return sess.backConns[len(sess.backConns)-1]
}

// clientBackchannelLocked returns a session of cl with a live backchannel,
// or nil.
func (m *stateManager) clientBackchannelLocked(cl *client) *session {
	for _, sess := range cl.sessions {
		if sess.backGranted && len(sess.backConns) > 0 {
			return sess
		}
	}
	return nil
}

// lookupStateLocked finds the state for sid, which must belong to cl,
// resolving the "current stateid" special value from cur. It returns nil
// for the anonymous and bypass special stateids, which are valid for READ.
func (m *stateManager) lookupStateLocked(cl *client, sid stateID, cur *stateID) (any, Status) {
	if sid == currentStateID {
		if cur == nil {
			return nil, ErrBadStateID
		}
		sid = *cur
	}
	if sid == anonStateID || sid == bypassStateID {
		return nil, OK
	}
	st, ok := m.states[sid.other]
	if !ok {
		return nil, ErrBadStateID
	}
	var owner *client
	var seq uint32
	switch st := st.(type) {
	case *openState:
		owner, seq = st.client, st.seqid
	case *lockState:
		owner, seq = st.client, st.seqid
	case *delegState:
		owner, seq = st.client, 1
		if st.revoked {
			return nil, ErrDelegRevoked
		}
	}
	if owner != cl {
		return nil, ErrBadStateID
	}
	if sid.seqid != 0 && sid.seqid != seq {
		if sid.seqid < seq {
			return nil, ErrOldStateID
		}
		return nil, ErrBadStateID
	}
	return st, OK
}

func (m *stateManager) removeDelegLocked(d *delegState) {
	delete(m.states, d.other)
	delete(d.client.delegs, d.other)
	key := string(d.fh)
	if set := m.delegsByFH[key]; set != nil {
		delete(set, d)
		if len(set) == 0 {
			delete(m.delegsByFH, key)
		}
	}
	if d.timer != nil {
		d.timer.Stop()
	}
	select {
	case <-d.done:
	default:
		close(d.done)
	}
}

// revokeDelegLocked revokes d because its client didn't return it in time.
// The stateid stays known (as revoked) until the client frees it with
// FREE_STATEID, and SEQUENCE reports SEQ4_STATUS_RECALLABLE_STATE_REVOKED
// until then.
func (m *stateManager) revokeDelegLocked(d *delegState) {
	if d.revoked {
		return
	}
	m.removeDelegLocked(d)
	d.revoked = true
	m.states[d.other] = d
	d.client.revoked[d.other] = d
	m.s.stats.revokes.Add(1)
}

func (m *stateManager) fillStats(st *Stats) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st.Clients = len(m.clients)
	st.Sessions = len(m.sessions)
	for _, s := range m.states {
		switch s := s.(type) {
		case *openState:
			st.Opens++
		case *lockState:
			st.Locks++
		case *delegState:
			if !s.revoked {
				st.Delegations++
			}
		}
	}
}

// reaper periodically discards the state of clients that have stopped
// renewing their leases.
func (m *stateManager) reaper(ctx context.Context) {
	interval := min(m.s.LeaseTime/2, 10*time.Second)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		m.reap(time.Now())
	}
}

func (m *stateManager) reap(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, cl := range m.clients {
		limit := m.s.ClientExpiry
		if !cl.confirmed {
			limit = m.s.LeaseTime
		}
		if now.Sub(cl.lastRenew) > limit {
			m.s.debugf("nfsv4: expiring client %#x (%s)", cl.id, cl.info.ImplName)
			m.destroyClientLocked(cl)
		}
	}
}

func (sid stateID) String() string {
	return fmt.Sprintf("%d:%x", sid.seqid, sid.other[:])
}
