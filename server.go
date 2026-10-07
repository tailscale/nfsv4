// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Server is an NFSv4.1 server serving an FS read-only.
//
// It speaks NFSv4 minor versions 1 and 2 over TCP. Clients mount it
// directly on whatever port it listens on, with no portmapper or mountd:
//
//	Linux: mount -t nfs4 -o vers=4.2,port=N,ro HOST:/ /mnt
//	macOS: mount -t nfs -o vers=4.1,port=N,rdonly HOST:/ /mnt
//
// The exported fields must not be changed after the first call to Serve or
// ServeConn.
type Server struct {
	// FS is the filesystem to serve. It's required.
	FS FS

	// Logf, if non-nil, is used to log errors and unusual events. If
	// nil, log.Printf is used.
	Logf func(format string, args ...any)

	// Debugf, if non-nil, logs every operation. It's very verbose.
	Debugf func(format string, args ...any)

	// LeaseTime is the lease time clients must renew their state within.
	// Clients send a SEQUENCE heartbeat at least this often, and the
	// Linux client returns idle file delegations it isn't using after one
	// or two thirds of it. If zero, 90 seconds is used.
	LeaseTime time.Duration

	// ClientExpiry is how long after a client stops renewing its lease
	// that the server discards the client's state. Read-only state never
	// conflicts with other clients, so the server is "courteous" and
	// keeps the state of unresponsive clients (such as laptops that went
	// to sleep) much longer than the lease time, so they can resume
	// seamlessly. If zero, one hour is used.
	ClientExpiry time.Duration

	// MaxIO is the maximum READ size (the maxread attribute) and the
	// basis for the session request and response size limits. If zero,
	// 1 MiB is used.
	MaxIO int

	// FSID is the default fsid attribute, used for objects whose
	// Attrs.FSID is nil. The zero value is fine.
	FSID FSID

	// FHExpireType is the value of the fh_expire_type attribute. The
	// zero value, FHPersistent, is the right choice for filehandles that
	// survive server restarts.
	FHExpireType uint32

	// ChangeIsMonotonic promises that every object's Attrs.Change value
	// only ever increases. It's reported to NFSv4.2 clients in the
	// change_attr_type attribute, and the Linux client then uses Change
	// values to order concurrent attribute updates. Leave it false if
	// Change values are arbitrary (such as hashes).
	ChangeIsMonotonic bool

	// ServerScope identifies the server for the purposes of client
	// state (eir_server_scope). Servers sharing a scope (and a
	// ServerOwner) are considered the same server by clients. If empty,
	// "github.com/tailscale/nfsv4" is used.
	ServerScope string

	// ServerOwner is the server owner major ID (so_major_id), used by
	// clients for trunking detection. If empty, a random value is chosen
	// at startup.
	ServerOwner string

	initOnce sync.Once
	fsAttrs  fsAttrs
	bootTime time.Time
	epoch    uint32 // low 32 bits of a random boot identifier
	owner    string

	state *stateManager

	mu        sync.Mutex
	listeners map[net.Listener]struct{}
	conns     map[*conn]struct{}
	closed    bool
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	stats serverStats
}

// ErrServerClosed is returned by Serve after Close is called.
var ErrServerClosed = errors.New("nfsv4: server closed")

func (s *Server) init() {
	s.initOnce.Do(func() {
		if s.LeaseTime == 0 {
			s.LeaseTime = 90 * time.Second
		}
		if s.ClientExpiry == 0 {
			s.ClientExpiry = time.Hour
		}
		if s.ClientExpiry < s.LeaseTime {
			s.ClientExpiry = s.LeaseTime
		}
		if s.MaxIO == 0 {
			s.MaxIO = 1 << 20
		}
		if s.ServerScope == "" {
			s.ServerScope = "github.com/tailscale/nfsv4"
		}
		var rnd [8]byte
		rand.Read(rnd[:])
		s.epoch = binary.BigEndian.Uint32(rnd[:4])
		if s.epoch == 0 {
			s.epoch = 1
		}
		s.owner = s.ServerOwner
		if s.owner == "" {
			s.owner = "nfsv4-" + hexString(rnd[:])
		}
		s.bootTime = time.Now()
		s.fsAttrs = fsAttrs{
			fhExpireType:   s.FHExpireType,
			leaseTime:      uint32((s.LeaseTime + time.Second - 1) / time.Second),
			maxRead:        uint64(s.MaxIO),
			maxName:        255,
			fsid:           s.FSID,
			changeAttrType: changeUndefined,
		}
		if s.ChangeIsMonotonic {
			s.fsAttrs.changeAttrType = changeMonotonicIncr
		}
		s.ctx, s.cancel = context.WithCancel(context.Background())
		s.listeners = make(map[net.Listener]struct{})
		s.conns = make(map[*conn]struct{})
		s.state = newStateManager(s)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.state.reaper(s.ctx)
		}()
	})
}

func hexString(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hex[c>>4], hex[c&0xf])
	}
	return string(out)
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (s *Server) debugf(format string, args ...any) {
	if s.Debugf != nil {
		s.Debugf(format, args...)
	}
}

// Serve accepts connections on ln and serves them until ln fails or Close is
// called, in which case it returns ErrServerClosed.
func (s *Server) Serve(ln net.Listener) error {
	s.init()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrServerClosed
	}
	s.listeners[ln] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.listeners, ln)
		s.mu.Unlock()
	}()

	var tempDelay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if s.isClosed() {
				return ErrServerClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				tempDelay = min(max(tempDelay*2, 5*time.Millisecond), time.Second)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		tempDelay = 0
		go s.ServeConn(c)
	}
}

// addWork adds one to s.wg, unless the server is closed, in which case it
// reports false. The caller must call s.wg.Done when the work is done.
func (s *Server) addWork() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.wg.Add(1)
	return true
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// ServeConn serves a single client connection until it closes or the
// server is closed. It closes c before returning.
func (s *Server) ServeConn(c net.Conn) error {
	s.init()
	cc := newConn(s, c)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		c.Close()
		return ErrServerClosed
	}
	s.conns[cc] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.conns, cc)
		s.mu.Unlock()
		s.wg.Done()
	}()
	return cc.serve()
}

// Close stops all listeners and closes all connections. Client state is
// discarded. It waits for in-progress requests to finish.
func (s *Server) Close() error {
	s.init()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	for ln := range s.listeners {
		ln.Close()
	}
	for c := range s.conns {
		c.nc.Close()
	}
	s.mu.Unlock()
	s.cancel()
	s.wg.Wait()
	return nil
}

// serverStats are the server's counters.
type serverStats struct {
	ops       [maxOpStat]atomic.Uint64
	compounds atomic.Uint64
	recalls   atomic.Uint64
	revokes   atomic.Uint64
}

const maxOpStat = 80

// Stats are server statistics, as returned by Server.Stats.
type Stats struct {
	// Ops counts the operations processed, by operation.
	Ops map[Op]uint64

	// Compounds is the number of COMPOUND procedures processed.
	Compounds uint64

	// Clients and Sessions are the current numbers of clients and
	// sessions.
	Clients, Sessions int

	// Opens, Locks, and Delegations are the current numbers of open,
	// lock, and delegation stateids.
	Opens, Locks, Delegations int

	// Recalls is the number of delegation recalls sent. Revocations is
	// the number of delegations revoked because the client failed to
	// return them in time.
	Recalls, Revocations uint64
}

// Stats returns a snapshot of the server's statistics.
func (s *Server) Stats() Stats {
	s.init()
	st := Stats{
		Ops:         make(map[Op]uint64),
		Compounds:   s.stats.compounds.Load(),
		Recalls:     s.stats.recalls.Load(),
		Revocations: s.stats.revokes.Load(),
	}
	for i := range s.stats.ops {
		if n := s.stats.ops[i].Load(); n > 0 {
			st.Ops[Op(i)] = n
		}
	}
	s.state.fillStats(&st)
	return st
}

func (s *Server) countOp(op Op) {
	if op < maxOpStat {
		s.stats.ops[op].Add(1)
	}
}
