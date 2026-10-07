// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tailscale/nfsv4/internal/oncrpc"
	"github.com/tailscale/nfsv4/internal/xdr"
)

const (
	nfsProgram = 100003
	nfsVersion = 4

	procNull     = 0
	procCompound = 1

	// maxInflightPerConn bounds the number of concurrently executing
	// requests per connection. Clients are limited by their session's
	// slot count anyway; this is a backstop.
	maxInflightPerConn = 128

	// writeTimeout bounds how long a single reply write may block on a
	// client that isn't reading.
	writeTimeout = 2 * time.Minute

	nobodyID = 65534
)

// conn is a client TCP connection.
type conn struct {
	srv    *Server
	nc     net.Conn
	ctx    context.Context
	cancel context.CancelFunc

	wmu sync.Mutex // serializes writes to nc

	inflight chan struct{}

	cbMu      sync.Mutex
	cbNextXID uint32
	cbPending map[uint32]chan []byte // XID of outgoing callback → reply
	closed    bool                   // guarded by cbMu

	// backFor is the set of sessions this connection is bound to as
	// a backchannel, and gone is whether the connection has closed.
	// They're guarded by the stateManager's mutex.
	backFor map[*session]bool
	gone    bool
}

func newConn(s *Server, nc net.Conn) *conn {
	ctx, cancel := context.WithCancel(s.ctx)
	return &conn{
		srv:       s,
		nc:        nc,
		ctx:       ctx,
		cancel:    cancel,
		inflight:  make(chan struct{}, maxInflightPerConn),
		cbPending: make(map[uint32]chan []byte),
		cbNextXID: 0x80000000,
	}
}

// maxRecordSize returns the largest RPC record accepted from clients.
func (s *Server) maxRecordSize() int {
	return s.MaxIO + 64<<10
}

var bufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 8<<10); return &b },
}

func getBuf() *[]byte { return bufPool.Get().(*[]byte) }

func putBuf(b *[]byte) {
	if cap(*b) > 4<<20 {
		return
	}
	*b = (*b)[:0]
	bufPool.Put(b)
}

func (c *conn) serve() error {
	defer c.close()
	br := bufio.NewReaderSize(c.nc, 64<<10)
	maxRec := c.srv.maxRecordSize()
	for {
		bp := getBuf()
		msg, err := oncrpc.ReadRecord(br, *bp, maxRec)
		if err != nil {
			putBuf(bp)
			if errors.Is(err, io.EOF) || c.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			c.srv.debugf("nfsv4: read from %v: %v", c.nc.RemoteAddr(), err)
			return err
		}
		*bp = msg
		xid, mtype, err := oncrpc.MessageType(msg)
		if err != nil {
			putBuf(bp)
			return err
		}
		if mtype == oncrpc.Reply {
			c.handleCallbackReply(xid, msg)
			putBuf(bp)
			continue
		}
		select {
		case c.inflight <- struct{}{}:
		case <-c.ctx.Done():
			putBuf(bp)
			return nil
		}
		// The connection's own s.wg count keeps this Add from racing
		// with Server.Close's Wait.
		c.srv.wg.Add(1)
		go func() {
			defer c.srv.wg.Done()
			defer func() { <-c.inflight }()
			defer putBuf(bp)
			c.handleCall(msg)
		}()
	}
}

func (c *conn) close() {
	c.cancel()
	c.nc.Close()
	c.cbMu.Lock()
	c.closed = true
	for xid, ch := range c.cbPending {
		close(ch)
		delete(c.cbPending, xid)
	}
	c.cbMu.Unlock()
	c.srv.state.connClosed(c)
}

// writeRecord writes msg, whose first oncrpc.RecordHeaderLen bytes are
// reserved for the record marking header.
func (c *conn) writeRecord(msg []byte) error {
	oncrpc.FinishRecord(msg)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := c.nc.Write(msg)
	if err != nil {
		c.nc.Close()
	}
	return err
}

func (c *conn) handleCall(msg []byte) {
	rbp := getBuf()
	defer putBuf(rbp)
	e := xdr.NewEncoder(*rbp)
	e.Reserve(oncrpc.RecordHeaderLen)

	h, args, err := oncrpc.ParseCall(msg)
	if err != nil {
		var ve *oncrpc.VersionError
		if errors.As(err, &ve) {
			oncrpc.EncodeRPCMismatch(e, h.XID)
			c.writeRecord(e.Bytes())
			return
		}
		// Undecodable header; there's nothing useful to reply.
		c.srv.debugf("nfsv4: bad RPC call from %v: %v", c.nc.RemoteAddr(), err)
		return
	}
	if h.Prog != nfsProgram {
		oncrpc.EncodeAcceptedReply(e, h.XID, oncrpc.ProgUnavail)
		c.writeRecord(e.Bytes())
		return
	}
	if h.Vers != nfsVersion {
		oncrpc.EncodeAcceptedReply(e, h.XID, oncrpc.ProgMismatch)
		e.Uint32(nfsVersion)
		e.Uint32(nfsVersion)
		c.writeRecord(e.Bytes())
		return
	}
	cred, ok := parseCred(h.Cred)
	if !ok {
		oncrpc.EncodeAuthError(e, h.XID, oncrpc.AuthTooWeak)
		c.writeRecord(e.Bytes())
		return
	}
	switch h.Proc {
	case procNull:
		oncrpc.EncodeAcceptedReply(e, h.XID, oncrpc.Success)
		c.writeRecord(e.Bytes())
	case procCompound:
		oncrpc.EncodeAcceptedReply(e, h.XID, oncrpc.Success)
		cp := newCompound(c, cred, len(msg))
		cp.run(args, e)
		*rbp = e.Bytes() // keep any growth for reuse
		c.writeRecord(e.Bytes())
		cp.afterReplySent()
	default:
		oncrpc.EncodeAcceptedReply(e, h.XID, oncrpc.ProcUnavail)
		c.writeRecord(e.Bytes())
	}
}

func parseCred(a oncrpc.OpaqueAuth) (Cred, bool) {
	switch a.Flavor {
	case oncrpc.AuthNone:
		return Cred{Flavor: oncrpc.AuthNone, UID: nobodyID, GID: nobodyID}, true
	case oncrpc.AuthSys:
		sc, err := oncrpc.ParseAuthSys(a.Body)
		if err != nil {
			return Cred{}, false
		}
		return Cred{
			Flavor:      oncrpc.AuthSys,
			UID:         sc.UID,
			GID:         sc.GID,
			GIDs:        sc.GIDs,
			MachineName: sc.MachineName,
		}, true
	}
	return Cred{}, false
}

// errConnClosed is returned by call when the connection closes before a
// reply arrives.
var errConnClosed = errors.New("nfsv4: connection closed")

// call sends an RPC call to the client over this connection (used as a
// backchannel) and waits for the reply. It returns the reply's results
// (the bytes after the accepted-reply header) if the call succeeded at
// the RPC level.
func (c *conn) call(ctx context.Context, prog, vers, proc uint32, cred oncrpc.OpaqueAuth, args []byte) ([]byte, error) {
	ch := make(chan []byte, 1)
	c.cbMu.Lock()
	if c.closed {
		c.cbMu.Unlock()
		return nil, errConnClosed
	}
	xid := c.cbNextXID
	c.cbNextXID++
	c.cbPending[xid] = ch
	c.cbMu.Unlock()
	defer func() {
		c.cbMu.Lock()
		delete(c.cbPending, xid)
		c.cbMu.Unlock()
	}()

	e := xdr.NewEncoder(make([]byte, 0, 256+len(args)))
	e.Reserve(oncrpc.RecordHeaderLen)
	oncrpc.EncodeCall(e, oncrpc.CallHeader{
		XID:  xid,
		Prog: prog,
		Vers: vers,
		Proc: proc,
		Cred: cred,
		Verf: oncrpc.OpaqueAuth{Flavor: oncrpc.AuthNone},
	})
	e.FixedOpaque(args)
	if err := c.writeRecord(e.Bytes()); err != nil {
		return nil, err
	}

	select {
	case msg, ok := <-ch:
		if !ok {
			return nil, errConnClosed
		}
		h, res, err := oncrpc.ParseReply(msg)
		if err != nil {
			return nil, err
		}
		if h.Stat != oncrpc.MsgAccepted {
			return nil, errors.New("nfsv4: callback denied by client")
		}
		if h.AcceptStat != oncrpc.Success {
			return nil, errors.New("nfsv4: callback not accepted by client")
		}
		return res, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, errConnClosed
	}
}

func (c *conn) handleCallbackReply(xid uint32, msg []byte) {
	c.cbMu.Lock()
	ch, ok := c.cbPending[xid]
	delete(c.cbPending, xid)
	c.cbMu.Unlock()
	if !ok {
		c.srv.debugf("nfsv4: unexpected RPC reply xid %#x from %v", xid, c.nc.RemoteAddr())
		return
	}
	ch <- append([]byte(nil), msg...)
}
