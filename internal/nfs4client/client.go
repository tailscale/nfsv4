// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package nfs4client is a minimal NFSv4.1 client for testing the server at
// the protocol level. It builds COMPOUND requests from raw XDR and leaves
// decoding results to the caller.
package nfs4client

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/internal/oncrpc"
	"github.com/tailscale/nfsv4/internal/xdr"
)

// Client is a connection to an NFSv4 server.
type Client struct {
	nc net.Conn

	wmu sync.Mutex

	mu      sync.Mutex
	nextXID uint32
	pending map[uint32]chan []byte
	err     error

	// Callback, if non-nil, handles backchannel calls from the server.
	// It's given the CB_COMPOUND arguments and returns the results. It
	// must be set before the server could call back.
	Callback func(args []byte) []byte

	// MinorVersion is the minor version used for COMPOUNDs.
	MinorVersion uint32

	// Session state, set by CreateSession.
	ClientID  uint64
	SessionID [16]byte
	SlotSeq   []uint32
	slotMu    sync.Mutex
	freeSlots chan int
}

// New returns a Client using nc.
func New(nc net.Conn) *Client {
	c := &Client{
		nc:           nc,
		nextXID:      1,
		pending:      make(map[uint32]chan []byte),
		MinorVersion: 1,
	}
	go c.readLoop()
	return c
}

// Close closes the connection.
func (c *Client) Close() error { return c.nc.Close() }

func (c *Client) readLoop() {
	br := bufio.NewReader(c.nc)
	for {
		msg, err := oncrpc.ReadRecord(br, nil, 16<<20)
		if err != nil {
			c.mu.Lock()
			c.err = err
			for xid, ch := range c.pending {
				close(ch)
				delete(c.pending, xid)
			}
			c.mu.Unlock()
			return
		}
		xid, mtype, err := oncrpc.MessageType(msg)
		if err != nil {
			continue
		}
		if mtype == oncrpc.Call {
			go c.handleCallback(msg)
			continue
		}
		c.mu.Lock()
		ch := c.pending[xid]
		delete(c.pending, xid)
		c.mu.Unlock()
		if ch != nil {
			ch <- msg
		}
	}
}

func (c *Client) handleCallback(msg []byte) {
	h, args, err := oncrpc.ParseCall(msg)
	if err != nil {
		return
	}
	e := xdr.NewEncoder(nil)
	e.Reserve(oncrpc.RecordHeaderLen)
	oncrpc.EncodeAcceptedReply(e, h.XID, oncrpc.Success)
	if h.Proc == 1 && c.Callback != nil {
		e.FixedOpaque(c.Callback(args))
	}
	c.write(e.Bytes())
}

func (c *Client) write(msg []byte) error {
	oncrpc.FinishRecord(msg)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.nc.Write(msg)
	return err
}

// Call makes an RPC call to the NFS program and returns the results.
func (c *Client) Call(proc uint32, args []byte) ([]byte, error) {
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return nil, c.err
	}
	xid := c.nextXID
	c.nextXID++
	ch := make(chan []byte, 1)
	c.pending[xid] = ch
	c.mu.Unlock()

	cred := oncrpc.AuthSysCred{MachineName: "testclient", UID: 1000, GID: 1000}
	e := xdr.NewEncoder(nil)
	e.Reserve(oncrpc.RecordHeaderLen)
	oncrpc.EncodeCall(e, oncrpc.CallHeader{
		XID:  xid,
		Prog: 100003,
		Vers: 4,
		Proc: proc,
		Cred: oncrpc.OpaqueAuth{Flavor: oncrpc.AuthSys, Body: cred.Encode()},
		Verf: oncrpc.OpaqueAuth{Flavor: oncrpc.AuthNone},
	})
	e.FixedOpaque(args)
	if err := c.write(e.Bytes()); err != nil {
		return nil, err
	}
	msg, ok := <-ch
	if !ok {
		return nil, errors.New("connection closed")
	}
	h, res, err := oncrpc.ParseReply(msg)
	if err != nil {
		return nil, err
	}
	if h.Stat != oncrpc.MsgAccepted || h.AcceptStat != oncrpc.Success {
		return nil, fmt.Errorf("RPC failed: %+v", h)
	}
	return res, nil
}

// Compound is a COMPOUND request being built.
type Compound struct {
	E   xdr.Encoder
	n   int
	ops []nfsv4.Op
}

// Op appends an operation; the caller then encodes its arguments to
// b.E.
func (b *Compound) Op(op nfsv4.Op) *xdr.Encoder {
	b.E.Uint32(uint32(op))
	b.n++
	b.ops = append(b.ops, op)
	return &b.E
}

// Result is a COMPOUND result.
type Result struct {
	Status Status
	Tag    string
	NumRes int
	D      *xdr.Decoder // positioned at the first result
	ops    []nfsv4.Op
	idx    int

	// SeqFlags are the SEQUENCE status flags, set by DoSeq.
	SeqFlags uint32
}

// Status is an alias for nfsv4.Status.
type Status = nfsv4.Status

// Next reads the next result's operation number and status, checking the
// operation is the expected one.
func (r *Result) Next(op nfsv4.Op) (Status, error) {
	got := nfsv4.Op(r.D.Uint32())
	st := Status(r.D.Uint32())
	if err := r.D.Err(); err != nil {
		return 0, err
	}
	if got != op {
		return st, fmt.Errorf("result %d is %v; want %v", r.idx, got, op)
	}
	r.idx++
	return st, nil
}

// Do sends a COMPOUND with the given operations (without adding a
// SEQUENCE).
func (c *Client) Do(b *Compound) (*Result, error) {
	var e xdr.Encoder
	e.String("test")
	e.Uint32(c.MinorVersion)
	e.Uint32(uint32(b.n))
	e.FixedOpaque(b.E.Bytes())
	res, err := c.Call(1, e.Bytes())
	if err != nil {
		return nil, err
	}
	d := xdr.NewDecoder(res)
	r := &Result{
		Status: Status(d.Uint32()),
		Tag:    d.String(1024),
		NumRes: int(d.Uint32()),
		D:      d,
		ops:    b.ops,
	}
	return r, d.Err()
}

// ExchangeID sends EXCHANGE_ID with the given owner and verifier and
// records the client ID.
func (c *Client) ExchangeID(owner string, verifier uint64) (seq uint32, flags uint32, err error) {
	var b Compound
	e := b.Op(nfsv4.OpExchangeID)
	e.Uint64(verifier)
	e.String(owner)
	e.Uint32(0x101)
	e.Uint32(0) // SP4_NONE
	e.Uint32(0) // no impl id
	r, err := c.Do(&b)
	if err != nil {
		return 0, 0, err
	}
	st, err := r.Next(nfsv4.OpExchangeID)
	if err != nil {
		return 0, 0, err
	}
	if st != nfsv4.OK {
		return 0, 0, st
	}
	c.ClientID = r.D.Uint64()
	seq = r.D.Uint32()
	flags = r.D.Uint32()
	return seq, flags, r.D.Err()
}

// CreateSession creates a session with the given number of slots, with a
// backchannel if back is set.
func (c *Client) CreateSession(seq uint32, slots int, back bool) error {
	var b Compound
	e := b.Op(nfsv4.OpCreateSession)
	e.Uint64(c.ClientID)
	e.Uint32(seq)
	if back {
		e.Uint32(2) // CONN_BACK_CHAN
	} else {
		e.Uint32(0)
	}
	// fore channel
	for _, v := range []uint32{0, 1 << 20, 1 << 20, 8192, 16, uint32(slots), 0} {
		e.Uint32(v)
	}
	// back channel
	for _, v := range []uint32{0, 4096, 4096, 0, 2, 1, 0} {
		e.Uint32(v)
	}
	e.Uint32(0x40000000) // cb program
	e.Uint32(1)          // one sec parm
	e.Uint32(oncrpc.AuthSys)
	oncrpc.AuthSysCred{MachineName: "testclient"}.EncodeTo(e)
	r, err := c.Do(&b)
	if err != nil {
		return err
	}
	st, err := r.Next(nfsv4.OpCreateSession)
	if err != nil {
		return err
	}
	if st != nfsv4.OK {
		return st
	}
	copy(c.SessionID[:], r.D.FixedOpaque(16))
	r.D.Uint32() // seq
	r.D.Uint32() // flags
	r.D.Uint32() // fore: headerpad
	r.D.Uint32()
	r.D.Uint32()
	r.D.Uint32()
	r.D.Uint32()
	nslots := r.D.Uint32()
	if err := r.D.Err(); err != nil {
		return err
	}
	c.SlotSeq = make([]uint32, nslots)
	c.freeSlots = make(chan int, nslots)
	for i := range int(nslots) {
		c.freeSlots <- i
	}
	return nil
}

// Setup does EXCHANGE_ID and CREATE_SESSION.
func (c *Client) Setup(owner string, back bool) error {
	seq, _, err := c.ExchangeID(owner, 1)
	if err != nil {
		return fmt.Errorf("EXCHANGE_ID: %w", err)
	}
	if err := c.CreateSession(seq, 8, back); err != nil {
		return fmt.Errorf("CREATE_SESSION: %w", err)
	}
	return nil
}

// Seq starts a Compound with a SEQUENCE using a free slot. The caller must
// call Done on the result (or DoSeq does it).
func (c *Client) Seq() (*Compound, int) {
	slot := <-c.freeSlots
	c.slotMu.Lock()
	c.SlotSeq[slot]++
	seq := c.SlotSeq[slot]
	c.slotMu.Unlock()
	var b Compound
	e := b.Op(nfsv4.OpSequence)
	e.FixedOpaque(c.SessionID[:])
	e.Uint32(seq)
	e.Uint32(uint32(slot))
	e.Uint32(uint32(len(c.SlotSeq) - 1))
	e.Bool(false)
	return &b, slot
}

// DoSeq sends b (started by Seq) and checks the SEQUENCE result, leaving
// r.D positioned at the second result.
func (c *Client) DoSeq(b *Compound, slot int) (*Result, error) {
	defer func() { c.freeSlots <- slot }()
	r, err := c.Do(b)
	if err != nil {
		return nil, err
	}
	st, err := r.Next(nfsv4.OpSequence)
	if err != nil {
		return nil, err
	}
	if st != nfsv4.OK {
		return r, fmt.Errorf("SEQUENCE: %w", st)
	}
	r.D.FixedOpaque(16)
	r.D.Uint32()
	r.D.Uint32()
	r.D.Uint32()
	r.D.Uint32()
	r.SeqFlags = r.D.Uint32()
	return r, r.D.Err()
}

// RemoteAddr returns the server's address.
func (c *Client) RemoteAddr() string { return c.nc.RemoteAddr().String() }

// AdoptSession makes c use o's client ID and session (with its slot
// sequence numbers), as a client does when it reconnects.
func (c *Client) AdoptSession(o *Client) {
	c.ClientID = o.ClientID
	c.SessionID = o.SessionID
	o.slotMu.Lock()
	c.SlotSeq = append([]uint32(nil), o.SlotSeq...)
	o.slotMu.Unlock()
	c.freeSlots = make(chan int, len(c.SlotSeq))
	for i := range c.SlotSeq {
		c.freeSlots <- i
	}
}
