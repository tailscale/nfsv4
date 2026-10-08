// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/internal/nfs4client"
	"github.com/tailscale/nfsv4/internal/testfs"
	"github.com/tailscale/nfsv4/internal/xdr"
)

// newTestServer starts srv on a loopback listener and returns a connected
// client without a session.
func newTestServer(t *testing.T, srv *nfsv4.Server) *nfs4client.Client {
	t.Helper()
	if srv.Logf == nil {
		srv.Logf = t.Logf
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return dialTestServer(t, ln.Addr().String())
}

func dialTestServer(t *testing.T, addr string) *nfs4client.Client {
	t.Helper()
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c := nfs4client.New(nc)
	t.Cleanup(func() { c.Close() })
	return c
}

// newSessionClient returns a client with a session to a server for fs.
func newSessionClient(t *testing.T, srv *nfsv4.Server, back bool) *nfs4client.Client {
	t.Helper()
	c := newTestServer(t, srv)
	if err := c.Setup(t.Name(), back); err != nil {
		t.Fatal(err)
	}
	return c
}

func must(t *testing.T, r *nfs4client.Result, op nfsv4.Op) {
	t.Helper()
	st, err := r.Next(op)
	if err != nil {
		t.Fatal(err)
	}
	if st != nfsv4.OK {
		t.Fatalf("%v: %v", op, st)
	}
}

func expect(t *testing.T, r *nfs4client.Result, op nfsv4.Op, want nfsv4.Status) {
	t.Helper()
	st, err := r.Next(op)
	if err != nil {
		t.Fatal(err)
	}
	if st != want {
		t.Fatalf("%v = %v; want %v", op, st, want)
	}
}

func skipBitmap(d *xdr.Decoder) {
	n := d.ArrayLen(10, 4)
	for range n {
		d.Uint32()
	}
}

func encodeBitmap(e *xdr.Encoder, attrs ...nfsv4.Attr) {
	m := nfsv4.MakeAttrMask(attrs...)
	var w [3]uint32
	for _, a := range m.All() {
		w[a/32] |= 1 << (a % 32)
	}
	e.Uint32(3)
	for _, x := range w {
		e.Uint32(x)
	}
}

// lookupPath appends PUTROOTFH and LOOKUPs for each component of p.
func lookupPath(b *nfs4client.Compound, comps ...string) {
	b.Op(nfsv4.OpPutRootFH)
	for _, c := range comps {
		b.Op(nfsv4.OpLookup).String(c)
	}
}

func skipLookups(t *testing.T, r *nfs4client.Result, n int) {
	t.Helper()
	must(t, r, nfsv4.OpPutRootFH)
	for range n {
		must(t, r, nfsv4.OpLookup)
	}
}

func TestNullProc(t *testing.T) {
	c := newTestServer(t, &nfsv4.Server{FS: testfs.New()})
	if _, err := c.Call(0, nil); err != nil {
		t.Fatal(err)
	}
}

func TestMinorVersionMismatch(t *testing.T) {
	c := newTestServer(t, &nfsv4.Server{FS: testfs.New()})
	c.MinorVersion = 0
	var b nfs4client.Compound
	b.Op(nfsv4.OpPutRootFH)
	r, err := c.Do(&b)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != nfsv4.ErrMinorVersMismatch || r.NumRes != 0 {
		t.Errorf("got %v with %d results", r.Status, r.NumRes)
	}
}

func TestOpNotInSession(t *testing.T) {
	c := newTestServer(t, &nfsv4.Server{FS: testfs.New()})
	var b nfs4client.Compound
	b.Op(nfsv4.OpPutRootFH)
	b.Op(nfsv4.OpGetFH)
	r, err := c.Do(&b)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != nfsv4.ErrOpNotInSession || r.NumRes != 1 {
		t.Errorf("got %v with %d results", r.Status, r.NumRes)
	}
}

func TestExchangeIDConfirmed(t *testing.T) {
	c := newTestServer(t, &nfsv4.Server{FS: testfs.New()})
	seq, flags, err := c.ExchangeID("owner", 1)
	if err != nil {
		t.Fatal(err)
	}
	if flags&0x80000000 != 0 {
		t.Errorf("new client is CONFIRMED_R")
	}
	if flags&0x70000 != 0x10000 {
		t.Errorf("flags %#x lack exactly USE_NON_PNFS", flags)
	}
	id := c.ClientID
	if err := c.CreateSession(seq, 4, false); err != nil {
		t.Fatal(err)
	}
	// A replay of CREATE_SESSION gets the same session.
	sid := c.SessionID
	if err := c.CreateSession(seq, 4, false); err != nil {
		t.Fatalf("CREATE_SESSION replay: %v", err)
	}
	if c.SessionID != sid {
		t.Errorf("CREATE_SESSION replay returned a different session")
	}
	// A wrong sequence is misordered.
	if err := c.CreateSession(seq+5, 4, false); !errors.Is(err, nfsv4.ErrSeqMisordered) {
		t.Errorf("misordered CREATE_SESSION: %v", err)
	}
	// EXCHANGE_ID again with the same verifier returns the confirmed
	// client.
	_, flags, err = c.ExchangeID("owner", 1)
	if err != nil {
		t.Fatal(err)
	}
	if c.ClientID != id || flags&0x80000000 == 0 {
		t.Errorf("second EXCHANGE_ID: id %#x (want %#x), flags %#x", c.ClientID, id, flags)
	}
	// A new verifier means a client reboot: a new client ID.
	_, _, err = c.ExchangeID("owner", 2)
	if err != nil {
		t.Fatal(err)
	}
	if c.ClientID == id {
		t.Errorf("client ID unchanged after verifier change")
	}
	// A stale client ID.
	c.ClientID = 12345
	if err := c.CreateSession(1, 4, false); !errors.Is(err, nfsv4.ErrStaleClientID) {
		t.Errorf("CREATE_SESSION with bogus client ID: %v", err)
	}
}

// rawSeq builds a compound with a SEQUENCE with explicit fields followed by
// PUTROOTFH and GETFH.
func rawSeq(c *nfs4client.Client, seq, slot uint32, cacheThis bool) *nfs4client.Compound {
	var b nfs4client.Compound
	e := b.Op(nfsv4.OpSequence)
	e.FixedOpaque(c.SessionID[:])
	e.Uint32(seq)
	e.Uint32(slot)
	e.Uint32(slot)
	e.Bool(cacheThis)
	b.Op(nfsv4.OpPutRootFH)
	b.Op(nfsv4.OpGetFH)
	return &b
}

func TestSequenceSlots(t *testing.T) {
	c := newSessionClient(t, &nfsv4.Server{FS: testfs.New()}, false)
	do := func(seq, slot uint32, cacheThis bool) (*nfs4client.Result, nfsv4.Status) {
		t.Helper()
		r, err := c.Do(rawSeq(c, seq, slot, cacheThis))
		if err != nil {
			t.Fatal(err)
		}
		st, err := r.Next(nfsv4.OpSequence)
		if err != nil {
			t.Fatal(err)
		}
		return r, st
	}
	if _, st := do(1, 0, true); st != nfsv4.OK {
		t.Fatalf("first SEQUENCE: %v", st)
	}
	// A replay of a cached request gets the cached reply.
	if r, st := do(1, 0, true); st != nfsv4.OK || r.NumRes != 3 {
		t.Errorf("replay: %v, %d results", st, r.NumRes)
	}
	if _, st := do(2, 0, false); st != nfsv4.OK {
		t.Fatalf("second SEQUENCE: %v", st)
	}
	// A replay of an uncached request.
	if r, st := do(2, 0, false); st != nfsv4.OK || r.Status != nfsv4.ErrRetryUncachedRep || r.NumRes != 2 {
		t.Fatalf("uncached replay: SEQUENCE %v, compound %v, %d results", st, r.Status, r.NumRes)
	} else {
		r.D.FixedOpaque(36)
		expect(t, r, nfsv4.OpPutRootFH, nfsv4.ErrRetryUncachedRep)
		if r.D.Err() != nil || r.D.Remaining() != 0 {
			t.Fatalf("uncached replay has malformed or extra results: %v", r.D.Err())
		}
	}
	if _, st := do(5, 0, false); st != nfsv4.ErrSeqMisordered {
		t.Errorf("misordered: %v", st)
	}
	if _, st := do(1, 1, false); st != nfsv4.OK {
		t.Errorf("other slot: %v", st)
	}
	if _, st := do(1, 100, false); st != nfsv4.ErrBadSlot {
		t.Errorf("bad slot: %v", st)
	}
	c.SessionID[0] ^= 0xff
	if _, st := do(3, 0, false); st != nfsv4.ErrBadSession {
		t.Errorf("bad session: %v", st)
	}
}

func TestLookupGetAttr(t *testing.T) {
	fs := newTestTree()
	c := newSessionClient(t, &nfsv4.Server{FS: fs}, false)

	b, slot := c.Seq()
	lookupPath(b, "sub", "exec.sh")
	b.Op(nfsv4.OpGetFH)
	encodeBitmap(b.Op(nfsv4.OpGetAttr), nfsv4.AttrType, nfsv4.AttrSize, nfsv4.AttrMode, nfsv4.AttrOwner, nfsv4.AttrNumLinks)
	r, err := c.DoSeq(b, slot)
	if err != nil {
		t.Fatal(err)
	}
	skipLookups(t, r, 2)
	must(t, r, nfsv4.OpGetFH)
	fh := r.D.Opaque(128)
	if string(fh) != string(fs.Handle("/sub/exec.sh")) {
		t.Errorf("GETFH = %x", fh)
	}
	must(t, r, nfsv4.OpGetAttr)
	skipBitmap(r.D)
	vals := xdr.NewDecoder(r.D.Opaque(1000))
	typ, size, mode := vals.Uint32(), vals.Uint64(), vals.Uint32()
	nlink, owner := vals.Uint32(), vals.String(100)
	if typ != 1 || size != 18 || mode != 0o755 || nlink != 1 || owner != "0" {
		t.Errorf("attrs: type=%d size=%d mode=%o nlink=%d owner=%q", typ, size, mode, nlink, owner)
	}

	for _, tt := range []struct {
		name string
		want nfsv4.Status
	}{
		{"nope", nfsv4.ErrNoEnt},
		{"..", nfsv4.ErrBadName},
		{"a/b", nfsv4.ErrBadChar},
		{"", nfsv4.ErrInval},
	} {
		b, slot := c.Seq()
		lookupPath(b, tt.name)
		r, err := c.DoSeq(b, slot)
		if err != nil {
			t.Fatal(err)
		}
		must(t, r, nfsv4.OpPutRootFH)
		expect(t, r, nfsv4.OpLookup, tt.want)
	}

	// LOOKUP in a file.
	b, slot = c.Seq()
	lookupPath(b, "hello.txt", "x")
	r, err = c.DoSeq(b, slot)
	if err != nil {
		t.Fatal(err)
	}
	skipLookups(t, r, 1)
	expect(t, r, nfsv4.OpLookup, nfsv4.ErrNotDir)

	// LOOKUPP from the root, and from a subdirectory.
	b, slot = c.Seq()
	b.Op(nfsv4.OpPutRootFH)
	b.Op(nfsv4.OpLookupp)
	r, _ = c.DoSeq(b, slot)
	must(t, r, nfsv4.OpPutRootFH)
	expect(t, r, nfsv4.OpLookupp, nfsv4.ErrNoEnt)

	b, slot = c.Seq()
	lookupPath(b, "sub", "dir")
	b.Op(nfsv4.OpLookupp)
	b.Op(nfsv4.OpGetFH)
	r, _ = c.DoSeq(b, slot)
	skipLookups(t, r, 2)
	must(t, r, nfsv4.OpLookupp)
	must(t, r, nfsv4.OpGetFH)
	if fh := r.D.Opaque(128); string(fh) != string(fs.Handle("/sub")) {
		t.Errorf("LOOKUPP gave %x", fh)
	}
}

func TestReadDirPaging(t *testing.T) {
	fs := newTestTree()
	c := newSessionClient(t, &nfsv4.Server{FS: fs}, false)
	var names []string
	var cookie, verf uint64
	pages := 0
	for {
		b, slot := c.Seq()
		lookupPath(b, "many")
		e := b.Op(nfsv4.OpReadDir)
		e.Uint64(cookie)
		e.Uint64(verf)
		e.Uint32(0)
		e.Uint32(1024)
		encodeBitmap(e, nfsv4.AttrType, nfsv4.AttrFileID)
		r, err := c.DoSeq(b, slot)
		if err != nil {
			t.Fatal(err)
		}
		skipLookups(t, r, 1)
		must(t, r, nfsv4.OpReadDir)
		verf = r.D.Uint64()
		n := 0
		for r.D.Bool() {
			cookie = r.D.Uint64()
			names = append(names, r.D.String(255))
			skipBitmap(r.D)
			r.D.Opaque(100)
			n++
		}
		eof := r.D.Bool()
		if err := r.D.Err(); err != nil {
			t.Fatal(err)
		}
		pages++
		if n == 0 && !eof {
			t.Fatal("empty non-eof page")
		}
		if eof {
			break
		}
	}
	if len(names) != 300 || !sort.StringsAreSorted(names) || names[0] != "f000" {
		t.Errorf("got %d names (sorted: %v)", len(names), sort.StringsAreSorted(names))
	}
	if pages < 5 {
		t.Errorf("only %d pages with maxcount 1024", pages)
	}

	// A maxcount too small for even one entry.
	b, slot := c.Seq()
	lookupPath(b, "many")
	e := b.Op(nfsv4.OpReadDir)
	e.Uint64(0)
	e.Uint64(0)
	e.Uint32(0)
	e.Uint32(20)
	encodeBitmap(e, nfsv4.AttrType)
	r, _ := c.DoSeq(b, slot)
	skipLookups(t, r, 1)
	expect(t, r, nfsv4.OpReadDir, nfsv4.ErrTooSmall)
}

// openArgs encodes OPEN arguments for a CLAIM_NULL open of name.
func openArgs(e *xdr.Encoder, access uint32, name string) {
	e.Uint32(0)      // seqid
	e.Uint32(access) // share_access
	e.Uint32(0)      // share_deny
	e.Uint64(0)      // owner clientid
	e.String("open-owner")
	e.Uint32(0) // OPEN4_NOCREATE
	e.Uint32(0) // CLAIM_NULL
	e.String(name)
}

type stateID struct {
	seq   uint32
	other []byte
}

func decodeStateID(d *xdr.Decoder) stateID {
	return stateID{d.Uint32(), d.FixedOpaque(12)}
}

func (s stateID) encode(e *xdr.Encoder) {
	e.Uint32(s.seq)
	e.FixedOpaque(s.other)
}

// decodeOpen decodes an OPEN result, returning the open stateid and the
// delegation stateid (if a read delegation was granted).
func decodeOpen(t *testing.T, d *xdr.Decoder) (open stateID, deleg *stateID) {
	t.Helper()
	open = decodeStateID(d)
	d.Bool()   // cinfo atomic
	d.Uint64() // before
	d.Uint64() // after
	d.Uint32() // rflags
	skipBitmap(d)
	switch dt := d.Uint32(); dt {
	case 0:
	case 1:
		s := decodeStateID(d)
		deleg = &s
		d.Bool()
		d.Uint32()
		d.Uint32()
		d.Uint32()
		d.String(100)
	case 3:
		why := d.Uint32()
		if why == 1 || why == 2 {
			d.Bool()
		}
	default:
		t.Fatalf("unexpected delegation type %d", dt)
	}
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}
	return open, deleg
}

func TestOpenReadClose(t *testing.T) {
	fs := newTestTree()
	c := newSessionClient(t, &nfsv4.Server{FS: fs}, false)

	b, slot := c.Seq()
	b.Op(nfsv4.OpPutRootFH)
	openArgs(b.Op(nfsv4.OpOpen), 1, "hello.txt")
	b.Op(nfsv4.OpGetFH)
	r, err := c.DoSeq(b, slot)
	if err != nil {
		t.Fatal(err)
	}
	must(t, r, nfsv4.OpPutRootFH)
	must(t, r, nfsv4.OpOpen)
	sid, deleg := decodeOpen(t, r.D)
	if deleg != nil {
		t.Errorf("got a delegation without a Delegator")
	}
	must(t, r, nfsv4.OpGetFH)
	fh := r.D.Opaque(128)

	read := func(s stateID, off uint64, count uint32) (nfsv4.Status, string, bool) {
		t.Helper()
		b, slot := c.Seq()
		b.Op(nfsv4.OpPutFH).Opaque(fh)
		e := b.Op(nfsv4.OpRead)
		s.encode(e)
		e.Uint64(off)
		e.Uint32(count)
		r, err := c.DoSeq(b, slot)
		if err != nil {
			t.Fatal(err)
		}
		must(t, r, nfsv4.OpPutFH)
		st, err := r.Next(nfsv4.OpRead)
		if err != nil {
			t.Fatal(err)
		}
		if st != nfsv4.OK {
			return st, "", false
		}
		eof := r.D.Bool()
		return st, string(r.D.Opaque(1 << 20)), eof
	}
	if st, data, eof := read(sid, 0, 5); st != nfsv4.OK || data != "hello" || eof {
		t.Errorf("READ = %v, %q, %v", st, data, eof)
	}
	if st, data, eof := read(sid, 7, 100); st != nfsv4.OK || data != "world\n" || !eof {
		t.Errorf("READ = %v, %q, %v", st, data, eof)
	}
	anon := stateID{0, make([]byte, 12)}
	if st, data, _ := read(anon, 0, 100); st != nfsv4.OK || data != "hello, world\n" {
		t.Errorf("anonymous READ = %v, %q", st, data)
	}
	old := sid
	old.seq = 0
	if st, _, _ := read(old, 0, 1); st != nfsv4.OK {
		t.Errorf("READ with seqid 0 = %v", st)
	}

	// CLOSE, after which the stateid is invalid.
	b, slot = c.Seq()
	b.Op(nfsv4.OpPutFH).Opaque(fh)
	e := b.Op(nfsv4.OpClose)
	e.Uint32(0)
	sid.encode(e)
	r, err = c.DoSeq(b, slot)
	if err != nil {
		t.Fatal(err)
	}
	must(t, r, nfsv4.OpPutFH)
	must(t, r, nfsv4.OpClose)
	// Reading with a stateid that's no longer valid works (see
	// checkReadStateID), but not with one for a different file.
	if st, _, _ := read(sid, 0, 1); st != nfsv4.OK {
		t.Errorf("READ after CLOSE = %v", st)
	}
	b, slot = c.Seq()
	b.Op(nfsv4.OpPutRootFH)
	openArgs(b.Op(nfsv4.OpOpen), 1, "big.bin")
	r, err = c.DoSeq(b, slot)
	if err != nil {
		t.Fatal(err)
	}
	must(t, r, nfsv4.OpPutRootFH)
	must(t, r, nfsv4.OpOpen)
	other, _ := decodeOpen(t, r.D)
	if st, _, _ := read(other, 0, 1); st != nfsv4.ErrBadStateID {
		t.Errorf("READ with another file's stateid = %v", st)
	}

	// Opens that fail.
	for _, tt := range []struct {
		access uint32
		name   string
		want   nfsv4.Status
	}{
		{3, "hello.txt", nfsv4.ErrROFS},
		{1, "sub", nfsv4.ErrIsDir},
		{1, "nope", nfsv4.ErrNoEnt},
	} {
		b, slot := c.Seq()
		b.Op(nfsv4.OpPutRootFH)
		openArgs(b.Op(nfsv4.OpOpen), tt.access, tt.name)
		r, err := c.DoSeq(b, slot)
		if err != nil {
			t.Fatal(err)
		}
		must(t, r, nfsv4.OpPutRootFH)
		expect(t, r, nfsv4.OpOpen, tt.want)
	}
}

func TestReadOnlyAndIllegalOps(t *testing.T) {
	c := newSessionClient(t, &nfsv4.Server{FS: newTestTree()}, false)
	b, slot := c.Seq()
	b.Op(nfsv4.OpPutRootFH)
	b.Op(nfsv4.OpRemove).String("hello.txt")
	r, _ := c.DoSeq(b, slot)
	must(t, r, nfsv4.OpPutRootFH)
	expect(t, r, nfsv4.OpRemove, nfsv4.ErrROFS)

	b, slot = c.Seq()
	b.Op(nfsv4.OpPutRootFH)
	b.Op(nfsv4.Op(9999))
	r, _ = c.DoSeq(b, slot)
	must(t, r, nfsv4.OpPutRootFH)
	expect(t, r, nfsv4.OpIllegal, nfsv4.ErrOpIllegal)
}

// recallClient is a test client whose backchannel handler answers
// CB_RECALL, recording recalled stateids.
type recallClient struct {
	*nfs4client.Client
	t *testing.T

	mu       sync.Mutex
	recalled [][]byte // stateid "other" values
	onRecall func(other []byte, fh []byte)
}

func newRecallClient(t *testing.T, srv *nfsv4.Server) *recallClient {
	rc := &recallClient{t: t}
	rc.Client = newTestServer(t, srv)
	rc.Callback = rc.handle
	if err := rc.Setup(t.Name(), true); err != nil {
		t.Fatal(err)
	}
	return rc
}

func (rc *recallClient) handle(args []byte) []byte {
	d := xdr.NewDecoder(args)
	d.String(100)
	d.Uint32() // minor
	d.Uint32() // ident
	n := d.Uint32()
	var e xdr.Encoder
	e.Uint32(0)
	e.String("")
	e.Uint32(n)
	for range n {
		op := d.Uint32()
		e.Uint32(op)
		switch nfsv4.CBOp(op) {
		case nfsv4.CBOpSequence:
			sid := d.FixedOpaque(16)
			seq := d.Uint32()
			slot := d.Uint32()
			d.Uint32()
			d.Bool()
			nl := d.Uint32()
			for range nl {
				d.FixedOpaque(16)
				nc := d.Uint32()
				for range nc {
					d.Uint32()
					d.Uint32()
				}
			}
			e.Uint32(0)
			e.FixedOpaque(sid)
			e.Uint32(seq)
			e.Uint32(slot)
			e.Uint32(0)
			e.Uint32(0)
		case nfsv4.CBOpRecall:
			s := decodeStateID(d)
			d.Bool()
			fh := d.Opaque(128)
			rc.mu.Lock()
			rc.recalled = append(rc.recalled, s.other)
			f := rc.onRecall
			rc.mu.Unlock()
			if f != nil {
				go f(s.other, fh)
			}
			e.Uint32(0)
		default:
			e.Uint32(uint32(nfsv4.ErrNotSupp))
			return e.Bytes()
		}
	}
	return e.Bytes()
}

func (rc *recallClient) delegReturn(fh []byte, s stateID) error {
	b, slot := rc.Seq()
	b.Op(nfsv4.OpPutFH).Opaque(fh)
	s.encode(b.Op(nfsv4.OpDelegReturn))
	r, err := rc.DoSeq(b, slot)
	if err != nil {
		return err
	}
	r.Next(nfsv4.OpPutFH)
	st, err := r.Next(nfsv4.OpDelegReturn)
	if err != nil {
		return err
	}
	if st != nfsv4.OK {
		return st
	}
	return nil
}

func delegatingServer(fs *testfs.FS) *nfsv4.Server {
	fs.DelegatePolicy = func(path string, a *nfsv4.Attrs) nfsv4.Delegation {
		return nfsv4.Delegation{Grant: true}
	}
	return &nfsv4.Server{FS: fs.WithDelegator(), LeaseTime: 2 * time.Second}
}

func (rc *recallClient) openDeleg(name string) (fh []byte, deleg stateID) {
	t := rc.t
	t.Helper()
	b, slot := rc.Seq()
	b.Op(nfsv4.OpPutRootFH)
	openArgs(b.Op(nfsv4.OpOpen), 1, name)
	b.Op(nfsv4.OpGetFH)
	r, err := rc.DoSeq(b, slot)
	if err != nil {
		t.Fatal(err)
	}
	must(t, r, nfsv4.OpPutRootFH)
	must(t, r, nfsv4.OpOpen)
	_, d := decodeOpen(t, r.D)
	if d == nil {
		t.Fatal("no delegation granted")
	}
	must(t, r, nfsv4.OpGetFH)
	return r.D.Opaque(128), *d
}

func TestDelegationRecall(t *testing.T) {
	fs := newTestTree()
	srv := delegatingServer(fs)
	rc := newRecallClient(t, srv)
	fh, deleg := rc.openDeleg("hello.txt")

	returned := make(chan error, 1)
	rc.mu.Lock()
	rc.onRecall = func(other, rfh []byte) {
		if string(other) != string(deleg.other) || string(rfh) != string(fh) {
			returned <- fmt.Errorf("recall of wrong delegation")
			return
		}
		returned <- rc.delegReturn(fh, deleg)
	}
	rc.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	release, err := srv.Recall(ctx, fh)
	if err != nil {
		t.Fatalf("Recall: %v", err)
	}
	release()
	if err := <-returned; err != nil {
		t.Fatal(err)
	}
	if st := srv.Stats(); st.Delegations != 0 || st.Revocations != 0 || st.Recalls != 1 {
		t.Errorf("stats: %+v", st)
	}
	// Recall with nothing delegated returns immediately.
	release, err = srv.Recall(ctx, fh)
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestDelegationRevoked(t *testing.T) {
	fs := newTestTree()
	srv := delegatingServer(fs)
	rc := newRecallClient(t, srv)
	fh, deleg := rc.openDeleg("hello.txt")

	// The client acknowledges the recall but never returns the
	// delegation, so it's revoked after the lease time.
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	release, err := srv.Recall(ctx, fh)
	if err != nil {
		t.Fatalf("Recall: %v", err)
	}
	release()
	if d := time.Since(start); d < time.Second {
		t.Errorf("Recall returned after only %v", d)
	}
	if st := srv.Stats(); st.Revocations != 1 || st.Delegations != 0 {
		t.Errorf("stats: %+v", st)
	}

	// SEQUENCE now reports revoked state, TEST_STATEID reports it, and
	// FREE_STATEID clears it.
	b, slot := rc.Seq()
	e := b.Op(nfsv4.OpTestStateID)
	e.Uint32(1)
	deleg.encode(e)
	r, err := rc.DoSeq(b, slot)
	if err != nil {
		t.Fatal(err)
	}
	if r.SeqFlags&0x40 == 0 {
		t.Errorf("SEQUENCE flags %#x lack RECALLABLE_STATE_REVOKED", r.SeqFlags)
	}
	must(t, r, nfsv4.OpTestStateID)
	if n, st := r.D.Uint32(), nfsv4.Status(r.D.Uint32()); n != 1 || st != nfsv4.ErrDelegRevoked {
		t.Errorf("TEST_STATEID = %d, %v", n, st)
	}

	b, slot = rc.Seq()
	deleg.encode(b.Op(nfsv4.OpFreeStateID))
	r, err = rc.DoSeq(b, slot)
	if err != nil {
		t.Fatal(err)
	}
	must(t, r, nfsv4.OpFreeStateID)

	b, slot = rc.Seq()
	b.Op(nfsv4.OpPutRootFH)
	r, err = rc.DoSeq(b, slot)
	if err != nil {
		t.Fatal(err)
	}
	if r.SeqFlags&0x40 != 0 {
		t.Errorf("SEQUENCE flags %#x still have RECALLABLE_STATE_REVOKED after FREE_STATEID", r.SeqFlags)
	}
}

func TestGetDirDelegation(t *testing.T) {
	fs := newTestTree()
	srv := delegatingServer(fs)
	rc := newRecallClient(t, srv)

	gdd := func(comps ...string) *nfs4client.Result {
		b, slot := rc.Seq()
		lookupPath(b, comps...)
		e := b.Op(nfsv4.OpGetDirDelegation)
		e.Bool(false)
		e.Uint32(1)
		e.Uint32(0)
		e.Uint64(0)
		e.Uint32(0)
		e.Uint64(0)
		e.Uint32(0)
		e.Uint32(1)
		e.Uint32(0)
		e.Uint32(1)
		e.Uint32(0)
		r, err := rc.DoSeq(b, slot)
		if err != nil {
			t.Fatal(err)
		}
		skipLookups(t, r, len(comps))
		return r
	}
	r := gdd("sub")
	must(t, r, nfsv4.OpGetDirDelegation)
	if st := r.D.Uint32(); st != 0 {
		t.Fatalf("GDD non-fatal status %d", st)
	}
	r.D.Uint64() // cookie verifier
	decodeStateID(r.D)
	// Each bitmap must have exactly one word for the Linux client.
	for i := range 3 {
		if n := r.D.Uint32(); n != 1 {
			t.Errorf("bitmap %d has %d words", i, n)
		}
		r.D.Uint32()
	}
	if err := r.D.Err(); err != nil {
		t.Fatal(err)
	}

	// Asking again while holding it gets GDD4_UNAVAIL.
	r = gdd("sub")
	must(t, r, nfsv4.OpGetDirDelegation)
	if st := r.D.Uint32(); st != 1 {
		t.Errorf("second GDD status %d; want GDD4_UNAVAIL", st)
	}

	r = gdd("hello.txt")
	expect(t, r, nfsv4.OpGetDirDelegation, nfsv4.ErrNotDir)
}

func TestDelegationMaxAge(t *testing.T) {
	fs := newTestTree()
	fs.DelegatePolicy = func(path string, a *nfsv4.Attrs) nfsv4.Delegation {
		return nfsv4.Delegation{Grant: true, MaxAge: 200 * time.Millisecond}
	}
	srv := &nfsv4.Server{FS: fs.WithDelegator()}
	rc := newRecallClient(t, srv)
	recalled := make(chan bool, 1)
	delegc := make(chan stateID, 1)
	rc.mu.Lock()
	rc.onRecall = func(other, rfh []byte) {
		rc.delegReturn(rfh, <-delegc)
		recalled <- true
	}
	rc.mu.Unlock()
	_, deleg := rc.openDeleg("hello.txt")
	delegc <- deleg
	select {
	case <-recalled:
	case <-time.After(5 * time.Second):
		t.Fatal("delegation with MaxAge not recalled")
	}
}

func TestClientExpiry(t *testing.T) {
	srv := &nfsv4.Server{FS: testfs.New(), LeaseTime: time.Second, ClientExpiry: 2 * time.Second}
	c := newSessionClient(t, srv, false)
	b, slot := c.Seq()
	b.Op(nfsv4.OpPutRootFH)
	if _, err := c.DoSeq(b, slot); err != nil {
		t.Fatal(err)
	}
	// Past the lease time but within ClientExpiry, the client's state
	// is kept (the server is courteous).
	time.Sleep(1500 * time.Millisecond)
	b, slot = c.Seq()
	b.Op(nfsv4.OpPutRootFH)
	if _, err := c.DoSeq(b, slot); err != nil {
		t.Fatalf("after lease expiry: %v", err)
	}
	// Past ClientExpiry, it's gone.
	time.Sleep(3 * time.Second)
	if st := srv.Stats(); st.Clients != 0 {
		t.Errorf("clients = %d", st.Clients)
	}
	b, slot = c.Seq()
	b.Op(nfsv4.OpPutRootFH)
	if _, err := c.DoSeq(b, slot); !errors.Is(err, nfsv4.ErrBadSession) {
		t.Errorf("after client expiry: %v", err)
	}
}

func TestBackchannelRebind(t *testing.T) {
	srv := &nfsv4.Server{FS: testfs.New()}
	c1 := newSessionClient(t, srv, true)
	addr := c1.RemoteAddr()

	// A second connection using the same session has no backchannel
	// until bound, which SEQUENCE reports once the first connection is
	// gone.
	c1.Close()
	time.Sleep(100 * time.Millisecond)
	c2 := dialTestServer(t, addr)
	c2.AdoptSession(c1)
	b, slot := c2.Seq()
	r, err := c2.DoSeq(b, slot)
	if err != nil {
		t.Fatal(err)
	}
	const pathDownSession = 0x200
	if r.SeqFlags&pathDownSession == 0 {
		t.Errorf("SEQUENCE flags %#x lack CB_PATH_DOWN_SESSION", r.SeqFlags)
	}

	var bb nfs4client.Compound
	e := bb.Op(nfsv4.OpBindConnToSession)
	e.FixedOpaque(c2.SessionID[:])
	e.Uint32(3) // CDFC4_FORE_OR_BOTH
	e.Bool(false)
	r, err = c2.Do(&bb)
	if err != nil {
		t.Fatal(err)
	}
	must(t, r, nfsv4.OpBindConnToSession)
	r.D.FixedOpaque(16)
	if dir := r.D.Uint32(); dir != 3 {
		t.Errorf("BIND_CONN_TO_SESSION dir = %d; want CDFS4_BOTH", dir)
	}

	b, slot = c2.Seq()
	r, err = c2.DoSeq(b, slot)
	if err != nil {
		t.Fatal(err)
	}
	if r.SeqFlags&pathDownSession != 0 {
		t.Errorf("SEQUENCE flags %#x after binding", r.SeqFlags)
	}
}

func TestSequenceHighestSlot(t *testing.T) {
	c := newSessionClient(t, &nfsv4.Server{FS: testfs.New()}, false)
	r, err := c.Do(rawSeq(c, 1, 0, false))
	if err != nil {
		t.Fatal(err)
	}
	must(t, r, nfsv4.OpSequence)
	r.D.FixedOpaque(16)
	r.D.Uint32() // seq
	r.D.Uint32() // slot
	highest, target := r.D.Uint32(), r.D.Uint32()
	if want := uint32(len(c.SlotSeq) - 1); highest != want || target != want {
		t.Errorf("highest, target = %d, %d; want %d (not an echo of the client's)", highest, target, want)
	}
}

func TestReadDirFileHandleOnly(t *testing.T) {
	fs := newTestTree()
	c := newSessionClient(t, &nfsv4.Server{FS: fs}, false)
	b, slot := c.Seq()
	lookupPath(b, "sub")
	e := b.Op(nfsv4.OpReadDir)
	e.Uint64(0)
	e.Uint64(0)
	e.Uint32(0)
	e.Uint32(8192)
	encodeBitmap(e, nfsv4.AttrFileHandle)
	r, err := c.DoSeq(b, slot)
	if err != nil {
		t.Fatal(err)
	}
	skipLookups(t, r, 1)
	must(t, r, nfsv4.OpReadDir)
	r.D.Uint64()
	n := 0
	for r.D.Bool() {
		r.D.Uint64()
		name := r.D.String(255)
		skipBitmap(r.D)
		vals := xdr.NewDecoder(r.D.Opaque(200))
		if fh := vals.Opaque(128); string(fh) != string(fs.Handle("/sub/"+name)) {
			t.Errorf("%s: filehandle %x", name, fh)
		}
		n++
	}
	if n != 3 {
		t.Errorf("got %d entries", n)
	}
}
