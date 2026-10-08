// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4_test

import (
	"bytes"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/internal/nfs4client"
	"github.com/tailscale/nfsv4/internal/testfs"
	"github.com/tailscale/nfsv4/internal/xdr"
)

func replaySession(t *testing.T, request, response, cached uint32) *nfs4client.Client {
	t.Helper()
	c := newTestServer(t, &nfsv4.Server{
		FS: testfs.New(),
	})
	seq, _, err := c.ExchangeID(t.Name(), 1)
	if err != nil {
		t.Fatal(err)
	}
	var b nfs4client.Compound
	e := b.Op(nfsv4.OpCreateSession)
	e.Uint64(c.ClientID)
	e.Uint32(seq)
	e.Uint32(0)
	for _, v := range []uint32{0, request, response, cached, 16, 1, 0, 0, 4096, 4096, 0, 2, 1, 0} {
		e.Uint32(v)
	}
	e.Uint32(0)
	e.Uint32(0)
	r, err := c.Do(&b)
	if err != nil {
		t.Fatal(err)
	}
	must(t, r, nfsv4.OpCreateSession)
	copy(c.SessionID[:], r.D.FixedOpaque(16))
	return c
}

func replayRequest(c *nfs4client.Client, seq uint32, cache bool) *nfs4client.Compound {
	var b nfs4client.Compound
	e := b.Op(nfsv4.OpSequence)
	e.FixedOpaque(c.SessionID[:])
	e.Uint32(seq)
	e.Uint32(0)
	e.Uint32(0)
	e.Bool(cache)
	return &b
}

func replayRawCompound(t *testing.T, c *nfs4client.Client, b *nfs4client.Compound, tag string) []byte {
	t.Helper()
	e := xdr.NewEncoder(nil)
	e.String(tag)
	e.Uint32(c.MinorVersion)
	// These requests contain SEQUENCE and operations with no arguments.
	e.Uint32(uint32(1 + (b.E.Len()-36)/4))
	e.FixedOpaque(b.E.Bytes())
	res, err := c.Call(1, e.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

type replayFS struct {
	nfsv4.FS
	roots   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (fs *replayFS) Root(r *nfsv4.Request) (nfsv4.FileHandle, error) {
	fs.roots.Add(1)
	if fs.entered != nil {
		fs.entered <- struct{}{}
		<-fs.release
	}
	return fs.FS.Root(r)
}

func replayDecode(t *testing.T, reply []byte, tag string, status nfsv4.Status, count int) *xdr.Decoder {
	t.Helper()
	d := xdr.NewDecoder(reply)
	if got := nfsv4.Status(d.Uint32()); got != status {
		t.Fatalf("compound status = %v; want %v", got, status)
	}
	if got := d.String(1024); got != tag {
		t.Fatalf("tag = %q; want %q", got, tag)
	}
	if got := int(d.Uint32()); got != count {
		t.Fatalf("result count = %d; want %d", got, count)
	}
	return d
}

func replayOp(t *testing.T, d *xdr.Decoder, op nfsv4.Op, status nfsv4.Status) {
	t.Helper()
	gotOp, gotStatus := nfsv4.Op(d.Uint32()), nfsv4.Status(d.Uint32())
	if gotOp != op || gotStatus != status || d.Err() != nil {
		t.Fatalf("result = %v/%v (%v); want %v/%v", gotOp, gotStatus, d.Err(), op, status)
	}
}

func replaySequence(t *testing.T, d *xdr.Decoder, c *nfs4client.Client, seq uint32) []byte {
	t.Helper()
	replayOp(t, d, nfsv4.OpSequence, nfsv4.OK)
	body := append([]byte(nil), d.FixedOpaque(36)...)
	s := xdr.NewDecoder(body)
	if !bytes.Equal(s.FixedOpaque(16), c.SessionID[:]) || s.Uint32() != seq || s.Uint32() != 0 {
		t.Fatal("incorrect SEQUENCE identity")
	}
	highest, target := s.Uint32(), s.Uint32()
	s.Uint32()
	if highest != target || s.Err() != nil {
		t.Fatalf("incorrect SEQUENCE metadata: highest=%d target=%d error=%v", highest, target, s.Err())
	}
	return body
}

func replayEnd(t *testing.T, d *xdr.Decoder) {
	t.Helper()
	if d.Err() != nil || d.Remaining() != 0 {
		t.Fatalf("trailing or malformed results: remaining=%d error=%v", d.Remaining(), d.Err())
	}
}

func TestSessionReplayMultiOp(t *testing.T) {
	for _, cache := range []bool{false, true} {
		t.Run(fmt.Sprintf("cache-%v", cache), func(t *testing.T) {
			fs := &replayFS{
				FS: testfs.New(),
			}
			c := newSessionClient(t, &nfsv4.Server{
				FS: fs,
			}, false)
			b := rawSeq(c, 1, 0, cache)
			original := replayRawCompound(t, c, b, "original-tag")
			d := replayDecode(t, original, "original-tag", nfsv4.OK, 3)
			seqBody := replaySequence(t, d, c, 1)
			replayOp(t, d, nfsv4.OpPutRootFH, nfsv4.OK)
			replayOp(t, d, nfsv4.OpGetFH, nfsv4.OK)
			d.Opaque(128)
			replayEnd(t, d)
			for range 2 {
				reply := replayRawCompound(t, c, b, "retry-tag")
				if cache {
					if !bytes.Equal(reply, original) {
						t.Fatal("cached replay changed")
					}
				} else {
					d := replayDecode(t, reply, "original-tag", nfsv4.ErrRetryUncachedRep, 2)
					if !bytes.Equal(replaySequence(t, d, c, 1), seqBody) {
						t.Fatal("uncached replay changed SEQUENCE metadata")
					}
					replayOp(t, d, nfsv4.OpPutRootFH, nfsv4.ErrRetryUncachedRep)
					replayEnd(t, d)
				}
			}
			if fs.roots.Load() != 1 {
				t.Fatalf("replay repeated FS calls: %d", fs.roots.Load())
			}
			next := rawSeq(c, 2, 0, !cache)
			d = replayDecode(t, replayRawCompound(t, c, next, "next"), "next", nfsv4.OK, 3)
			replaySequence(t, d, c, 2)
			if fs.roots.Load() != 2 {
				t.Fatal("next sequence did not execute")
			}
			r, err := c.Do(b)
			if err != nil {
				t.Fatal(err)
			}
			expect(t, r, nfsv4.OpSequence, nfsv4.ErrSeqMisordered)
		})
	}
}

func TestSessionReplaySmallCacheTransition(t *testing.T) {
	c := replaySession(t, 4096, 4096, 10)
	r, err := c.Do(replayRequest(c, 1, true))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != nfsv4.ErrRepTooBigToCache || r.NumRes != 1 {
		t.Fatalf("small cache result = %v/%d", r.Status, r.NumRes)
	}
	expect(t, r, nfsv4.OpSequence, nfsv4.ErrRepTooBigToCache)
	b := replayRequest(c, 1, false)
	original := replayRawCompound(t, c, b, "singleton")
	d := replayDecode(t, original, "singleton", nfsv4.OK, 1)
	replaySequence(t, d, c, 1)
	replayEnd(t, d)
	for _, cache := range []bool{false, true} {
		retry := replayRequest(c, 1, cache)
		if reply := replayRawCompound(t, c, retry, "retry"); !bytes.Equal(reply, original) {
			t.Fatal("mandatory singleton replay changed")
		}
	}
	r, err = c.Do(replayRequest(c, 2, false))
	if err != nil {
		t.Fatal(err)
	}
	must(t, r, nfsv4.OpSequence)
}

func TestSessionReplayInFlight(t *testing.T) {
	for _, cache := range []bool{false, true} {
		t.Run(fmt.Sprintf("cache-%v", cache), func(t *testing.T) {
			fs := &replayFS{
				FS:      testfs.New(),
				entered: make(chan struct{}, 1),
				release: make(chan struct{}),
			}
			defer close(fs.release)
			c := newSessionClient(t, &nfsv4.Server{
				FS: fs,
			}, false)
			b := rawSeq(c, 1, 0, cache)
			type response struct {
				r   *nfs4client.Result
				err error
			}
			done := make(chan response, 1)
			go func() {
				r, err := c.Do(b)
				done <- response{
					r:   r,
					err: err,
				}
			}()
			select {
			case <-fs.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("original request did not enter FS")
			}
			for _, seq := range []uint32{1, 2} {
				r, err := c.Do(rawSeq(c, seq, 0, cache))
				if err != nil {
					t.Fatal(err)
				}
				if r.Status != nfsv4.ErrDelay || r.NumRes != 1 {
					t.Fatalf("in-flight result = %v/%d", r.Status, r.NumRes)
				}
				expect(t, r, nfsv4.OpSequence, nfsv4.ErrDelay)
			}
			fs.release <- struct{}{}
			select {
			case got := <-done:
				if got.err != nil || got.r.Status != nfsv4.OK || got.r.NumRes != 3 {
					t.Fatalf("original result = %+v", got)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("original request did not finish")
			}
			r, err := c.Do(b)
			if err != nil {
				t.Fatal(err)
			}
			must(t, r, nfsv4.OpSequence)
			r.D.FixedOpaque(36)
			want, count := nfsv4.OK, 3
			if !cache {
				want, count = nfsv4.ErrRetryUncachedRep, 2
			}
			if r.Status != want || r.NumRes != count || fs.roots.Load() != 1 {
				t.Fatalf("replay = %v/%d; FS calls=%d", r.Status, r.NumRes, fs.roots.Load())
			}
			expect(t, r, nfsv4.OpPutRootFH, want)
			r, err = c.Do(replayRequest(c, 2, false))
			if err != nil {
				t.Fatal(err)
			}
			must(t, r, nfsv4.OpSequence)
		})
	}
}

func TestSessionReplayResponseBoundary(t *testing.T) {
	for _, cache := range []bool{false, true} {
		t.Run(fmt.Sprintf("cache-%v", cache), func(t *testing.T) {
			c := replaySession(t, 4096, 92, 92)
			b := replayRequest(c, 1, cache)
			b.Op(nfsv4.OpPutRootFH)
			original := replayRawCompound(t, c, b, "test")
			d := replayDecode(t, original, "test", nfsv4.OK, 2)
			seqBody := replaySequence(t, d, c, 1)
			replayOp(t, d, nfsv4.OpPutRootFH, nfsv4.OK)
			replayEnd(t, d)
			if len(original)+24 != 92 {
				t.Fatalf("original RPC size = %d; want 92", len(original)+24)
			}
			// The retry tag does not fit, but the stored reply does.
			reply := replayRawCompound(t, c, b, "larger-retry-tag")
			status := nfsv4.OK
			if !cache {
				status = nfsv4.ErrRetryUncachedRep
			}
			d = replayDecode(t, reply, "test", status, 2)
			if !bytes.Equal(replaySequence(t, d, c, 1), seqBody) {
				t.Fatal("boundary replay changed SEQUENCE metadata")
			}
			replayOp(t, d, nfsv4.OpPutRootFH, status)
			replayEnd(t, d)
			if len(reply)+24 != 92 {
				t.Fatalf("replay RPC size = %d; want 92", len(reply)+24)
			}
		})
	}
}

func TestSessionReplayIllegalSecondOp(t *testing.T) {
	for _, tc := range []struct {
		name       string
		op, result nfsv4.Op
		status     nfsv4.Status
	}{
		{"unknown", nfsv4.Op(9999), nfsv4.OpIllegal, nfsv4.ErrOpIllegal},
		{"minor-version", nfsv4.OpAllocate, nfsv4.OpIllegal, nfsv4.ErrOpIllegal},
		{"v4.0-only", nfsv4.OpRenew, nfsv4.OpRenew, nfsv4.ErrNotSupp},
		{"sequence-position", nfsv4.OpSequence, nfsv4.OpSequence, nfsv4.ErrSequencePos},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := replaySession(t, 4096, 4096, 0)
			b := replayRequest(c, 1, false)
			b.Op(tc.op)
			for range 2 {
				d := replayDecode(t, replayRawCompound(t, c, b, "test"), "test", tc.status, 2)
				replaySequence(t, d, c, 1)
				replayOp(t, d, tc.result, tc.status)
				replayEnd(t, d)
			}
		})
	}
}

func TestSessionReplayMetadataAfterCallbackLoss(t *testing.T) {
	for _, cache := range []bool{false, true} {
		t.Run(fmt.Sprintf("cache-%v", cache), func(t *testing.T) {
			fs := &replayFS{
				FS: testfs.New(),
			}
			c := newSessionClient(t, &nfsv4.Server{
				FS: fs,
			}, true)
			b := rawSeq(c, 1, 0, cache)
			original := replayRawCompound(t, c, b, "metadata")
			d := replayDecode(t, original, "metadata", nfsv4.OK, 3)
			seqBody := replaySequence(t, d, c, 1)
			if flags := xdr.NewDecoder(seqBody[32:]).Uint32(); flags != 0 {
				t.Fatalf("initial SEQUENCE flags = %#x; want 0", flags)
			}
			c.Close()
			reconnected := dialTestServer(t, c.RemoteAddr())
			reconnected.SessionID = c.SessionID
			deadline := time.Now().Add(5 * time.Second)
			var current []byte
			for seq := uint32(1); ; seq++ {
				var probe nfs4client.Compound
				e := probe.Op(nfsv4.OpSequence)
				e.FixedOpaque(c.SessionID[:])
				e.Uint32(seq)
				e.Uint32(1)
				e.Uint32(1)
				e.Bool(false)
				r, err := reconnected.Do(&probe)
				if err != nil {
					t.Fatal(err)
				}
				must(t, r, nfsv4.OpSequence)
				current = append([]byte(nil), r.D.FixedOpaque(36)...)
				if flags := xdr.NewDecoder(current[32:]).Uint32(); flags&0x201 == 0x201 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("callback loss did not change current SEQUENCE flags")
				}
				time.Sleep(time.Millisecond)
			}
			reply := replayRawCompound(t, reconnected, b, "retry")
			status, count := nfsv4.OK, 3
			if !cache {
				status, count = nfsv4.ErrRetryUncachedRep, 2
			}
			d = replayDecode(t, reply, "metadata", status, count)
			if !bytes.Equal(replaySequence(t, d, c, 1), seqBody) {
				t.Fatal("replay recomputed the original SEQUENCE metadata")
			}
			replayOp(t, d, nfsv4.OpPutRootFH, status)
			if fs.roots.Load() != 1 {
				t.Fatal("metadata replay repeated FS calls")
			}
			// A new sequence reports current flags, not the cached flags.
			next := replayRequest(reconnected, 2, false)
			d = replayDecode(t, replayRawCompound(t, reconnected, next, "next"), "next", nfsv4.OK, 1)
			if flags := xdr.NewDecoder(replaySequence(t, d, c, 2)[32:]).Uint32(); flags&0x201 != 0x201 {
				t.Fatalf("new sequence lost current status flags: %#x", flags)
			}
			replayEnd(t, d)
		})
	}
}

func TestSessionReplaySingleton(t *testing.T) {
	c := replaySession(t, 4096, 4096, 0)
	b := replayRequest(c, 1, false)
	var previous []byte
	for i := 0; i < 2; i++ {
		r, err := c.Do(b)
		if err != nil {
			t.Fatal(err)
		}
		must(t, r, nfsv4.OpSequence)
		body := r.D.FixedOpaque(36)
		if i == 1 && !bytes.Equal(body, previous) {
			t.Fatal("singleton replay changed")
		}
		previous = append([]byte(nil), body...)
	}
}
