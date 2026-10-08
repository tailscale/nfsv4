// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4_test

import (
	"fmt"
	"testing"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/internal/nfs4client"
	"github.com/tailscale/nfsv4/internal/oncrpc"
	"github.com/tailscale/nfsv4/internal/testfs"
	"github.com/tailscale/nfsv4/internal/xdr"
)

func limitsCreateSession(t *testing.T, c *nfs4client.Client, seq, flags, request, response, cached uint32) *nfs4client.Result {
	t.Helper()
	var b nfs4client.Compound
	e := b.Op(nfsv4.OpCreateSession)
	e.Uint64(c.ClientID)
	e.Uint32(seq)
	e.Uint32(flags)
	for _, v := range []uint32{0, request, response, cached, 16, 1, 0, 0, 4096, 4096, 0, 2, 1, 0} {
		e.Uint32(v)
	}
	e.Uint32(0)
	e.Uint32(0)
	r, err := c.Do(&b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func limitsClient(t *testing.T) (*nfs4client.Client, uint32) {
	t.Helper()
	c := newTestServer(t, &nfsv4.Server{
		FS: testfs.New(),
	})
	seq, _, err := c.ExchangeID(t.Name(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return c, seq
}

func limitsSession(t *testing.T, request, response, cached uint32) *nfs4client.Client {
	t.Helper()
	c, seq := limitsClient(t)
	r := limitsCreateSession(t, c, seq, 0, request, response, cached)
	must(t, r, nfsv4.OpCreateSession)
	copy(c.SessionID[:], r.D.FixedOpaque(16))
	return c
}

func limitsSequence(c *nfs4client.Client, seq uint32, cache bool) *nfs4client.Compound {
	var b nfs4client.Compound
	e := b.Op(nfsv4.OpSequence)
	e.FixedOpaque(c.SessionID[:])
	e.Uint32(seq)
	e.Uint32(0)
	e.Uint32(0)
	e.Bool(cache)
	return &b
}

func TestSessionLimitsCreateFlags(t *testing.T) {
	for bit := uint(3); bit < 32; bit++ {
		t.Run(fmt.Sprint(bit), func(t *testing.T) {
			c, seq := limitsClient(t)
			r := limitsCreateSession(t, c, seq, 1<<bit, 4096, 4096, 4096)
			expect(t, r, nfsv4.OpCreateSession, nfsv4.ErrInval)
			// A rejected request must not consume the sequence ID.
			r = limitsCreateSession(t, c, seq, 7, 4096, 4096, 4096)
			must(t, r, nfsv4.OpCreateSession)
			r.D.FixedOpaque(16)
			r.D.Uint32()
			if flags := r.D.Uint32(); flags&5 != 0 {
				t.Fatalf("unsupported PERSIST or RDMA granted: %#x", flags)
			}
		})
	}
}

func TestSessionLimitsCreateMinimum(t *testing.T) {
	for _, tc := range []struct {
		name              string
		request, response uint32
		want              nfsv4.Status
	}{
		{"request-zero", 0, 4096, nfsv4.ErrTooSmall},
		{"request-below-minimum", 87, 4096, nfsv4.ErrTooSmall},
		{"response-zero", 4096, 0, nfsv4.ErrTooSmall},
		{"response-below-minimum", 4096, 79, nfsv4.ErrTooSmall},
		{"minimum", 88, 80, nfsv4.OK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, seq := limitsClient(t)
			r := limitsCreateSession(t, c, seq, 0, tc.request, tc.response, 0)
			expect(t, r, nfsv4.OpCreateSession, tc.want)
			if tc.want != nfsv4.OK {
				r = limitsCreateSession(t, c, seq, 0, 4096, 4096, 0)
				must(t, r, nfsv4.OpCreateSession)
			}
		})
	}
}

func TestSessionLimitsRequestRPCSize(t *testing.T) {
	// Match the test client's RPC credential, without a record marker.
	cred := oncrpc.AuthSysCred{
		MachineName: "testclient",
		UID:         1000,
		GID:         1000,
	}
	header := xdr.NewEncoder(nil)
	oncrpc.EncodeCall(header, oncrpc.CallHeader{
		Prog: 100003,
		Vers: 4,
		Proc: 1,
		Cred: oncrpc.OpaqueAuth{
			Flavor: oncrpc.AuthSys,
			Body:   cred.Encode(),
		},
	})
	// The COMPOUND has a four-byte tag and a 36-byte SEQUENCE operation.
	size := uint32(header.Len() + 16 + 36)
	for _, delta := range []uint32{0, 1, 4} {
		t.Run(fmt.Sprint(delta), func(t *testing.T) {
			c := limitsSession(t, size-delta, 4096, 4096)
			r, err := c.Do(limitsSequence(c, 1, false))
			if err != nil {
				t.Fatal(err)
			}
			want := nfsv4.OK
			if delta != 0 {
				want = nfsv4.ErrReqTooBig
			}
			expect(t, r, nfsv4.OpSequence, want)
			if delta != 0 {
				// An empty tag saves four bytes. Retry the same sequence ID.
				res := limitsRawCompound(t, c, limitsSequence(c, 1, false), "")
				if st := nfsv4.Status(xdr.NewDecoder(res).Uint32()); st != nfsv4.OK {
					t.Fatalf("smaller request with the same sequence ID: %v", st)
				}
			}
		})
	}
}

func limitsRawCompound(t *testing.T, c *nfs4client.Client, b *nfs4client.Compound, tag string) []byte {
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

func TestSessionLimitsResponseRPCSize(t *testing.T) {
	// RPC reply (24), COMPOUND header with tag (16), SEQUENCE (44),
	// and PUTROOTFH (8) require 92 bytes, without a record marker.
	for _, cached := range []bool{false, true} {
		for _, limit := range []uint32{91, 92} {
			t.Run(fmt.Sprintf("cache-%v-limit-%d", cached, limit), func(t *testing.T) {
				response, cacheLimit := uint32(4096), uint32(4096)
				if cached {
					cacheLimit = limit
				} else {
					response = limit
				}
				c := limitsSession(t, 4096, response, cacheLimit)
				b := limitsSequence(c, 1, cached)
				b.Op(nfsv4.OpPutRootFH)
				res := limitsRawCompound(t, c, b, "test")
				st := nfsv4.Status(xdr.NewDecoder(res).Uint32())
				if !cached && len(res)+24 > int(limit) {
					t.Fatalf("RPC reply size %d exceeds limit %d", len(res)+24, limit)
				}
				want := nfsv4.OK
				if limit == 91 {
					want = nfsv4.ErrRepTooBig
					if cached {
						want = nfsv4.ErrRepTooBigToCache
					}
				}
				if st != want {
					t.Fatalf("status %v, want %v", st, want)
				}
				if limit == 91 {
					// Size errors on SEQUENCE must not consume its sequence ID.
					r, err := c.Do(limitsSequence(c, 1, cached))
					if err != nil {
						t.Fatal(err)
					}
					must(t, r, nfsv4.OpSequence)
				}
			})
		}
	}
}

func TestSessionLimitsResponseErrorSpace(t *testing.T) {
	c := limitsSession(t, 4096, 100, 4096)
	b := limitsSequence(c, 1, false)
	for range 3 {
		b.Op(nfsv4.OpPutRootFH)
	}
	res := limitsRawCompound(t, c, b, "test")
	if st := nfsv4.Status(xdr.NewDecoder(res).Uint32()); st != nfsv4.ErrRepTooBig {
		t.Fatalf("status %v, want REP_TOO_BIG", st)
	}
	if len(res)+24 > 100 {
		t.Fatalf("error reply size %d exceeds limit 100", len(res)+24)
	}
}
