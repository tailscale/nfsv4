// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4_test

import (
	"fmt"
	"testing"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/internal/nfs4client"
	"github.com/tailscale/nfsv4/internal/testfs"
)

func lifecycleClient(t *testing.T, back bool) *nfs4client.Client {
	t.Helper()
	return newSessionClient(t, &nfsv4.Server{
		FS: testfs.New(),
	}, back)
}

func lifecycleDo(t *testing.T, c *nfs4client.Client, b *nfs4client.Compound) *nfs4client.Result {
	t.Helper()
	r, err := c.Do(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func lifecycleDestroy(t *testing.T, c *nfs4client.Client, sid [16]byte, want nfsv4.Status) {
	t.Helper()
	var b nfs4client.Compound
	b.Op(nfsv4.OpDestroySession).FixedOpaque(sid[:])
	expect(t, lifecycleDo(t, c, &b), nfsv4.OpDestroySession, want)
}

func lifecycleSequence(c *nfs4client.Client, seq uint32) *nfs4client.Compound {
	var b nfs4client.Compound
	e := b.Op(nfsv4.OpSequence)
	e.FixedOpaque(c.SessionID[:])
	e.Uint32(seq)
	e.Uint32(0)
	e.Uint32(0)
	e.Bool(true)
	return &b
}

func lifecycleBind(t *testing.T, c *nfs4client.Client, sid [16]byte, dir uint32, want nfsv4.Status, replyDir uint32) {
	t.Helper()
	var b nfs4client.Compound
	e := b.Op(nfsv4.OpBindConnToSession)
	e.FixedOpaque(sid[:])
	e.Uint32(dir)
	e.Bool(false)
	r := lifecycleDo(t, c, &b)
	expect(t, r, nfsv4.OpBindConnToSession, want)
	if want == nfsv4.OK {
		r.D.FixedOpaque(16)
		if got := r.D.Uint32(); got != replyDir {
			t.Fatalf("binding direction = %d; want %d", got, replyDir)
		}
	}
}

func TestSessionLifecycleUnboundDestroy(t *testing.T) {
	c := lifecycleClient(t, false)
	rogue := dialTestServer(t, c.RemoteAddr())
	rogue.SessionID = c.SessionID
	lifecycleDestroy(t, rogue, c.SessionID, nfsv4.ErrConnNotBoundToSession)
	must(t, lifecycleDo(t, rogue, lifecycleSequence(rogue, 1)), nfsv4.OpSequence)
	lifecycleDestroy(t, rogue, c.SessionID, nfsv4.OK)
	lifecycleDestroy(t, c, c.SessionID, nfsv4.ErrBadSession)
}

func TestSessionLifecycleCurrentDestroyPosition(t *testing.T) {
	c := lifecycleClient(t, false)
	b := lifecycleSequence(c, 1)
	b.Op(nfsv4.OpDestroySession).FixedOpaque(c.SessionID[:])
	b.Op(nfsv4.OpPutRootFH)
	r := lifecycleDo(t, c, b)
	must(t, r, nfsv4.OpSequence)
	r.D.FixedOpaque(36)
	expect(t, r, nfsv4.OpDestroySession, nfsv4.ErrNotOnlyOp)
	// The rejected operation must leave the session available.
	b = lifecycleSequence(c, 2)
	b.Op(nfsv4.OpPutRootFH)
	b.Op(nfsv4.OpDestroySession).FixedOpaque(c.SessionID[:])
	r = lifecycleDo(t, c, b)
	must(t, r, nfsv4.OpSequence)
	r.D.FixedOpaque(36)
	must(t, r, nfsv4.OpPutRootFH)
	must(t, r, nfsv4.OpDestroySession)
}

func TestSessionLifecycleCreateBinding(t *testing.T) {
	c := lifecycleClient(t, false)
	lifecycleDestroy(t, c, c.SessionID, nfsv4.OK)
}

func TestSessionLifecycleOtherSession(t *testing.T) {
	for _, sameClient := range []bool{false, true} {
		t.Run(fmt.Sprintf("same-client-%v", sameClient), func(t *testing.T) {
			c := lifecycleClient(t, false)
			other := dialTestServer(t, c.RemoteAddr())
			if sameClient {
				other.ClientID = c.ClientID
				if err := other.CreateSession(2, 4, false); err != nil {
					t.Fatal(err)
				}
			} else if err := other.Setup(t.Name()+"-other", false); err != nil {
				t.Fatal(err)
			}
			b := lifecycleSequence(c, 1)
			b.Op(nfsv4.OpDestroySession).FixedOpaque(other.SessionID[:])
			r := lifecycleDo(t, c, b)
			must(t, r, nfsv4.OpSequence)
			r.D.FixedOpaque(36)
			expect(t, r, nfsv4.OpDestroySession, nfsv4.ErrConnNotBoundToSession)
			lifecycleBind(t, c, other.SessionID, 1, nfsv4.OK, 1)
			b = lifecycleSequence(c, 2)
			b.Op(nfsv4.OpDestroySession).FixedOpaque(other.SessionID[:])
			b.Op(nfsv4.OpPutRootFH)
			r = lifecycleDo(t, c, b)
			must(t, r, nfsv4.OpSequence)
			r.D.FixedOpaque(36)
			must(t, r, nfsv4.OpDestroySession)
			must(t, r, nfsv4.OpPutRootFH)
			lifecycleDestroy(t, other, other.SessionID, nfsv4.ErrBadSession)
		})
	}
}

func TestSessionLifecycleBindingDirections(t *testing.T) {
	for _, back := range []bool{false, true} {
		for _, dir := range []uint32{1, 2, 3, 7, 0} {
			t.Run(fmt.Sprintf("back-%v-dir-%d", back, dir), func(t *testing.T) {
				c := lifecycleClient(t, back)
				other := dialTestServer(t, c.RemoteAddr())
				want, reply := nfsv4.OK, dir
				switch dir {
				case 0:
					want = nfsv4.ErrInval
				case 2:
					if !back {
						want = nfsv4.ErrInval
					}
				case 3, 7:
					reply = 3
					if !back {
						if dir == 7 {
							want = nfsv4.ErrInval
						} else {
							reply = 1
						}
					}
				}
				lifecycleBind(t, other, c.SessionID, dir, want, reply)
				if want == nfsv4.OK {
					lifecycleBind(t, other, c.SessionID, dir, want, reply)
					lifecycleDestroy(t, other, c.SessionID, nfsv4.OK)
				} else {
					lifecycleDestroy(t, other, c.SessionID, nfsv4.ErrConnNotBoundToSession)
				}
			})
		}
	}
}

func TestSessionLifecycleReplayBinding(t *testing.T) {
	c := lifecycleClient(t, false)
	must(t, lifecycleDo(t, c, lifecycleSequence(c, 1)), nfsv4.OpSequence)
	c.Close()
	reconnected := dialTestServer(t, c.RemoteAddr())
	reconnected.SessionID = c.SessionID
	// A cached SEQUENCE reply must also associate the new connection.
	must(t, lifecycleDo(t, reconnected, lifecycleSequence(reconnected, 1)), nfsv4.OpSequence)
	lifecycleDestroy(t, reconnected, c.SessionID, nfsv4.OK)
}

func TestSessionLifecycleCreateReplayBinding(t *testing.T) {
	for _, back := range []bool{false, true} {
		t.Run(fmt.Sprintf("back-%v", back), func(t *testing.T) {
			c := lifecycleClient(t, back)
			c.Close()
			reconnected := dialTestServer(t, c.RemoteAddr())
			reconnected.ClientID = c.ClientID
			if err := reconnected.CreateSession(1, 8, back); err != nil {
				t.Fatal(err)
			}
			if reconnected.SessionID != c.SessionID {
				t.Fatal("CREATE_SESSION retry returned a different session")
			}
			if back {
				r := lifecycleDo(t, reconnected, lifecycleSequence(reconnected, 1))
				must(t, r, nfsv4.OpSequence)
				r.D.FixedOpaque(32)
				if flags := r.D.Uint32(); flags&0x200 != 0 {
					t.Fatalf("CREATE_SESSION retry did not bind the backchannel: flags %#x", flags)
				}
			}
			lifecycleDestroy(t, reconnected, c.SessionID, nfsv4.OK)
		})
	}
}

func TestSessionLifecycleDestroyOnlyOp(t *testing.T) {
	c := lifecycleClient(t, false)
	var b nfs4client.Compound
	b.Op(nfsv4.OpDestroySession).FixedOpaque(c.SessionID[:])
	b.Op(nfsv4.OpPutRootFH)
	expect(t, lifecycleDo(t, c, &b), nfsv4.OpDestroySession, nfsv4.ErrNotOnlyOp)
	lifecycleDestroy(t, c, c.SessionID, nfsv4.OK)
}

func TestSessionLifecycleBindOnlyOp(t *testing.T) {
	c := lifecycleClient(t, true)
	b := lifecycleSequence(c, 1)
	e := b.Op(nfsv4.OpBindConnToSession)
	e.FixedOpaque(c.SessionID[:])
	e.Uint32(3)
	e.Bool(false)
	r := lifecycleDo(t, c, b)
	must(t, r, nfsv4.OpSequence)
	r.D.FixedOpaque(36)
	expect(t, r, nfsv4.OpBindConnToSession, nfsv4.ErrNotOnlyOp)
}
