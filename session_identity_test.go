// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/tailscale/nfsv4/internal/oncrpc"
	"github.com/tailscale/nfsv4/internal/xdr"
)

func identityCompound() *compound {
	s := &Server{
		LeaseTime:    90 * time.Second,
		ClientExpiry: time.Hour,
		MaxIO:        1 << 20,
		epoch:        1,
	}
	return &compound{
		s: s,
		c: &conn{
			srv: s,
		},
		m:     newStateManager(s),
		minor: 1,
	}
}

func identityCred(uid uint32) Cred {
	return Cred{
		Flavor:      oncrpc.AuthSys,
		UID:         uid,
		GID:         37,
		GIDs:        []uint32{37, 42},
		MachineName: "identity-test",
	}
}

func identityExchange(cp *compound, cred Cred, verifier byte, flags uint32) (uint64, uint32, Status) {
	cp.req.Cred = cred
	var a, r xdr.Encoder
	a.FixedOpaque([]byte{verifier, 0, 0, 0, 0, 0, 0, 0})
	a.String("identity-owner")
	a.Uint32(flags)
	a.Uint32(sp4None)
	a.Uint32(0)
	st := cp.opExchangeID(xdr.NewDecoder(a.Bytes()), &r)
	if st != OK {
		return 0, 0, st
	}
	d := xdr.NewDecoder(r.Bytes())
	id := d.Uint64()
	d.Uint32()
	return id, d.Uint32(), st
}

func identityCreate(cp *compound, cred Cred, id uint64, seq uint32) ([]byte, Status) {
	cp.req.Cred = cred
	var a, r xdr.Encoder
	a.Uint64(id)
	a.Uint32(seq)
	a.Uint32(0)
	ca := channelAttrs{
		maxRequestSize:    8192,
		maxResponseSize:   8192,
		maxResponseCached: 8192,
		maxOperations:     128,
		maxRequests:       8,
	}
	encodeChannelAttrs(&a, ca)
	encodeChannelAttrs(&a, ca)
	a.Uint32(123)
	a.Uint32(1)
	a.Uint32(oncrpc.AuthNone)
	st := cp.opCreateSession(xdr.NewDecoder(a.Bytes()), &r)
	return r.Bytes(), st
}

func requireIdentityStatus(t *testing.T, got, want Status) {
	t.Helper()
	if got != want {
		t.Fatalf("status = %v; want %v", got, want)
	}
}

func TestIdentityExchangeFlags(t *testing.T) {
	valid := uint32(exchgidSuppMovedRefer | exchgidSuppMovedMigr | exchgidBindPrincStateID | exchgidMaskPNFS | exchgidUpdConfirmedRecA)
	for bit := range 32 {
		flag := uint32(1) << bit
		if flag&valid != 0 {
			continue
		}
		t.Run(fmt.Sprintf("invalid-%08x", flag), func(t *testing.T) {
			cp := identityCompound()
			_, _, st := identityExchange(cp, identityCred(1000), 1, flag)
			requireIdentityStatus(t, st, ErrInval)
			if len(cp.m.clients) != 0 || len(cp.m.byOwner) != 0 {
				t.Fatal("invalid flags created identity state")
			}
		})
	}
	for _, flags := range []uint32{0, 0x101, valid &^ exchgidUpdConfirmedRecA} {
		cp := identityCompound()
		_, _, st := identityExchange(cp, identityCred(1000), 1, flags)
		requireIdentityStatus(t, st, OK)
	}
}

// TestIdentityExchangeAlgorithm covers RFC 8881 section 18.35.4 cases 1-9.
func TestIdentityExchangeAlgorithm(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		for _, update := range []bool{false, true} {
			for _, sameVerifier := range []bool{false, true} {
				for _, sameCred := range []bool{false, true} {
					name := fmt.Sprintf("confirmed=%t/update=%t/verifier=%t/cred=%t", confirmed, update, sameVerifier, sameCred)
					t.Run(name, func(t *testing.T) {
						cp := identityCompound()
						cred := identityCred(1000)
						oldID, _, st := identityExchange(cp, cred, 1, 0)
						requireIdentityStatus(t, st, OK)
						if confirmed {
							_, st = identityCreate(cp, cred, oldID, 1)
							requireIdentityStatus(t, st, OK)
							for _, sess := range cp.m.clients[oldID].sessions {
								cp.m.destroySessionLocked(sess)
							}
						}
						verifier := byte(1)
						if !sameVerifier {
							verifier = 2
						}
						if !sameCred {
							cred = identityCred(1111)
						}
						var flags uint32
						if update {
							flags = exchgidUpdConfirmedRecA
						}
						want := OK
						if update {
							switch {
							case !confirmed:
								want = ErrNoEnt
							case !sameVerifier:
								want = ErrNotSame
							case !sameCred:
								want = ErrPerm
							}
						}
						id, rflags, st := identityExchange(cp, cred, verifier, flags)
						requireIdentityStatus(t, st, want)
						if want != OK {
							if cp.m.clients[oldID] == nil {
								t.Fatal("failed update removed old record")
							}
							return
						}
						reuse := confirmed && sameCred && (update || sameVerifier)
						if (id == oldID) != reuse {
							t.Fatalf("id = %x, old = %x; reuse = %t", id, oldID, reuse)
						}
						if (rflags&exchgidConfirmedR != 0) != reuse {
							t.Fatalf("confirmed flag = %x; reuse = %t", rflags, reuse)
						}
						if !confirmed || !sameCred {
							_, st = identityCreate(cp, identityCred(1000), oldID, 1)
							requireIdentityStatus(t, st, ErrStaleClientID)
						}
					})
				}
			}
		}
	}
}

func TestIdentityMissingUpdate(t *testing.T) {
	cp := identityCompound()
	_, _, st := identityExchange(cp, identityCred(1000), 1, exchgidUpdConfirmedRecA)
	requireIdentityStatus(t, st, ErrNoEnt)
	if len(cp.m.clients) != 0 || len(cp.m.byOwner) != 0 {
		t.Fatal("missing update created client state")
	}
}

func TestIdentityFileStateCollision(t *testing.T) {
	for _, kind := range []string{"open", "lock", "delegation", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			cp := identityCompound()
			cred := identityCred(1000)
			id, _, st := identityExchange(cp, cred, 1, 0)
			requireIdentityStatus(t, st, OK)
			_, st = identityCreate(cp, cred, id, 1)
			requireIdentityStatus(t, st, OK)
			cl := cp.m.clients[id]
			for _, sess := range cl.sessions {
				cp.m.destroySessionLocked(sess)
			}
			switch kind {
			case "open":
				cl.opens[openKey{}] = &openState{}
			case "lock":
				cl.locks[lockKey{}] = &lockState{}
			case "delegation":
				cl.delegs[stateOther{}] = &delegState{}
			case "revoked":
				cl.revoked[stateOther{}] = &delegState{}
			}
			_, _, st = identityExchange(cp, identityCred(1111), 1, 0)
			requireIdentityStatus(t, st, ErrClidInUse)
			if cp.m.clients[id] != cl {
				t.Fatal("collision removed file state")
			}
		})
	}
}

func TestIdentityCreateConfirmationAndReplay(t *testing.T) {
	cp := identityCompound()
	cred := identityCred(1000)
	id, _, st := identityExchange(cp, cred, 1, 0)
	requireIdentityStatus(t, st, OK)
	for range 2 {
		_, st = identityCreate(cp, identityCred(1111), id, 1)
		requireIdentityStatus(t, st, ErrClidInUse)
	}
	if cp.m.clients[id].confirmed || len(cp.m.sessions) != 0 || cp.m.clients[id].csSeq != 1 {
		t.Fatal("unauthorized confirmation changed client state")
	}
	reply, st := identityCreate(cp, cred, id, 1)
	requireIdentityStatus(t, st, OK)
	// SP4_NONE does not restrict credentials after confirmation (CSESS10).
	replay, st := identityCreate(cp, identityCred(1111), id, 1)
	requireIdentityStatus(t, st, OK)
	if !bytes.Equal(reply, replay) {
		t.Fatal("CREATE_SESSION replay changed")
	}
	_, st = identityCreate(cp, identityCred(1111), id, 2)
	requireIdentityStatus(t, st, OK)
}

func TestIdentityCollisionLeaseAndRestart(t *testing.T) {
	for _, expired := range []bool{false, true} {
		for _, sameVerifier := range []bool{false, true} {
			t.Run(fmt.Sprintf("expired=%t/verifier=%t", expired, sameVerifier), func(t *testing.T) {
				cp := identityCompound()
				id, _, st := identityExchange(cp, identityCred(1000), 1, 0)
				requireIdentityStatus(t, st, OK)
				_, st = identityCreate(cp, identityCred(1000), id, 1)
				requireIdentityStatus(t, st, OK)
				if expired {
					cp.m.clients[id].lastRenew = time.Now().Add(-cp.s.LeaseTime - time.Second)
				}
				verifier := byte(1)
				if !sameVerifier {
					verifier = 2
				}
				newID, _, st := identityExchange(cp, identityCred(1111), verifier, 0)
				if !expired {
					requireIdentityStatus(t, st, ErrClidInUse)
					if cp.m.clients[id] == nil || len(cp.m.sessions) != 1 {
						t.Fatal("collision removed live state")
					}
				} else {
					requireIdentityStatus(t, st, OK)
					if newID == id || cp.m.clients[id] != nil || len(cp.m.sessions) != 0 {
						t.Fatal("collision retained expired state")
					}
				}
			})
		}
	}
	t.Run("restart-delays-old-state-removal", func(t *testing.T) {
		cp := identityCompound()
		cred := identityCred(1000)
		id, _, st := identityExchange(cp, cred, 1, 0)
		requireIdentityStatus(t, st, OK)
		_, st = identityCreate(cp, cred, id, 1)
		requireIdentityStatus(t, st, OK)
		newID, _, st := identityExchange(cp, cred, 2, 0)
		requireIdentityStatus(t, st, OK)
		if id == newID || cp.m.clients[id] == nil || len(cp.m.sessions) != 1 {
			t.Fatal("restart removed state before confirmation")
		}
		_, st = identityCreate(cp, cred, newID, 1)
		requireIdentityStatus(t, st, OK)
		if cp.m.clients[id] != nil || len(cp.m.sessions) != 1 {
			t.Fatal("confirmation retained old state")
		}
	})
}

func TestIdentityConfirmedRetryPreservesRecord(t *testing.T) {
	cp := identityCompound()
	cred := identityCred(1000)
	id, _, st := identityExchange(cp, cred, 1, 0)
	requireIdentityStatus(t, st, OK)
	_, st = identityCreate(cp, cred, id, 1)
	requireIdentityStatus(t, st, OK)
	cl := cp.m.clients[id]
	cl.info.ImplName = "original"
	lastRenew := time.Now().Add(-time.Second)
	cl.lastRenew = lastRenew
	_, _, st = identityExchange(cp, cred, 1, 0)
	requireIdentityStatus(t, st, OK)
	if cl.info.ImplName != "original" || cl.lastRenew != lastRenew {
		t.Fatal("non-update retry changed confirmed record")
	}
}

func TestIdentityCredentialSnapshot(t *testing.T) {
	cp := identityCompound()
	cred := identityCred(1000)
	id, _, st := identityExchange(cp, cred, 1, 0)
	requireIdentityStatus(t, st, OK)
	cred.GIDs[1]++
	_, st = identityCreate(cp, cred, id, 1)
	requireIdentityStatus(t, st, ErrClidInUse)
	_, st = identityCreate(cp, identityCred(1000), id, 1)
	requireIdentityStatus(t, st, OK)
}

func TestIdentityCredentialComponents(t *testing.T) {
	for _, component := range []string{"uid", "gid", "groups", "flavor", "machine"} {
		t.Run(component, func(t *testing.T) {
			cp := identityCompound()
			cred := identityCred(1000)
			id, _, st := identityExchange(cp, cred, 1, 0)
			requireIdentityStatus(t, st, OK)
			other := identityCred(1000)
			want := ErrClidInUse
			switch component {
			case "uid":
				other.UID++
			case "gid":
				other.GID++
			case "groups":
				other.GIDs[1]++
			case "flavor":
				other.Flavor = oncrpc.AuthNone
			case "machine":
				other.MachineName = "new-connection"
				want = OK
			}
			_, st = identityCreate(cp, other, id, 1)
			requireIdentityStatus(t, st, want)
		})
	}
	t.Run("auth-none", func(t *testing.T) {
		cp := identityCompound()
		cred, ok := parseCred(oncrpc.OpaqueAuth{})
		if !ok {
			t.Fatal("AUTH_NONE rejected")
		}
		id, _, st := identityExchange(cp, cred, 1, 0x101)
		requireIdentityStatus(t, st, OK)
		_, st = identityCreate(cp, cred, id, 1)
		requireIdentityStatus(t, st, OK)
	})
}
