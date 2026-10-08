// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4

import (
	"fmt"
	"strings"
	"testing"

	"github.com/tailscale/nfsv4/internal/xdr"
)

// nameConformanceFS records the bytes sent to Lookup.
type nameConformanceFS struct {
	FS
	names []string
}

func (fs *nameConformanceFS) Lookup(r *Request, dir FileHandle, name string) (FileHandle, *Attrs, error) {
	fs.names = append(fs.names, name)
	return nil, nil, ErrNoEnt
}

func TestNameConformance(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, operation := range []struct {
			name  string
			op    func(*compound, *xdr.Decoder, *xdr.Encoder) Status
			open  bool
			claim uint32
		}{
			{"LOOKUP", (*compound).opLookup, false, 0},
			{"SECINFO", (*compound).opSecInfo, false, 0},
			{"OPEN_NULL", (*compound).opOpen, true, claimNull},
			{"OPEN_DELEGATE_CUR", (*compound).opOpen, true, claimDelegateCur},
			{"OPEN_DELEGATE_PREV", (*compound).opOpen, true, claimDelegatePrev},
		} {
			t.Run(fmt.Sprintf("v4.%d/%s", minor, operation.name), func(t *testing.T) {
				fs := &nameConformanceFS{}
				s := &Server{
					FS: fs,
				}
				s.init()
				t.Cleanup(func() { s.Close() })
				for _, tt := range []struct {
					label string
					name  string
					want  Status
					cut   int
				}{
					{"empty", "", ErrInval, 0},
					{"dot", ".", ErrBadName, 0},
					{"dotdot", "..", ErrBadName, 0},
					{"slash", "a/b", ErrBadChar, 0},
					{"nul", "a\x00b", ErrBadChar, 0},
					{"plain", "file", ErrNoEnt, 0},
					{"non_utf8", "\xff\xfe\x80", ErrNoEnt, 0},
					{"255_bytes", strings.Repeat("a", 255), ErrNoEnt, 0},
					{"256_bytes", strings.Repeat("a", 256), ErrNameTooLong, 0},
					{"1024_bytes", strings.Repeat("a", 1024), ErrNameTooLong, 0},
					{"1025_bytes", strings.Repeat("a", 1025), ErrNameTooLong, 0},
					{"AD_LOOK4", strings.Repeat("abc", 512), ErrNameTooLong, 0},
					{"utf8_byte_limit", strings.Repeat("界", 86), ErrNameTooLong, 0},
					{"truncated_count", "", ErrBadXDR, 1},
					{"truncated_data", "abcd", ErrBadXDR, 1},
					{"truncated_padding", "abc", ErrBadXDR, 1},
					{"truncated_long_data", strings.Repeat("abc", 512), ErrBadXDR, 1},
					{"truncated_long_padding", strings.Repeat("a", 1025), ErrBadXDR, 1},
				} {
					t.Run(tt.label, func(t *testing.T) {
						var e xdr.Encoder
						if operation.open {
							e.Uint32(0) // seqid
							e.Uint32(shareAccessRead)
							e.Uint32(0) // share deny
							e.Uint64(0) // client ID
							e.Opaque([]byte("owner"))
							e.Uint32(opentypeNoCreate)
							e.Uint32(operation.claim)
							if operation.claim == claimDelegateCur {
								encodeStateID(&e, anonStateID)
							}
						}
						e.String(tt.name)
						e.Truncate(e.Len() - tt.cut)
						d := xdr.NewDecoder(e.Bytes())
						cp := &compound{
							s:     s,
							m:     s.state,
							minor: minor,
							curFH: FileHandle("root"),
						}
						before := len(fs.names)
						var reply xdr.Encoder
						got := operation.op(cp, d, &reply)
						want := tt.want
						if operation.open && operation.claim == claimDelegatePrev && tt.cut == 0 {
							// CLAIM_DELEGATE_PREV is not supported.
							want = ErrNotSupp
						}
						if got != want {
							t.Fatalf("got %v; want %v", got, want)
						}
						if tt.cut == 0 && (d.Err() != nil || d.Remaining() != 0) {
							t.Fatalf("valid XDR not consumed: err=%v remaining=%d", d.Err(), d.Remaining())
						}
						if tt.cut != 0 && d.Err() == nil {
							t.Fatal("truncated XDR did not set a decoder error")
						}
						if want == ErrNoEnt {
							if len(fs.names) != before+1 || fs.names[before] != tt.name {
								t.Fatalf("Lookup did not receive the original name bytes: %q", fs.names[before:])
							}
						} else if len(fs.names) != before {
							t.Fatal("Lookup called with an invalid or unsupported name")
						}
					})
				}
			})
		}
	}
}
