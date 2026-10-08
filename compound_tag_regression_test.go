// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4_test

import (
	"fmt"
	"testing"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/internal/testfs"
	"github.com/tailscale/nfsv4/internal/xdr"
)

func TestFSConformanceCompoundTag(t *testing.T) {
	c := newTestServer(t, &nfsv4.Server{
		FS: testfs.New(),
	})
	for _, minor := range []uint32{1, 2} {
		for _, tt := range []struct {
			tag  string
			want nfsv4.Status
		}{
			{"\xc0\xc1", nfsv4.ErrInval},
			{"\x80", nfsv4.ErrInval},
			{"\xe2\x82", nfsv4.ErrInval},
			{"\xed\xa0\x80", nfsv4.ErrInval},
			{"\xf4\x90\x80\x80", nfsv4.ErrInval},
			{"", nfsv4.OK},
			{"tag test", nfsv4.OK},
			{"世界\x00/", nfsv4.OK},
			{"\ufffd", nfsv4.OK},
		} {
			t.Run(fmt.Sprintf("%d/%x", minor, tt.tag), func(t *testing.T) {
				var e xdr.Encoder
				e.String(tt.tag)
				e.Uint32(minor)
				e.Uint32(0)
				res, err := c.Call(1, e.Bytes())
				if err != nil {
					t.Fatal(err)
				}
				d := xdr.NewDecoder(res)
				st := nfsv4.Status(d.Uint32())
				tag := d.String(1024)
				nres := d.Uint32()
				if st != tt.want || tag != tt.tag || nres != 0 || d.Err() != nil {
					t.Fatalf("status=%v tag=%x nres=%d err=%v; want %v", st, tag, nres, d.Err(), tt.want)
				}
			})
		}
	}
}
