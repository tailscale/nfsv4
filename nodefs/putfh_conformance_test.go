// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nodefs

import (
	"errors"
	"testing"

	"github.com/tailscale/nfsv4"
)

func TestFSConformanceHandleErrors(t *testing.T) {
	fs := New(dirT{
		tnode: newTree("file").root,
	}, nil)
	for _, h := range []nfsv4.FileHandle{
		[]byte("abc"),
		{fmtRoot, 0},
		{fmtPath},
		{fmtPath, 4, 'a'},
		{fmtTable},
		{fmtTable, 0, 0, 0},
	} {
		if _, err := fs.GetAttr(req, h, nfsv4.AttrMask{}); !errors.Is(err, nfsv4.ErrBadHandle) {
			t.Errorf("GetAttr(%x) = %v; want BADHANDLE", h, err)
		}
	}
	if _, err := fs.GetAttr(req, fs.Handle("missing"), nfsv4.AttrMask{}); !errors.Is(err, nfsv4.ErrStale) {
		t.Errorf("missing path = %v; want STALE", err)
	}
	unknownTable := fs.encodeTable(123)
	if _, err := fs.GetAttr(req, unknownTable, nfsv4.AttrMask{}); !errors.Is(err, nfsv4.ErrStale) {
		t.Errorf("unknown table ID = %v; want STALE", err)
	}
}
