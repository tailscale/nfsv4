// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nodefs

import (
	"errors"
	"testing"

	"github.com/tailscale/nfsv4"
)

type conformanceLink struct{}

func (conformanceLink) Attr(*nfsv4.Request) (*nfsv4.Attrs, error) {
	return &nfsv4.Attrs{
		Type: nfsv4.TypeSymlink,
	}, nil
}

func (conformanceLink) Readlink(*nfsv4.Request) (string, error) { return "target", nil }

func TestFSConformanceLookupParentTypes(t *testing.T) {
	tr := newTree("dir/file")
	fs := New(dirT{
		tnode: tr.root,
	}, nil)
	fs.cachePut("link", conformanceLink{})
	for _, tt := range []struct {
		path string
		want nfsv4.Status
	}{
		{"dir/file", nfsv4.ErrNotDir},
		{"link", nfsv4.ErrSymlink},
		{"missing", nfsv4.ErrStale},
	} {
		if _, err := fs.LookupParent(req, fs.Handle(tt.path)); !errors.Is(err, tt.want) {
			t.Errorf("LookupParent(%q) = %v; want %v", tt.path, err, tt.want)
		}
	}
}
