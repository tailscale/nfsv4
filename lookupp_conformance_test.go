// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/internal/testfs"
	"github.com/tailscale/nfsv4/memfs"
)

// lookuppConformanceFS uses handles that do not have the nodefs format.
type lookuppConformanceFS struct {
	nfsv4.FS
	typ         nfsv4.FileType
	parentCalls int
}

func (fs *lookuppConformanceFS) GetAttr(r *nfsv4.Request, fh nfsv4.FileHandle, want nfsv4.AttrMask) (*nfsv4.Attrs, error) {
	return &nfsv4.Attrs{
		Type: fs.typ,
	}, nil
}

func (fs *lookuppConformanceFS) LookupParent(r *nfsv4.Request, fh nfsv4.FileHandle) (nfsv4.FileHandle, error) {
	fs.parentCalls++
	return fs.Root(r)
}

func TestFSConformanceLookupp(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, tt := range []struct {
			typ  nfsv4.FileType
			want nfsv4.Status
		}{
			{nfsv4.TypeSymlink, nfsv4.ErrSymlink},
			{nfsv4.TypeReg, nfsv4.ErrNotDir},
			{nfsv4.TypeFIFO, nfsv4.ErrNotDir},
			{nfsv4.TypeDir, nfsv4.OK},
			{nfsv4.TypeAttrDir, nfsv4.OK},
		} {
			t.Run(fmt.Sprintf("%d/%v", minor, tt.typ), func(t *testing.T) {
				fs := &lookuppConformanceFS{
					FS:  testfs.New(),
					typ: tt.typ,
				}
				c := newSessionClient(t, &nfsv4.Server{
					FS: fs,
				}, false)
				c.MinorVersion = minor
				b, slot := c.Seq()
				b.Op(nfsv4.OpPutFH).Opaque([]byte("abc"))
				b.Op(nfsv4.OpLookupp)
				r, err := c.DoSeq(b, slot)
				if err != nil {
					t.Fatal(err)
				}
				must(t, r, nfsv4.OpPutFH)
				expect(t, r, nfsv4.OpLookupp, tt.want)
				if tt.want != nfsv4.OK && fs.parentCalls != 0 {
					t.Error("LookupParent called for a non-directory")
				}
			})
		}
	}
}

func TestFSConformanceLookuppNodeTree(t *testing.T) {
	fs := memfs.New()
	if err := fs.WriteFile("dir/file", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.Symlink("dir", "link"); err != nil {
		t.Fatal(err)
	}
	c := newSessionClient(t, &nfsv4.Server{
		FS: fs,
	}, false)
	for _, tt := range []struct {
		path string
		want nfsv4.Status
	}{
		{"link", nfsv4.ErrSymlink},
		{"dir/file", nfsv4.ErrNotDir},
		{"dir", nfsv4.OK},
		{"", nfsv4.ErrNoEnt},
	} {
		t.Run(tt.path, func(t *testing.T) {
			b, slot := c.Seq()
			b.Op(nfsv4.OpPutFH).Opaque(fs.Handle(tt.path))
			b.Op(nfsv4.OpLookupp)
			b.Op(nfsv4.OpGetFH)
			r, err := c.DoSeq(b, slot)
			if err != nil {
				t.Fatal(err)
			}
			must(t, r, nfsv4.OpPutFH)
			expect(t, r, nfsv4.OpLookupp, tt.want)
			if tt.want == nfsv4.OK {
				must(t, r, nfsv4.OpGetFH)
				if got := r.D.Opaque(nfsv4.MaxFileHandleSize); !bytes.Equal(got, fs.Handle("")) {
					t.Fatalf("parent = %x; want root", got)
				}
			}
		})
	}
	b, slot := c.Seq()
	b.Op(nfsv4.OpLookupp)
	r, err := c.DoSeq(b, slot)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, r, nfsv4.OpLookupp, nfsv4.ErrNoFileHandle)
}
