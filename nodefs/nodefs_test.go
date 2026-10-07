// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nodefs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/tailscale/nfsv4"
)

// tnode is a simple test node.
type tnode struct {
	name     string
	children map[string]*tnode // nil for files
	data     string
	lookups  *int
	readdirs *int
}

func (n *tnode) Attr(r *nfsv4.Request) (*nfsv4.Attrs, error) {
	if n.children != nil {
		return &nfsv4.Attrs{Type: nfsv4.TypeDir, Mode: 0o755}, nil
	}
	return &nfsv4.Attrs{Type: nfsv4.TypeReg, Mode: 0o644, Size: uint64(len(n.data))}, nil
}

func (n dirT) Lookup(r *nfsv4.Request, name string) (Node, error) {
	*n.lookups++
	c, ok := n.children[name]
	if !ok {
		return nil, nfsv4.ErrNoEnt
	}
	return c.node(), nil
}

func (n dirT) ReadDir(r *nfsv4.Request) ([]DirEntry, error) {
	*n.readdirs++
	var ents []DirEntry
	for name := range n.children {
		ents = append(ents, DirEntry{Name: name})
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name < ents[j].Name })
	return ents, nil
}

func (n *tnode) node() Node {
	if n.children != nil {
		return dirT{n}
	}
	return fileT{n}
}

type dirT struct{ *tnode }
type fileT struct{ *tnode }

func (f fileT) ReadAt(r *nfsv4.Request, p []byte, off int64) (int, error) {
	if off >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.data[off:])
	if off+int64(n) == int64(len(f.data)) {
		return n, io.EOF
	}
	return n, nil
}

type tree struct {
	root     *tnode
	lookups  int
	readdirs int
}

func newTree(paths ...string) *tree {
	t := &tree{}
	t.root = &tnode{children: map[string]*tnode{}, lookups: &t.lookups, readdirs: &t.readdirs}
	for _, p := range paths {
		n := t.root
		comps := strings.Split(p, "/")
		for i, c := range comps {
			child, ok := n.children[c]
			if !ok {
				child = &tnode{name: c, lookups: &t.lookups, readdirs: &t.readdirs}
				if i < len(comps)-1 {
					child.children = map[string]*tnode{}
				} else {
					child.data = "contents of " + p
				}
				n.children[c] = child
			}
			n = child
		}
	}
	return t
}

var req = &nfsv4.Request{}

// lookupPath looks up p from the root with fs, returning its handle.
func lookupPath(t *testing.T, fs *FS, p string) nfsv4.FileHandle {
	t.Helper()
	h, _ := fs.Root(req)
	for _, c := range strings.Split(p, "/") {
		var err error
		h, _, err = fs.Lookup(req, h, c)
		if err != nil {
			t.Fatalf("Lookup %q in %q: %v", c, p, err)
		}
	}
	return h
}

func readAll(t *testing.T, fs *FS, h nfsv4.FileHandle) string {
	t.Helper()
	buf := make([]byte, 1000)
	n, eof, err := fs.Read(req, h, 0, buf)
	if err != nil || !eof {
		t.Fatalf("Read: %d, %v, %v", n, eof, err)
	}
	return string(buf[:n])
}

// findCollision returns two distinct names with the same component hash.
func findCollision() (string, string) {
	seen := map[uint32]string{}
	for i := 0; ; i++ {
		name := fmt.Sprintf("n%d", i)
		h := compHash(name)
		if prev, ok := seen[h]; ok {
			return prev, name
		}
		seen[h] = name
	}
}

func TestResolveAfterRestart(t *testing.T) {
	long := strings.Repeat("long-directory-name/", 8)
	a, b := findCollision()
	paths := []string{
		"short/file.txt",
		long + "deep.txt",
		long + "x/" + a,
		long + "x/" + b,
	}
	tr := newTree(paths...)
	fs1 := New(dirT{tr.root}, nil)
	handles := map[string]nfsv4.FileHandle{}
	for _, p := range paths {
		handles[p] = lookupPath(t, fs1, p)
		if got := readAll(t, fs1, handles[p]); got != "contents of "+p {
			t.Errorf("%q: read %q", p, got)
		}
	}
	if bytes.Equal(handles[paths[2]], handles[paths[3]]) {
		t.Fatalf("colliding names got the same handle")
	}
	if h := handles[paths[1]]; h[0] != fmtPath || !isHashed(h, splitPath(paths[1])) {
		t.Errorf("deep handle %x is not a hashed path handle", h)
	}

	// A fresh FS over the same tree, as after a restart, resolves all
	// the handles without any lookups from the client.
	fs2 := New(dirT{tr.root}, nil)
	for _, p := range paths {
		if got := readAll(t, fs2, handles[p]); got != "contents of "+p {
			t.Errorf("after restart, %q: read %q", p, got)
		}
		a, err := fs2.GetAttr(req, handles[p], nfsv4.AttrMask{})
		if err != nil {
			t.Fatal(err)
		}
		a1, _ := fs1.GetAttr(req, handles[p], nfsv4.AttrMask{})
		if a.FileID != a1.FileID || a.FileID == 0 {
			t.Errorf("%q: FileID %d after restart; was %d", p, a.FileID, a1.FileID)
		}
	}
	if tr.readdirs == 0 {
		t.Errorf("expected directory listings to resolve hashed handles")
	}

	// Resolution results are cached.
	l, r := tr.lookups, tr.readdirs
	for _, p := range paths {
		readAll(t, fs2, handles[p])
	}
	if tr.lookups != l || tr.readdirs != r {
		t.Errorf("re-resolving did %d lookups and %d readdirs", tr.lookups-l, tr.readdirs-r)
	}

	// Handles for things that no longer exist are stale.
	delete(tr.root.children, "short")
	fs3 := New(dirT{tr.root}, nil)
	if _, err := fs3.GetAttr(req, handles["short/file.txt"], nfsv4.AttrMask{}); !errors.Is(err, nfsv4.ErrStale) {
		t.Errorf("removed file: %v", err)
	}
	if _, err := fs3.GetAttr(req, nfsv4.FileHandle{0x99}, nfsv4.AttrMask{}); !errors.Is(err, nfsv4.ErrBadHandle) {
		t.Errorf("garbage handle: %v", err)
	}
}

func TestTableHandles(t *testing.T) {
	deep := strings.Repeat("abcdefghijklmnop/", 30) + "f"
	tr := newTree(deep)
	fs1 := New(dirT{tr.root}, nil)
	h := lookupPath(t, fs1, deep)
	if h[0] != fmtTable {
		t.Fatalf("handle format %#x; want table", h[0])
	}
	if got := readAll(t, fs1, h); got != "contents of "+deep {
		t.Errorf("read %q", got)
	}
	if h2 := fs1.Handle(deep); !bytes.Equal(h, h2) {
		t.Errorf("table handle not stable")
	}
	// They don't survive a restart.
	fs2 := New(dirT{tr.root}, nil)
	if _, err := fs2.GetAttr(req, h, nfsv4.AttrMask{}); !errors.Is(err, nfsv4.ErrStale) {
		t.Errorf("table handle after restart: %v", err)
	}
}

func TestLookupParentAndReadDir(t *testing.T) {
	tr := newTree("a/b/c.txt", "a/b/d.txt", "a/e.txt")
	fs := New(dirT{tr.root}, nil)
	hb := lookupPath(t, fs, "a/b")
	hp, err := fs.LookupParent(req, hb)
	if err != nil || !bytes.Equal(hp, fs.Handle("a")) {
		t.Errorf("LookupParent = %x, %v", hp, err)
	}
	ha := fs.Handle("a")
	hr, err := fs.LookupParent(req, ha)
	if err != nil || !bytes.Equal(hr, rootHandle) {
		t.Errorf("LookupParent(a) = %x, %v", hr, err)
	}

	var names []string
	var last uint64
	_, err = fs.ReadDir(req, hb, nfsv4.ReadDirArgs{Want: nfsv4.MakeAttrMask(nfsv4.AttrType)}, func(e nfsv4.DirEntry) bool {
		names = append(names, e.Name)
		last = e.Cookie
		if e.Attrs == nil || e.Handle == nil {
			t.Errorf("entry %q lacks attrs or handle", e.Name)
		}
		return true
	})
	if err != nil || strings.Join(names, ",") != "c.txt,d.txt" {
		t.Errorf("ReadDir = %q, %v", names, err)
	}
	// Resuming after the last cookie yields nothing.
	n := 0
	fs.ReadDir(req, hb, nfsv4.ReadDirArgs{Cookie: last}, func(e nfsv4.DirEntry) bool { n++; return true })
	if n != 0 {
		t.Errorf("resumed listing has %d entries", n)
	}
	if _, err := fs.ReadDir(req, hb, nfsv4.ReadDirArgs{Cookie: 1000}, func(nfsv4.DirEntry) bool { return true }); !errors.Is(err, nfsv4.ErrBadCookie) {
		t.Errorf("bad cookie: %v", err)
	}
	hc := lookupPath(t, fs, "a/b/c.txt")
	if _, _, err := fs.Lookup(req, hc, "x"); !errors.Is(err, nfsv4.ErrNotDir) {
		t.Errorf("Lookup in file: %v", err)
	}
	if _, _, err := fs.Lookup(req, hb, "nope"); !errors.Is(err, nfsv4.ErrNoEnt) {
		t.Errorf("Lookup missing: %v", err)
	}
}

func TestCraftedHandles(t *testing.T) {
	tr := newTree("a/b.txt", "c.txt")
	fs := New(dirT{tr.root}, nil)
	for _, h := range []nfsv4.FileHandle{
		{fmtPath, 2, '.', '.', 5, 'c', '.', 't', 'x', 't'},
		{fmtPath, 1, '.', 5, 'c', '.', 't', 'x', 't'},
		{fmtPath, 7, 'a', '/', 'b', '.', 't', 'x', 't'},
		{fmtPath, 3, 'a', 0, 'b'},
		// A short path in the hashed format isn't canonical.
		append(nfsv4.FileHandle{fmtPath, 1, 'a', 0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
	} {
		if _, err := fs.GetAttr(req, h, nfsv4.AttrMask{}); err == nil {
			t.Errorf("GetAttr(%q) succeeded", h)
		}
	}
	if _, err := fs.ReadDir(req, rootHandle, nfsv4.ReadDirArgs{Cookie: 1 << 63}, func(nfsv4.DirEntry) bool { return true }); !errors.Is(err, nfsv4.ErrBadCookie) {
		t.Errorf("huge cookie: %v", err)
	}
}
