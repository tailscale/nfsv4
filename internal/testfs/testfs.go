// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package testfs is a simple in-memory nfsv4.FS using raw filehandles (the
// 8-byte inode number), for tests.
package testfs

import (
	"encoding/binary"
	"path"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/nfsv4"
)

// FS is an in-memory filesystem.
type FS struct {
	mu    sync.Mutex
	nodes map[uint64]*node
	next  uint64

	// Gen, if non-zero, is included in all filehandles except the
	// root's, and filehandles with a different Gen are stale. Setting
	// it differently in two FS instances simulates a server whose
	// filehandles don't survive restarts.
	Gen uint64

	// StaleHits counts uses of stale filehandles.
	StaleHits atomic.Int64

	// DelegatePolicy, if non-nil, decides delegations.
	DelegatePolicy func(path string, a *nfsv4.Attrs) nfsv4.Delegation
}

type node struct {
	ino      uint64
	parent   uint64
	path     string
	attrs    nfsv4.Attrs
	data     []byte
	target   string
	children map[string]uint64
}

var modTime = time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)

// New returns an empty FS (with just a root directory).
func New() *FS {
	fs := &FS{nodes: make(map[uint64]*node), next: 1}
	fs.nodes[1] = &node{
		ino:      1,
		parent:   1,
		path:     "/",
		attrs:    nfsv4.Attrs{Type: nfsv4.TypeDir, Mode: 0o755, FileID: 1, Change: 1, ModTime: modTime, Size: 4096},
		children: map[string]uint64{},
	}
	return fs
}

func (fs *FS) mkdirAllLocked(p string) *node {
	n := fs.nodes[1]
	if p == "/" || p == "" {
		return n
	}
	for _, el := range strings.Split(strings.Trim(p, "/"), "/") {
		ino, ok := n.children[el]
		if !ok {
			fs.next++
			ino = fs.next
			fs.nodes[ino] = &node{
				ino:      ino,
				parent:   n.ino,
				path:     path.Join(n.path, el),
				attrs:    nfsv4.Attrs{Type: nfsv4.TypeDir, Mode: 0o755, FileID: ino, Change: 1, ModTime: modTime, Size: 4096},
				children: map[string]uint64{},
			}
			n.children[el] = ino
			n.attrs.Change++
		}
		n = fs.nodes[ino]
	}
	return n
}

// MkdirAll creates directory p and its parents.
func (fs *FS) MkdirAll(p string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.mkdirAllLocked(p)
}

func (fs *FS) addLocked(p string, a nfsv4.Attrs) *node {
	dir := fs.mkdirAllLocked(path.Dir(p))
	name := path.Base(p)
	if ino, ok := dir.children[name]; ok {
		n := fs.nodes[ino]
		a.FileID = n.ino
		a.Change = n.attrs.Change + 1
		n.attrs = a
		return n
	}
	fs.next++
	a.FileID = fs.next
	a.Change = 1
	n := &node{ino: fs.next, parent: dir.ino, path: p, attrs: a}
	fs.nodes[n.ino] = n
	dir.children[name] = n.ino
	dir.attrs.Change++
	return n
}

// WriteFile creates or replaces the regular file p.
func (fs *FS) WriteFile(p string, data []byte, mode uint32) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n := fs.addLocked(p, nfsv4.Attrs{Type: nfsv4.TypeReg, Mode: mode, Size: uint64(len(data)), ModTime: modTime, NumLinks: 1})
	n.data = append([]byte(nil), data...)
}

// Symlink creates the symlink p pointing to target.
func (fs *FS) Symlink(target, p string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n := fs.addLocked(p, nfsv4.Attrs{Type: nfsv4.TypeSymlink, Mode: 0o777, Size: uint64(len(target)), ModTime: modTime})
	n.target = target
}

// Handle returns the filehandle of p, or nil.
func (fs *FS) Handle(p string) nfsv4.FileHandle {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n := fs.nodes[1]
	for _, el := range strings.Split(strings.Trim(p, "/"), "/") {
		if el == "" {
			continue
		}
		ino, ok := n.children[el]
		if !ok {
			return nil
		}
		n = fs.nodes[ino]
	}
	return fs.fh(n.ino)
}

func (fs *FS) fh(ino uint64) nfsv4.FileHandle {
	var h nfsv4.FileHandle
	if fs.Gen != 0 && ino != 1 {
		h = binary.BigEndian.AppendUint64(h, fs.Gen)
	}
	return binary.BigEndian.AppendUint64(h, ino)
}

func (fs *FS) nodeLocked(h nfsv4.FileHandle) (*node, error) {
	var ino uint64
	switch {
	case len(h) == 8:
		ino = binary.BigEndian.Uint64(h)
		if fs.Gen != 0 && ino != 1 {
			fs.StaleHits.Add(1)
			return nil, nfsv4.ErrStale
		}
	case len(h) == 16 && fs.Gen != 0:
		if binary.BigEndian.Uint64(h) != fs.Gen {
			fs.StaleHits.Add(1)
			return nil, nfsv4.ErrStale
		}
		ino = binary.BigEndian.Uint64(h[8:])
	default:
		return nil, nfsv4.ErrBadHandle
	}
	n, ok := fs.nodes[ino]
	if !ok {
		fs.StaleHits.Add(1)
		return nil, nfsv4.ErrStale
	}
	return n, nil
}

func (fs *FS) Root(r *nfsv4.Request) (nfsv4.FileHandle, error) { return fs.fh(1), nil }

func (fs *FS) GetAttr(r *nfsv4.Request, h nfsv4.FileHandle, want nfsv4.AttrMask) (*nfsv4.Attrs, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n, err := fs.nodeLocked(h)
	if err != nil {
		return nil, err
	}
	a := n.attrs
	return &a, nil
}

func (fs *FS) Lookup(r *nfsv4.Request, dir nfsv4.FileHandle, name string) (nfsv4.FileHandle, *nfsv4.Attrs, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n, err := fs.nodeLocked(dir)
	if err != nil {
		return nil, nil, err
	}
	if n.attrs.Type != nfsv4.TypeDir {
		return nil, nil, nfsv4.ErrNotDir
	}
	ino, ok := n.children[name]
	if !ok {
		return nil, nil, nfsv4.ErrNoEnt
	}
	a := fs.nodes[ino].attrs
	return fs.fh(ino), &a, nil
}

func (fs *FS) LookupParent(r *nfsv4.Request, dir nfsv4.FileHandle) (nfsv4.FileHandle, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n, err := fs.nodeLocked(dir)
	if err != nil {
		return nil, err
	}
	return fs.fh(n.parent), nil
}

func (fs *FS) ReadDir(r *nfsv4.Request, dir nfsv4.FileHandle, args nfsv4.ReadDirArgs, emit func(nfsv4.DirEntry) bool) (nfsv4.ReadDirResult, error) {
	fs.mu.Lock()
	n, err := fs.nodeLocked(dir)
	if err != nil {
		fs.mu.Unlock()
		return nfsv4.ReadDirResult{}, err
	}
	if n.attrs.Type != nfsv4.TypeDir {
		fs.mu.Unlock()
		return nfsv4.ReadDirResult{}, nfsv4.ErrNotDir
	}
	names := make([]string, 0, len(n.children))
	for name := range n.children {
		names = append(names, name)
	}
	sort.Strings(names)
	var ents []nfsv4.DirEntry
	for i, name := range names {
		cookie := uint64(i) + 3
		if cookie <= args.Cookie {
			continue
		}
		c := fs.nodes[n.children[name]]
		a := c.attrs
		ents = append(ents, nfsv4.DirEntry{Name: name, Cookie: cookie, Handle: fs.fh(c.ino), Attrs: &a})
	}
	fs.mu.Unlock()
	for _, ent := range ents {
		if !emit(ent) {
			break
		}
	}
	return nfsv4.ReadDirResult{}, nil
}

func (fs *FS) Read(r *nfsv4.Request, h nfsv4.FileHandle, off uint64, p []byte) (int, bool, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n, err := fs.nodeLocked(h)
	if err != nil {
		return 0, false, err
	}
	switch n.attrs.Type {
	case nfsv4.TypeReg:
	case nfsv4.TypeDir:
		return 0, false, nfsv4.ErrIsDir
	default:
		return 0, false, nfsv4.ErrInval
	}
	if off >= uint64(len(n.data)) {
		return 0, true, nil
	}
	c := copy(p, n.data[off:])
	return c, off+uint64(c) >= uint64(len(n.data)), nil
}

func (fs *FS) ReadLink(r *nfsv4.Request, h nfsv4.FileHandle) (string, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n, err := fs.nodeLocked(h)
	if err != nil {
		return "", err
	}
	if n.attrs.Type != nfsv4.TypeSymlink {
		return "", nfsv4.ErrInval
	}
	return n.target, nil
}

// Delegator returns an nfsv4.Delegator for fs using fs.DelegatePolicy.
func (fs *FS) Delegator() nfsv4.Delegator { return delegator{fs} }

type delegator struct{ fs *FS }

func (d delegator) Delegate(r *nfsv4.Request, h nfsv4.FileHandle, a *nfsv4.Attrs) nfsv4.Delegation {
	d.fs.mu.Lock()
	n, err := d.fs.nodeLocked(h)
	d.fs.mu.Unlock()
	if err != nil || d.fs.DelegatePolicy == nil {
		return nfsv4.Delegation{}
	}
	return d.fs.DelegatePolicy(n.path, a)
}

// WithDelegator wraps fs in an FS that also implements nfsv4.Delegator.
func (fs *FS) WithDelegator() nfsv4.FS {
	return struct {
		*FS
		delegator
	}{fs, delegator{fs}}
}
