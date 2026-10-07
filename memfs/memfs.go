// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package memfs is an in-memory filesystem served with nodefs. It's useful
// for tests and demos, and as an example of using nodefs.
//
// Files can be marked immutable, in which case clients are granted
// delegations to cache them forever. Changes to mutable files and
// directories recall delegations (when SetServer has been called), so
// clients see changes immediately.
package memfs

import (
	"context"
	"io"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/nodefs"
)

// FS is an in-memory filesystem. It embeds the *nodefs.FS that serves it,
// which is what to use as the nfsv4.Server's FS.
type FS struct {
	*nodefs.FS

	mu     sync.Mutex
	root   *node
	srv    *nfsv4.Server
	nextID uint64
}

// node is a file, directory, or symlink.
type node struct {
	fs *FS

	// The following are guarded by fs.mu.
	attrs     nfsv4.Attrs
	data      []byte
	target    string
	children  map[string]*node
	immutable bool
	cache     nfsv4.Delegation
}

// New returns a new FS with an empty root directory.
func New() *FS {
	m := &FS{}
	m.root = m.newNode(nfsv4.TypeDir, 0o755)
	m.FS = nodefs.New(dirNode{m.root}, nil)
	return m
}

// SetServer sets the server whose client caches are invalidated when files
// change.
func (m *FS) SetServer(srv *nfsv4.Server) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.srv = srv
}

func (m *FS) newNode(t nfsv4.FileType, mode uint32) *node {
	m.nextID++
	now := time.Now()
	n := &node{
		fs: m,
		attrs: nfsv4.Attrs{
			Type:       t,
			Mode:       mode,
			FileID:     m.nextID + 1, // 1 is the root's FileID by convention
			Change:     1,
			ModTime:    now,
			ChangeTime: now,
		},
	}
	if t == nfsv4.TypeDir {
		n.children = make(map[string]*node)
		n.attrs.Size = 4096
	}
	if m.root == nil {
		n.attrs.FileID = 1
	}
	return n
}

func split(p string) []string {
	p = strings.Trim(path.Clean("/"+p), "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// mkdirAllLocked returns the directory at comps, creating it and its
// parents as needed. It returns the paths of directories whose entries
// changed.
func (m *FS) mkdirAllLocked(comps []string, changed *[]string) *node {
	n := m.root
	for i, c := range comps {
		child, ok := n.children[c]
		if !ok {
			child = m.newNode(nfsv4.TypeDir, 0o755)
			child.immutable = n.immutable
			child.cache = n.cache
			n.children[c] = child
			n.touchLocked()
			*changed = append(*changed, strings.Join(comps[:i], "/"))
		}
		n = child
	}
	return n
}

func (n *node) touchLocked() {
	n.attrs.Change++
	now := time.Now()
	n.attrs.ModTime = now
	n.attrs.ChangeTime = now
}

// MkdirAll creates the directory p and any missing parents.
func (m *FS) MkdirAll(p string) error {
	var changed []string
	m.mu.Lock()
	m.mkdirAllLocked(split(p), &changed)
	m.mu.Unlock()
	return m.invalidate(changed)
}

// WriteFile creates or replaces the contents of the regular file p,
// creating parent directories as needed. It panics if p is immutable.
func (m *FS) WriteFile(p string, data []byte, mode uint32) error {
	return m.add(p, nfsv4.TypeReg, mode, func(n *node) {
		n.data = slices.Clone(data)
		n.attrs.Size = uint64(len(data))
	})
}

// Symlink creates or replaces the symlink p pointing to target.
func (m *FS) Symlink(target, p string) error {
	return m.add(p, nfsv4.TypeSymlink, 0o777, func(n *node) {
		n.target = target
		n.attrs.Size = uint64(len(target))
	})
}

func (m *FS) add(p string, t nfsv4.FileType, mode uint32, set func(*node)) error {
	comps := split(p)
	if len(comps) == 0 {
		panic("memfs: can't replace the root")
	}
	var changed []string
	m.mu.Lock()
	dir := m.mkdirAllLocked(comps[:len(comps)-1], &changed)
	name := comps[len(comps)-1]
	n, ok := dir.children[name]
	if ok && (n.immutable || n.attrs.Type != t) {
		m.mu.Unlock()
		if n.immutable {
			panic("memfs: modifying immutable " + p)
		}
		panic("memfs: changing type of " + p)
	}
	if !ok {
		n = m.newNode(t, mode)
		n.immutable = dir.immutable
		n.cache = dir.cache
		dir.children[name] = n
		dir.touchLocked()
		changed = append(changed, strings.Join(comps[:len(comps)-1], "/"))
	} else {
		n.touchLocked()
		n.attrs.Mode = mode
		changed = append(changed, strings.Join(comps, "/"))
	}
	set(n)
	m.mu.Unlock()
	return m.invalidate(changed)
}

// Remove removes p and anything below it.
func (m *FS) Remove(p string) error {
	comps := split(p)
	if len(comps) == 0 {
		panic("memfs: can't remove the root")
	}
	m.mu.Lock()
	n := m.root
	for _, c := range comps[:len(comps)-1] {
		n = n.children[c]
		if n == nil {
			m.mu.Unlock()
			return nil
		}
	}
	name := comps[len(comps)-1]
	if _, ok := n.children[name]; !ok {
		m.mu.Unlock()
		return nil
	}
	delete(n.children, name)
	n.touchLocked()
	m.mu.Unlock()
	m.Forget(p)
	return m.invalidate([]string{strings.Join(comps[:len(comps)-1], "/"), strings.Join(comps, "/")})
}

// SetImmutable marks p and everything below it (including things created
// below it later) as immutable, granting clients delegations to cache them
// forever. Immutable files can't be changed, but new entries may still be
// added to immutable directories created by MkdirAll.
func (m *FS) SetImmutable(p string) {
	m.setCache(p, nfsv4.Delegation{Grant: true}, true)
}

// SetCachePolicy sets the cache policy of p and everything below it
// (including things created below it later). Changes to mutable objects
// recall delegations, so granting delegations for mutable objects is safe.
func (m *FS) SetCachePolicy(p string, d nfsv4.Delegation) {
	m.setCache(p, d, false)
}

func (m *FS) setCache(p string, d nfsv4.Delegation, immutable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.root
	for _, c := range split(p) {
		n = n.children[c]
		if n == nil {
			return
		}
	}
	var walk func(*node)
	walk = func(n *node) {
		n.cache = d
		if immutable {
			n.immutable = true
		}
		for _, c := range n.children {
			walk(c)
		}
	}
	walk(n)
}

// invalidate recalls delegations for the given paths.
func (m *FS) invalidate(paths []string) error {
	m.mu.Lock()
	srv := m.srv
	m.mu.Unlock()
	for _, p := range paths {
		m.Forget(p)
		if srv == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		err := srv.Invalidate(ctx, m.Handle(p))
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}

// The nodefs node types. A *node is wrapped in the type matching its
// file type so nodefs sees the right interfaces.
type (
	dirNode     struct{ n *node }
	fileNode    struct{ n *node }
	symlinkNode struct{ n *node }
	otherNode   struct{ n *node }
)

func wrap(n *node) nodefs.Node {
	switch n.attrs.Type {
	case nfsv4.TypeDir:
		return dirNode{n}
	case nfsv4.TypeReg:
		return fileNode{n}
	case nfsv4.TypeSymlink:
		return symlinkNode{n}
	}
	return otherNode{n}
}

func (n *node) attr() (*nfsv4.Attrs, error) {
	n.fs.mu.Lock()
	defer n.fs.mu.Unlock()
	a := n.attrs
	return &a, nil
}

func (n *node) cachePolicy() nfsv4.Delegation {
	n.fs.mu.Lock()
	defer n.fs.mu.Unlock()
	return n.cache
}

func (d dirNode) Attr(r *nfsv4.Request) (*nfsv4.Attrs, error)     { return d.n.attr() }
func (d fileNode) Attr(r *nfsv4.Request) (*nfsv4.Attrs, error)    { return d.n.attr() }
func (d symlinkNode) Attr(r *nfsv4.Request) (*nfsv4.Attrs, error) { return d.n.attr() }
func (d otherNode) Attr(r *nfsv4.Request) (*nfsv4.Attrs, error)   { return d.n.attr() }

func (d dirNode) CachePolicy(r *nfsv4.Request) nfsv4.Delegation     { return d.n.cachePolicy() }
func (d fileNode) CachePolicy(r *nfsv4.Request) nfsv4.Delegation    { return d.n.cachePolicy() }
func (d symlinkNode) CachePolicy(r *nfsv4.Request) nfsv4.Delegation { return d.n.cachePolicy() }

func (d dirNode) Lookup(r *nfsv4.Request, name string) (nodefs.Node, error) {
	d.n.fs.mu.Lock()
	defer d.n.fs.mu.Unlock()
	c, ok := d.n.children[name]
	if !ok {
		return nil, nfsv4.ErrNoEnt
	}
	return wrap(c), nil
}

func (d dirNode) ReadDir(r *nfsv4.Request) ([]nodefs.DirEntry, error) {
	d.n.fs.mu.Lock()
	defer d.n.fs.mu.Unlock()
	ents := make([]nodefs.DirEntry, 0, len(d.n.children))
	for name, c := range d.n.children {
		ents = append(ents, nodefs.DirEntry{Name: name, Node: wrap(c)})
	}
	slices.SortFunc(ents, func(a, b nodefs.DirEntry) int { return strings.Compare(a.Name, b.Name) })
	return ents, nil
}

func (f fileNode) ReadAt(r *nfsv4.Request, p []byte, off int64) (int, error) {
	f.n.fs.mu.Lock()
	defer f.n.fs.mu.Unlock()
	if off >= int64(len(f.n.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.n.data[off:])
	if off+int64(n) >= int64(len(f.n.data)) {
		return n, io.EOF
	}
	return n, nil
}

func (s symlinkNode) Readlink(r *nfsv4.Request) (string, error) {
	s.n.fs.mu.Lock()
	defer s.n.fs.mu.Unlock()
	return s.n.target, nil
}
