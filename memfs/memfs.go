// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package memfs is an in-memory filesystem served with nodefs. It's useful
// for tests and demos, and as an example of using nodefs.
//
// Files can be marked immutable, in which case clients are granted
// delegations to cache them forever. Changes to mutable files and
// directories first recall delegations (when SetServer has been called).
// After a recall, clients can still use their ordinary attribute and data
// caches. Changes become visible when the client revalidates those caches.
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

	mu   sync.Mutex
	root *node
	srv  *nfsv4.Server
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

// SetServer sets the server whose delegations are recalled before files
// change.
func (m *FS) SetServer(srv *nfsv4.Server) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.srv = srv
}

func (m *FS) newNode(t nfsv4.FileType, mode uint32) *node {
	now := time.Now()
	n := &node{
		fs: m,
		attrs: nfsv4.Attrs{
			// FileID is left zero, so nodefs derives it from the
			// path, keeping it stable across restarts regardless of
			// the order in which the tree is built.
			Type:       t,
			Mode:       mode,
			Change:     1,
			ModTime:    now,
			ChangeTime: now,
		},
	}
	if t == nfsv4.TypeDir {
		n.children = make(map[string]*node)
		n.attrs.Size = 4096
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
// parents as needed.
func (m *FS) mkdirAllLocked(comps []string) *node {
	n := m.root
	for _, c := range comps {
		child, ok := n.children[c]
		if !ok {
			child = m.newNode(nfsv4.TypeDir, 0o755)
			child.immutable = n.immutable
			child.cache = n.cache
			n.children[c] = child
			n.touchLocked()
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
	comps := split(p)
	return m.change(comps, false, func() { m.mkdirAllLocked(comps) })
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
	return m.change(comps, false, func() {
		dir := m.mkdirAllLocked(comps[:len(comps)-1])
		name := comps[len(comps)-1]
		n, ok := dir.children[name]
		if ok && n.immutable {
			panic("memfs: modifying immutable " + p)
		}
		if ok && n.attrs.Type != t {
			panic("memfs: changing type of " + p)
		}
		if !ok {
			n = m.newNode(t, mode)
			n.immutable = dir.immutable
			n.cache = dir.cache
			dir.children[name] = n
			dir.touchLocked()
		} else {
			n.touchLocked()
			n.attrs.Mode = mode
		}
		set(n)
	})
}

// Remove removes p and anything below it.
func (m *FS) Remove(p string) error {
	comps := split(p)
	if len(comps) == 0 {
		panic("memfs: can't remove the root")
	}
	err := m.change(comps, true, func() {
		n := m.root
		for _, c := range comps[:len(comps)-1] {
			n = n.children[c]
			if n == nil {
				return
			}
		}
		name := comps[len(comps)-1]
		if _, ok := n.children[name]; ok {
			delete(n.children, name)
			n.touchLocked()
		}
	})
	m.Forget(p)
	return err
}

// change runs fn with m.mu held, while delegations are recalled for the
// objects that changing the path comps (and creating its missing parent
// directories) affects.
func (m *FS) change(comps []string, remove bool, fn func()) error {
	for {
		m.mu.Lock()
		srv := m.srv
		paths := m.affectedLocked(comps, remove)
		m.mu.Unlock()

		release := func() {}
		if srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			var err error
			release, err = m.Recall(ctx, srv, paths...)
			cancel()
			if err != nil {
				return err
			}
		}
		m.mu.Lock()
		if !slices.Equal(paths, m.affectedLocked(comps, remove)) {
			// Something else changed the tree meanwhile.
			m.mu.Unlock()
			release()
			continue
		}
		fn()
		m.mu.Unlock()
		release()
		for _, p := range paths {
			m.Forget(p)
		}
		return nil
	}
}

// affectedLocked returns the paths whose objects change when creating or
// modifying the path comps: the object itself if it exists, and otherwise
// the deepest existing directory (which gains an entry). When removing, the
// parent directory is affected too.
func (m *FS) affectedLocked(comps []string, remove bool) []string {
	n := m.root
	for i, c := range comps {
		child, ok := n.children[c]
		if !ok {
			return []string{strings.Join(comps[:i], "/")}
		}
		n = child
	}
	p := strings.Join(comps, "/")
	if remove && len(comps) > 0 {
		return []string{p, strings.Join(comps[:len(comps)-1], "/")}
	}
	return []string{p}
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
