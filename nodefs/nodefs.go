// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package nodefs adapts a tree of nodes to an nfsv4.FS, managing NFSv4
// filehandles so that implementations don't have to think about them.
//
// Implementations provide a root Dir. Directories look up and list
// children, files read their contents, and symlinks return their targets;
// all nodes report their attributes.
//
// Filehandles are derived from each node's path. For typical paths they're
// the path itself, so after a server restart they're resolved again by
// looking up each path component from the root, without the server having
// to remember anything. Clients holding filehandles across a restart
// (including open files and processes with their working directory in the
// mount) carry on as if nothing happened. Long or deep paths that don't
// fit in NFSv4's 128-byte filehandles have their trailing components
// hashed; those are resolved after a restart by listing directories and
// matching hashes, so such directories must be listable. Only paths too
// deep for even that (more than about 20 levels of long names) get
// volatile filehandles that clients must re-look-up after a restart.
//
// Resolved nodes are cached by path in an LRU cache, so nodes should be
// cheap to keep in memory, and an FS whose nodes change identity (a path
// that now refers to a different object) should call FS.Forget, or use
// FS.Recall when changing objects that clients may have delegations for.
package nodefs

import (
	"bytes"
	"container/list"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	iofs "io/fs"
	"path"
	"sync"

	"github.com/tailscale/nfsv4"
)

// Node is a filesystem object. Every Node must also implement Dir, File,
// or Symlink, matching the Type in its attributes (other types, such as
// devices, need only implement Node).
type Node interface {
	// Attr returns the node's attributes. Type is required. If FileID
	// is zero, a stable FileID is derived from the node's path.
	Attr(r *nfsv4.Request) (*nfsv4.Attrs, error)
}

// Dir is a directory node.
type Dir interface {
	Node

	// Lookup returns the child named name, or an error wrapping
	// fs.ErrNotExist (or nfsv4.ErrNoEnt) if there's no such child.
	Lookup(r *nfsv4.Request, name string) (Node, error)

	// ReadDir returns the directory's entries, not including "." or
	// "..". The order must be stable while the directory is unchanged,
	// since clients resume listings by position. Clients may list a
	// large directory in several requests, each calling ReadDir, so
	// implementations of large directories should cache their entries.
	ReadDir(r *nfsv4.Request) ([]DirEntry, error)
}

// DirEntry is a directory entry.
type DirEntry struct {
	Name string

	// Node is the entry's node, if known. If nil and the client wants
	// the entry's attributes, the Dir's Lookup is called.
	Node Node
}

// File is a regular file node.
type File interface {
	Node

	// ReadAt reads len(p) bytes at offset off, like io.ReaderAt. At the
	// end of the file, it returns io.EOF, which may accompany the last
	// bytes.
	ReadAt(r *nfsv4.Request, p []byte, off int64) (int, error)
}

// Symlink is a symbolic link node.
type Symlink interface {
	Node

	// Readlink returns the link's target.
	Readlink(r *nfsv4.Request) (string, error)
}

// CacheController is an optional interface for nodes to control client
// caching of themselves; see nfsv4.Delegation. Nodes that don't implement
// it get Options.DefaultCache.
type CacheController interface {
	CachePolicy(r *nfsv4.Request) nfsv4.Delegation
}

// Options are options for New.
type Options struct {
	// MaxCachedNodes is the maximum number of nodes kept in the cache.
	// If zero, 100,000 is used.
	MaxCachedNodes int

	// DefaultCache is the cache policy for nodes that don't implement
	// CacheController.
	DefaultCache nfsv4.Delegation

	// StatFS, if non-nil, reports filesystem space and file counts.
	StatFS func(r *nfsv4.Request) (*nfsv4.FSStat, error)
}

// FS is an nfsv4.FS (and nfsv4.Delegator and nfsv4.StatFSer) serving a tree
// of nodes. Create one with New.
type FS struct {
	root Dir
	opts Options

	instance [8]byte // random per-process ID for table handles

	mu      sync.Mutex
	byPath  map[string]*list.Element // of *entry
	lru     *list.List               // front is most recently used
	byAlias map[string]string        // handle with hashed components → path
	aliases *list.List               // of string handles, for eviction order
	table   map[uint64]string        // table handle ID → path (never evicted)
	nextID  uint64
}

type entry struct {
	path string
	node Node
}

// New returns an FS serving the tree rooted at root.
func New(root Dir, opts *Options) *FS {
	fs := &FS{
		root:    root,
		byPath:  make(map[string]*list.Element),
		lru:     list.New(),
		byAlias: make(map[string]string),
		aliases: list.New(),
		table:   make(map[uint64]string),
	}
	if opts != nil {
		fs.opts = *opts
	}
	if fs.opts.MaxCachedNodes <= 0 {
		fs.opts.MaxCachedNodes = 100_000
	}
	rand.Read(fs.instance[:])
	return fs
}

var (
	_ nfsv4.FS        = (*FS)(nil)
	_ nfsv4.Delegator = (*FS)(nil)
	_ nfsv4.StatFSer  = (*FS)(nil)
)

// Handle returns the filehandle for the node at path p (slash-separated,
// relative to the root; "" or "/" is the root), as sent to clients.
// It's what to pass to nfsv4.Server.Recall.
func (fs *FS) Handle(p string) nfsv4.FileHandle {
	return fs.handleFor(cleanPath(p))
}

func cleanPath(p string) string {
	p = path.Clean("/" + p)
	if p == "/" {
		return ""
	}
	return p[1:]
}

// handleFor returns the filehandle for the clean relative path p.
func (fs *FS) handleFor(p string) nfsv4.FileHandle {
	comps := splitPath(p)
	h := encodePath(p, comps)
	if h == nil {
		return fs.tableHandle(p)
	}
	if h[0] == fmtPath && isHashed(h, comps) {
		fs.mu.Lock()
		fs.addAliasLocked(string(h), p)
		fs.mu.Unlock()
	}
	return h
}

// isHashed reports whether the fmtPath handle h for comps has hashed
// components.
func isHashed(h nfsv4.FileHandle, comps []string) bool {
	n := 1
	for _, c := range comps {
		n += 1 + len(c)
	}
	return len(h) != n
}

func (fs *FS) tableHandle(p string) nfsv4.FileHandle {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	// Reuse an existing ID for p, if any, so handles stay stable for
	// the life of the process.
	if id, ok := fs.tableIDLocked(p); ok {
		return fs.encodeTable(id)
	}
	fs.nextID++
	id := fs.nextID
	fs.table[id] = p
	return fs.encodeTable(id)
}

func (fs *FS) tableIDLocked(p string) (uint64, bool) {
	// Table handles are rare (only for absurdly deep paths), so a
	// linear scan is fine.
	for id, tp := range fs.table {
		if tp == p {
			return id, true
		}
	}
	return 0, false
}

func (fs *FS) encodeTable(id uint64) nfsv4.FileHandle {
	h := make(nfsv4.FileHandle, 0, 17)
	h = append(h, fmtTable)
	h = append(h, fs.instance[:]...)
	return binary.BigEndian.AppendUint64(h, id)
}

func (fs *FS) addAliasLocked(h, p string) {
	if _, ok := fs.byAlias[h]; ok {
		return
	}
	fs.byAlias[h] = p
	fs.aliases.PushBack(h)
	for fs.aliases.Len() > fs.opts.MaxCachedNodes {
		old := fs.aliases.Remove(fs.aliases.Front()).(string)
		delete(fs.byAlias, old)
	}
}

// cacheGet returns the cached node for path p.
func (fs *FS) cacheGet(p string) (Node, bool) {
	if p == "" {
		return fs.root, true
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	el, ok := fs.byPath[p]
	if !ok {
		return nil, false
	}
	fs.lru.MoveToFront(el)
	return el.Value.(*entry).node, true
}

func (fs *FS) cachePut(p string, n Node) {
	if p == "" {
		return
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if el, ok := fs.byPath[p]; ok {
		el.Value.(*entry).node = n
		fs.lru.MoveToFront(el)
		return
	}
	fs.byPath[p] = fs.lru.PushFront(&entry{path: p, node: n})
	for fs.lru.Len() > fs.opts.MaxCachedNodes {
		old := fs.lru.Remove(fs.lru.Back()).(*entry)
		delete(fs.byPath, old.path)
	}
}

// Forget drops the cached nodes for path p and everything below it, so
// they're looked up again from their parent directories when next used.
func (fs *FS) Forget(p string) {
	p = cleanPath(p)
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if p == "" {
		fs.byPath = make(map[string]*list.Element)
		fs.lru.Init()
		return
	}
	prefix := p + "/"
	for k, el := range fs.byPath {
		if k == p || (len(k) > len(prefix) && k[:len(prefix)] == prefix) {
			fs.lru.Remove(el)
			delete(fs.byPath, k)
		}
	}
}

// Recall recalls client delegations for the objects at paths with
// srv.Recall, before they're changed. The returned release function
// forgets the cached nodes for paths (see Forget) and allows delegations
// again; call it after making the changes. See nfsv4.Server.Recall.
//
// When adding or removing directory entries, include the directory's
// path.
func (fs *FS) Recall(ctx context.Context, srv *nfsv4.Server, paths ...string) (release func(), err error) {
	fhs := make([]nfsv4.FileHandle, len(paths))
	for i, p := range paths {
		fhs[i] = fs.Handle(p)
	}
	srvRelease, err := srv.Recall(ctx, fhs...)
	if err != nil {
		return nil, err
	}
	return func() {
		for _, p := range paths {
			fs.Forget(p)
		}
		srvRelease()
	}, nil
}

// resolve returns the path and node for filehandle h.
func (fs *FS) resolve(r *nfsv4.Request, h nfsv4.FileHandle) (string, Node, error) {
	if len(h) == 0 {
		return "", nil, nfsv4.ErrBadHandle
	}
	switch h[0] {
	case fmtRoot:
		if len(h) != 1 {
			return "", nil, nfsv4.ErrBadHandle
		}
		return "", fs.root, nil
	case fmtTable:
		// Table handles are volatile: they're only valid in the
		// process that created them.
		if len(h) != 17 || [8]byte(h[1:9]) != fs.instance {
			return "", nil, nfsv4.ErrStale
		}
		fs.mu.Lock()
		p, ok := fs.table[binary.BigEndian.Uint64(h[9:])]
		fs.mu.Unlock()
		if !ok {
			return "", nil, nfsv4.ErrStale
		}
		n, err := fs.walk(r, p)
		return p, n, err
	case fmtPath:
	default:
		return "", nil, nfsv4.ErrBadHandle
	}

	// Handles with hashed components are remembered for a while, to
	// avoid searching for them.
	fs.mu.Lock()
	p, ok := fs.byAlias[string(h)]
	fs.mu.Unlock()
	if ok {
		n, err := fs.walk(r, p)
		return p, n, err
	}
	comps, fullHash, err := decodePath(h)
	if err != nil {
		return "", nil, nfsv4.ErrBadHandle
	}
	hashed := false
	names := make([]string, 0, len(comps))
	for _, c := range comps {
		if c.hashed {
			hashed = true
			break
		}
		names = append(names, c.name)
	}
	if !hashed {
		p := joinPath(names)
		if !bytes.Equal(encodePath(p, names), h) {
			// Not the canonical encoding of p (for instance, a
			// short path with a full-path hash appended).
			return "", nil, nfsv4.ErrBadHandle
		}
		n, err := fs.walk(r, p)
		return p, n, err
	}
	p, n, err := fs.findHashed(r, joinPath(names), comps[len(names):], fullHash)
	if err != nil {
		return "", nil, err
	}
	if !bytes.Equal(encodePath(p, splitPath(p)), h) {
		return "", nil, nfsv4.ErrBadHandle
	}
	fs.mu.Lock()
	fs.addAliasLocked(string(h), p)
	fs.mu.Unlock()
	return p, n, nil
}

func joinPath(names []string) string {
	p := ""
	for i, n := range names {
		if i > 0 {
			p += "/"
		}
		p += n
	}
	return p
}

// walk returns the node at path p, looking up components from the
// deepest cached ancestor.
func (fs *FS) walk(r *nfsv4.Request, p string) (Node, error) {
	if n, ok := fs.cacheGet(p); ok {
		return n, nil
	}
	parent, name := path.Split(p)
	parent = trimSlash(parent)
	if !validName(name) {
		return nil, nfsv4.ErrBadHandle
	}
	pn, err := fs.walk(r, parent)
	if err != nil {
		return nil, err
	}
	d, ok := pn.(Dir)
	if !ok {
		return nil, nfsv4.ErrStale
	}
	n, err := d.Lookup(r, name)
	if err != nil {
		if isNotExist(err) {
			return nil, nfsv4.ErrStale
		}
		return nil, err
	}
	if n == nil {
		return nil, nfsv4.ErrStale
	}
	fs.cachePut(p, n)
	return n, nil
}

func trimSlash(p string) string {
	if len(p) > 0 && p[len(p)-1] == '/' {
		return p[:len(p)-1]
	}
	return p
}

// findHashed resolves the hashed components rest below the directory at
// prefix by listing directories and matching name hashes, trying every
// candidate when hashes collide, and checking the full path hash.
func (fs *FS) findHashed(r *nfsv4.Request, prefix string, rest []pathComp, fullHash uint64) (string, Node, error) {
	dn, err := fs.walk(r, prefix)
	if err != nil {
		return "", nil, err
	}
	if len(rest) == 0 {
		if pathHash(prefix) != fullHash {
			return "", nil, nfsv4.ErrStale
		}
		return prefix, dn, nil
	}
	d, ok := dn.(Dir)
	if !ok {
		return "", nil, nfsv4.ErrStale
	}
	ents, err := d.ReadDir(r)
	if err != nil {
		return "", nil, nfsv4.ErrStale
	}
	for _, ent := range ents {
		if compHash(ent.Name) != rest[0].hash || !validName(ent.Name) {
			continue
		}
		cp := ent.Name
		if prefix != "" {
			cp = prefix + "/" + ent.Name
		}
		if ent.Node != nil {
			fs.cachePut(cp, ent.Node)
		}
		if p, n, err := fs.findHashed(r, cp, rest[1:], fullHash); err == nil {
			return p, n, nil
		}
	}
	return "", nil, nfsv4.ErrStale
}

func childPath(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

// Root implements nfsv4.FS.
func (fs *FS) Root(r *nfsv4.Request) (nfsv4.FileHandle, error) {
	return rootHandle, nil
}

// attrs returns n's attributes, filling in a FileID if needed.
func attrs(r *nfsv4.Request, p string, n Node) (*nfsv4.Attrs, error) {
	a, err := n.Attr(r)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, errors.New("nodefs: Node.Attr returned nil")
	}
	if a.FileID == 0 {
		b := *a
		b.FileID = fileID(p)
		a = &b
	}
	return a, nil
}

// fileID derives a FileID from a path.
func fileID(p string) uint64 {
	if p == "" {
		return 1
	}
	id := pathHash("/" + p)
	if id <= 1 {
		id += 2
	}
	return id
}

// GetAttr implements nfsv4.FS.
func (fs *FS) GetAttr(r *nfsv4.Request, h nfsv4.FileHandle, want nfsv4.AttrMask) (*nfsv4.Attrs, error) {
	p, n, err := fs.resolve(r, h)
	if err != nil {
		return nil, err
	}
	return attrs(r, p, n)
}

// Lookup implements nfsv4.FS.
func (fs *FS) Lookup(r *nfsv4.Request, dir nfsv4.FileHandle, name string) (nfsv4.FileHandle, *nfsv4.Attrs, error) {
	dp, dn, err := fs.resolve(r, dir)
	if err != nil {
		return nil, nil, err
	}
	d, ok := dn.(Dir)
	if !ok {
		if _, ok := dn.(Symlink); ok {
			return nil, nil, nfsv4.ErrSymlink
		}
		return nil, nil, nfsv4.ErrNotDir
	}
	n, err := d.Lookup(r, name)
	if err != nil {
		if isNotExist(err) {
			return nil, nil, nfsv4.ErrNoEnt
		}
		return nil, nil, err
	}
	if n == nil {
		return nil, nil, nfsv4.ErrNoEnt
	}
	cp := childPath(dp, name)
	fs.cachePut(cp, n)
	return fs.handleFor(cp), nil, nil
}

// LookupParent implements nfsv4.FS.
func (fs *FS) LookupParent(r *nfsv4.Request, dir nfsv4.FileHandle) (nfsv4.FileHandle, error) {
	p, _, err := fs.resolve(r, dir)
	if err != nil {
		return nil, err
	}
	parent, _ := path.Split(p)
	return fs.handleFor(trimSlash(parent)), nil
}

// ReadDir implements nfsv4.FS. Cookies are positions in the listing
// returned by Dir.ReadDir.
func (fs *FS) ReadDir(r *nfsv4.Request, dir nfsv4.FileHandle, args nfsv4.ReadDirArgs, emit func(nfsv4.DirEntry) bool) (nfsv4.ReadDirResult, error) {
	dp, dn, err := fs.resolve(r, dir)
	if err != nil {
		return nfsv4.ReadDirResult{}, err
	}
	d, ok := dn.(Dir)
	if !ok {
		return nfsv4.ReadDirResult{}, nfsv4.ErrNotDir
	}
	ents, err := d.ReadDir(r)
	if err != nil {
		return nfsv4.ReadDirResult{}, err
	}
	start := 0
	if args.Cookie != 0 {
		// The cookie for entry i is i+3, so resume at Cookie-2.
		if args.Cookie < 3 || args.Cookie-2 > uint64(len(ents)) {
			return nfsv4.ReadDirResult{}, nfsv4.ErrBadCookie
		}
		start = int(args.Cookie - 2)
	}
	wantAttrs := !args.Want.IsEmpty()
	for i := start; i < len(ents); i++ {
		ent := ents[i]
		cp := childPath(dp, ent.Name)
		de := nfsv4.DirEntry{
			Name:   ent.Name,
			Cookie: uint64(i) + 3,
		}
		if wantAttrs {
			n := ent.Node
			if n == nil {
				n, err = d.Lookup(r, ent.Name)
				if err != nil || n == nil {
					// The entry vanished; skip it.
					continue
				}
			}
			fs.cachePut(cp, n)
			a, err := attrs(r, cp, n)
			if err != nil {
				return nfsv4.ReadDirResult{}, err
			}
			de.Handle = fs.handleFor(cp)
			de.Attrs = a
		} else if ent.Node != nil {
			fs.cachePut(cp, ent.Node)
		}
		if !emit(de) {
			break
		}
	}
	return nfsv4.ReadDirResult{}, nil
}

// Read implements nfsv4.FS.
func (fs *FS) Read(r *nfsv4.Request, h nfsv4.FileHandle, off uint64, p []byte) (int, bool, error) {
	_, n, err := fs.resolve(r, h)
	if err != nil {
		return 0, false, err
	}
	f, ok := n.(File)
	if !ok {
		if _, ok := n.(Dir); ok {
			return 0, false, nfsv4.ErrIsDir
		}
		return 0, false, nfsv4.ErrInval
	}
	if off > 1<<63-1 {
		return 0, true, nil
	}
	got, err := f.ReadAt(r, p, int64(off))
	if err == io.EOF {
		return got, true, nil
	}
	if err != nil {
		return 0, false, err
	}
	return got, false, nil
}

// ReadLink implements nfsv4.FS.
func (fs *FS) ReadLink(r *nfsv4.Request, h nfsv4.FileHandle) (string, error) {
	_, n, err := fs.resolve(r, h)
	if err != nil {
		return "", err
	}
	l, ok := n.(Symlink)
	if !ok {
		if _, ok := n.(Dir); ok {
			return "", nfsv4.ErrIsDir
		}
		return "", nfsv4.ErrInval
	}
	return l.Readlink(r)
}

// Delegate implements nfsv4.Delegator.
func (fs *FS) Delegate(r *nfsv4.Request, h nfsv4.FileHandle, a *nfsv4.Attrs) nfsv4.Delegation {
	_, n, err := fs.resolve(r, h)
	if err != nil {
		return nfsv4.Delegation{}
	}
	if cc, ok := n.(CacheController); ok {
		return cc.CachePolicy(r)
	}
	return fs.opts.DefaultCache
}

// StatFS implements nfsv4.StatFSer.
func (fs *FS) StatFS(r *nfsv4.Request, h nfsv4.FileHandle) (*nfsv4.FSStat, error) {
	if fs.opts.StatFS == nil {
		return &nfsv4.FSStat{}, nil
	}
	return fs.opts.StatFS(r)
}

func isNotExist(err error) bool {
	return errors.Is(err, iofs.ErrNotExist) || errors.Is(err, nfsv4.ErrNoEnt)
}
