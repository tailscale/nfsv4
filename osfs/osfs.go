// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package osfs serves a local directory tree read-only, using nodefs.
// It's mostly an example and a testing tool.
package osfs

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/nodefs"
)

// Options are options for New.
type Options struct {
	// Immutable says the directory tree never changes while served, so
	// clients get delegations to cache everything forever.
	Immutable bool

	// Nodefs are options for the underlying nodefs.FS. Its DefaultCache
	// is overridden if Immutable is set.
	Nodefs nodefs.Options
}

// New returns an FS serving the directory dir.
func New(dir string, opts *Options) (*nodefs.FS, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, errors.New("osfs: not a directory: " + dir)
	}
	var o Options
	if opts != nil {
		o = *opts
	}
	if o.Immutable {
		o.Nodefs.DefaultCache = nfsv4.Delegation{Grant: true}
	}
	rootDev, _ := devIno(fi)
	if o.Nodefs.StatFS == nil {
		o.Nodefs.StatFS = func(r *nfsv4.Request) (*nfsv4.FSStat, error) { return statFS(dir) }
	}
	return nodefs.New(osDir{osNode{path: dir, rootDev: rootDev}}, &o.Nodefs), nil
}

type osNode struct {
	path    string
	rootDev uint64
}

type (
	osDir     struct{ osNode }
	osFile    struct{ osNode }
	osSymlink struct{ osNode }
)

func (n osNode) Attr(r *nfsv4.Request) (*nfsv4.Attrs, error) {
	fi, err := os.Lstat(n.path)
	if err != nil {
		return nil, err
	}
	return attrsOf(fi, n.rootDev), nil
}

func (n osNode) child(name string, fi fs.FileInfo) nodefs.Node {
	c := osNode{path: filepath.Join(n.path, name), rootDev: n.rootDev}
	switch {
	case fi.IsDir():
		return osDir{c}
	case fi.Mode().IsRegular():
		return osFile{c}
	case fi.Mode()&fs.ModeSymlink != 0:
		return osSymlink{c}
	}
	return c
}

func (d osDir) Lookup(r *nfsv4.Request, name string) (nodefs.Node, error) {
	fi, err := os.Lstat(filepath.Join(d.path, name))
	if err != nil {
		return nil, err
	}
	return d.child(name, fi), nil
}

func (d osDir) ReadDir(r *nfsv4.Request) ([]nodefs.DirEntry, error) {
	des, err := os.ReadDir(d.path)
	if err != nil {
		return nil, err
	}
	ents := make([]nodefs.DirEntry, len(des))
	for i, de := range des {
		ents[i] = nodefs.DirEntry{Name: de.Name()}
	}
	return ents, nil
}

func (f osFile) ReadAt(r *nfsv4.Request, p []byte, off int64) (int, error) {
	fh, err := os.Open(f.path)
	if err != nil {
		return 0, err
	}
	defer fh.Close()
	n, err := fh.ReadAt(p, off)
	if err == nil && n == len(p) {
		// See if that was the end, so the client doesn't need another
		// round trip to find out.
		if fi, serr := fh.Stat(); serr == nil && off+int64(n) >= fi.Size() {
			err = io.EOF
		}
	}
	return n, err
}

func (s osSymlink) Readlink(r *nfsv4.Request) (string, error) {
	return os.Readlink(s.path)
}
