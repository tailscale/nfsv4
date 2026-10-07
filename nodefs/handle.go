// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nodefs

import (
	"encoding/binary"
	"errors"
	"hash/fnv"
	"strings"

	"github.com/tailscale/nfsv4"
)

// Filehandle formats. The first byte of every filehandle is its format.
const (
	fmtRoot  = 0x01 // the root: just the format byte
	fmtPath  = 0x02 // path components, verbatim then hashed
	fmtTable = 0x03 // an ID in the in-memory handle table
)

// Within a fmtPath handle, a verbatim component is a length byte (1-255)
// followed by the name. A hashed component is a zero byte followed by the
// 4-byte hash of the name. If any component is hashed, the handle ends
// with an 8-byte hash of the whole path, to keep handles unique despite
// collisions of the 4-byte component hashes.
const (
	hashMarker   = 0x00
	compHashLen  = 4
	pathHashLen  = 8
	maxHandleLen = nfsv4.MaxFileHandleSize
)

var rootHandle = nfsv4.FileHandle{fmtRoot}

func compHash(name string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(name))
	return h.Sum32()
}

func pathHash(p string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(p))
	return h.Sum64()
}

// splitPath splits a slash-separated relative path into components. The
// root is "".
func splitPath(p string) []string {
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// encodePath returns the filehandle for the relative path p (with
// components comps), or nil if p is too deep to encode, in which case a
// table handle must be used.
func encodePath(p string, comps []string) nfsv4.FileHandle {
	if len(comps) == 0 {
		return rootHandle
	}
	// Fully verbatim, if it fits.
	n := 1
	for _, c := range comps {
		n += 1 + len(c)
	}
	if n <= maxHandleLen {
		h := make(nfsv4.FileHandle, 0, n)
		h = append(h, fmtPath)
		for _, c := range comps {
			h = append(h, byte(len(c)))
			h = append(h, c...)
		}
		return h
	}
	// Otherwise, as many leading components verbatim as possible, then
	// hashes for the rest, then the full path hash.
	budget := maxHandleLen - 1 - pathHashLen
	k := 0 // number of verbatim components
	used := 0
	for k < len(comps) {
		next := used + 1 + len(comps[k])
		if next+(len(comps)-k-1)*(1+compHashLen) > budget {
			break
		}
		used = next
		k++
	}
	if used+(len(comps)-k)*(1+compHashLen) > budget {
		return nil
	}
	h := make(nfsv4.FileHandle, 0, maxHandleLen)
	h = append(h, fmtPath)
	for _, c := range comps[:k] {
		h = append(h, byte(len(c)))
		h = append(h, c...)
	}
	for _, c := range comps[k:] {
		h = append(h, hashMarker)
		h = binary.BigEndian.AppendUint32(h, compHash(c))
	}
	h = binary.BigEndian.AppendUint64(h, pathHash(p))
	return h
}

// pathComp is a decoded component of a fmtPath handle: a name, or the
// hash of a name if hashed is set.
type pathComp struct {
	name   string
	hash   uint32
	hashed bool
}

var errBadHandle = errors.New("bad handle")

// decodePath decodes a fmtPath handle into its components and, if any
// are hashed, the full path hash.
func decodePath(h nfsv4.FileHandle) (comps []pathComp, fullHash uint64, err error) {
	if len(h) < 2 || h[0] != fmtPath {
		return nil, 0, errBadHandle
	}
	b := h[1:]
	hashed := false
	for len(b) > 0 {
		if hashed && len(b) == pathHashLen {
			return comps, binary.BigEndian.Uint64(b), nil
		}
		l := int(b[0])
		b = b[1:]
		if l == hashMarker {
			if len(b) < compHashLen {
				return nil, 0, errBadHandle
			}
			comps = append(comps, pathComp{hash: binary.BigEndian.Uint32(b), hashed: true})
			b = b[compHashLen:]
			hashed = true
			continue
		}
		if hashed || len(b) < l {
			// Verbatim components never follow hashed ones.
			return nil, 0, errBadHandle
		}
		name := string(b[:l])
		if !validName(name) {
			return nil, 0, errBadHandle
		}
		comps = append(comps, pathComp{name: name})
		b = b[l:]
	}
	if hashed || len(comps) == 0 {
		return nil, 0, errBadHandle
	}
	return comps, 0, nil
}

// validName reports whether name is a valid path component: not empty,
// "." or "..", and without slashes or NULs. Handles are client-supplied, so
// this keeps crafted handles from escaping the tree.
func validName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}
