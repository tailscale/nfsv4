// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !darwin

package osfs

import (
	"io/fs"

	"github.com/tailscale/nfsv4"
)

func devIno(fi fs.FileInfo) (dev, ino uint64) { return 0, 0 }

func attrsOf(fi fs.FileInfo, rootDev uint64) *nfsv4.Attrs {
	a := &nfsv4.Attrs{
		Mode:    uint32(fi.Mode().Perm()),
		Size:    uint64(fi.Size()),
		ModTime: fi.ModTime(),
		Change:  uint64(fi.ModTime().UnixNano()),
	}
	switch m := fi.Mode(); {
	case m.IsDir():
		a.Type = nfsv4.TypeDir
	case m&fs.ModeSymlink != 0:
		a.Type = nfsv4.TypeSymlink
	default:
		a.Type = nfsv4.TypeReg
	}
	return a
}

func statFS(dir string) (*nfsv4.FSStat, error) { return &nfsv4.FSStat{}, nil }
