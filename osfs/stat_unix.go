// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package osfs

import (
	"io/fs"
	"syscall"
	"time"

	"github.com/tailscale/nfsv4"
)

func devIno(fi fs.FileInfo) (dev, ino uint64) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0
	}
	return uint64(st.Dev), uint64(st.Ino)
}

func attrsOf(fi fs.FileInfo, rootDev uint64) *nfsv4.Attrs {
	a := &nfsv4.Attrs{
		Mode:    uint32(fi.Mode().Perm()),
		Size:    uint64(fi.Size()),
		ModTime: fi.ModTime(),
	}
	m := fi.Mode()
	switch {
	case m.IsDir():
		a.Type = nfsv4.TypeDir
	case m.IsRegular():
		a.Type = nfsv4.TypeReg
	case m&fs.ModeSymlink != 0:
		a.Type = nfsv4.TypeSymlink
	case m&fs.ModeNamedPipe != 0:
		a.Type = nfsv4.TypeFIFO
	case m&fs.ModeSocket != 0:
		a.Type = nfsv4.TypeSocket
	case m&fs.ModeCharDevice != 0:
		a.Type = nfsv4.TypeChar
	case m&fs.ModeDevice != 0:
		a.Type = nfsv4.TypeBlock
	default:
		a.Type = nfsv4.TypeReg
	}
	if m&fs.ModeSetuid != 0 {
		a.Mode |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		a.Mode |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		a.Mode |= 0o1000
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return a
	}
	a.UID = st.Uid
	a.GID = st.Gid
	a.NumLinks = uint32(st.Nlink)
	a.SpaceUsed = uint64(st.Blocks) * 512
	a.FileID = uint64(st.Ino)
	if uint64(st.Dev) != rootDev {
		// A different filesystem mounted below the root. Keep FileIDs
		// distinct from the root filesystem's.
		a.FileID ^= uint64(st.Dev) << 40
	}
	a.RawDev = rawDev(uint64(st.Rdev))
	atime, ctime := statTimes(st)
	a.AccessTime = atime
	a.ChangeTime = ctime
	// The ctime changes whenever the contents or attributes change.
	a.Change = uint64(ctime.UnixNano())
	return a
}

func timespec(ts syscall.Timespec) time.Time {
	return time.Unix(int64(ts.Sec), int64(ts.Nsec))
}

func statFS(dir string) (*nfsv4.FSStat, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return nil, err
	}
	bs := uint64(st.Bsize)
	return &nfsv4.FSStat{
		SpaceTotal: uint64(st.Blocks) * bs,
		SpaceFree:  uint64(st.Bfree) * bs,
		SpaceAvail: uint64(st.Bavail) * bs,
		FilesTotal: uint64(st.Files),
		FilesFree:  uint64(st.Ffree),
		FilesAvail: uint64(st.Ffree),
	}, nil
}
