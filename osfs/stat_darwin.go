// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package osfs

import (
	"syscall"
	"time"

	"github.com/tailscale/nfsv4"
)

func statTimes(st *syscall.Stat_t) (atime, ctime time.Time) {
	return timespec(st.Atimespec), timespec(st.Ctimespec)
}

func rawDev(rdev uint64) nfsv4.Device {
	return nfsv4.Device{Major: uint32(rdev >> 24 & 0xff), Minor: uint32(rdev & 0xffffff)}
}
