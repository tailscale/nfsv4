// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package osfs

import (
	"syscall"
	"time"

	"github.com/tailscale/nfsv4"
)

func statTimes(st *syscall.Stat_t) (atime, ctime time.Time) {
	return timespec(st.Atim), timespec(st.Ctim)
}

func rawDev(rdev uint64) nfsv4.Device {
	return nfsv4.Device{
		Major: uint32((rdev>>8)&0xfff | (rdev>>32)&^0xfff),
		Minor: uint32(rdev&0xff | (rdev>>12)&^0xff),
	}
}
