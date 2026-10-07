// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4_test

import "fmt"

const isDarwin = true

func mountArgs(port int, vers, opts, src, dir string) []string {
	// nobrowse keeps Finder and Spotlight away from the mount. The
	// macOS client rejects soft NFSv4 mounts with EINVAL.
	o := fmt.Sprintf("vers=%s,port=%d,rdonly,timeo=50,retrans=2,nobrowse,rsize=1048576", vers, port)
	if opts != "" {
		o += "," + opts
	}
	return []string{"/sbin/mount", "-t", "nfs", "-o", o, src, dir}
}

func forceUnmount(dir string) {
	asRoot("/usr/sbin/diskutil", "unmount", "force", dir).Run()
}

// dropCaches drops the kernel's buffer cache.
func dropCaches() error {
	return asRoot("/usr/sbin/purge").Run()
}

const umountCmd = "/sbin/umount"

// dropPageCache drops the kernel's buffer cache.
func dropPageCache() error { return dropCaches() }
