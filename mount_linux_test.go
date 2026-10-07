// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4_test

import (
	"fmt"
)

const isDarwin = false

func mountArgs(port int, vers, opts, src, dir string) []string {
	o := fmt.Sprintf("vers=%s,port=%d,proto=tcp,ro,soft,timeo=50,retrans=2", vers, port)
	if opts != "" {
		o += "," + opts
	}
	return []string{"mount", "-t", "nfs4", "-o", o, src, dir}
}

func forceUnmount(dir string) {
	asRoot("umount", "-l", "-f", dir).Run()
}

// dropCaches drops the kernel's page cache.
func dropCaches() error {
	return asRoot("sh", "-c", "echo 3 > /proc/sys/vm/drop_caches").Run()
}

const umountCmd = "umount"

// dropPageCache drops the kernel's page cache, keeping cached dentries and
// inodes (and so the client's cached filehandles).
func dropPageCache() error {
	return asRoot("sh", "-c", "echo 1 > /proc/sys/vm/drop_caches").Run()
}
