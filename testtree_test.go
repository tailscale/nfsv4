// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4_test

import (
	"fmt"

	"github.com/tailscale/nfsv4/internal/testfs"
)

func newTestTree() *testfs.FS {
	fs := testfs.New()
	fs.WriteFile("/hello.txt", []byte("hello, world\n"), 0o644)
	fs.WriteFile("/sub/dir/file.go", []byte("package x\n"), 0o444)
	fs.WriteFile("/sub/exec.sh", []byte("#!/bin/sh\necho hi\n"), 0o755)
	fs.Symlink("../hello.txt", "/sub/link")
	big := make([]byte, 5<<20+123)
	for i := range big {
		big[i] = byte(i * 7)
	}
	fs.WriteFile("/big.bin", big, 0o644)
	for i := range 300 {
		fs.WriteFile(fmt.Sprintf("/many/f%03d", i), []byte(fmt.Sprint(i)), 0o644)
	}
	return fs
}
