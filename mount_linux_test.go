// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4_test

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/internal/testfs"
)

var mountTest = flag.Bool("mount", os.Getenv("NFSV4_MOUNT_TEST") != "", "run tests that mount the server with the kernel NFS client (requires passwordless sudo)")

// mountServer starts srv on a loopback port and mounts it with the kernel
// client using the given extra mount options. It returns the mount
// point. The mount is removed when the test ends.
func mountServer(t *testing.T, srv *nfsv4.Server, opts string) string {
	t.Helper()
	if !*mountTest {
		t.Skip("skipping kernel mount test without --mount or $NFSV4_MOUNT_TEST")
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skip("skipping kernel mount test: passwordless sudo unavailable")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	dir := t.TempDir()
	port := ln.Addr().(*net.TCPAddr).Port
	o := fmt.Sprintf("port=%d,proto=tcp,ro,soft,timeo=50,retrans=2", port)
	if opts != "" {
		o += "," + opts
	}
	out, err := exec.Command("sudo", "-n", "mount", "-t", "nfs4", "-o", o, "127.0.0.1:/", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("mount: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		out, err := exec.Command("sudo", "-n", "umount", "-f", dir).CombinedOutput()
		if err != nil {
			t.Logf("umount: %v, %s; trying lazy unmount", err, out)
			exec.Command("sudo", "-n", "umount", "-l", "-f", dir).Run()
		}
	})
	return dir
}

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

func TestKernelMountBasics(t *testing.T) {
	for _, vers := range []string{"4.1", "4.2"} {
		t.Run(vers, func(t *testing.T) {
			fs := newTestTree()
			srv := &nfsv4.Server{FS: fs, Logf: t.Logf}
			dir := mountServer(t, srv, "vers="+vers)

			got, err := os.ReadFile(dir + "/hello.txt")
			if err != nil || string(got) != "hello, world\n" {
				t.Fatalf("ReadFile = %q, %v", got, err)
			}
			got, err = os.ReadFile(dir + "/sub/link")
			if err != nil || string(got) != "hello, world\n" {
				t.Errorf("ReadFile via symlink = %q, %v", got, err)
			}
			target, err := os.Readlink(dir + "/sub/link")
			if err != nil || target != "../hello.txt" {
				t.Errorf("Readlink = %q, %v", target, err)
			}
			fi, err := os.Stat(dir + "/sub/exec.sh")
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o755 || fi.Size() != 18 {
				t.Errorf("stat exec.sh = %v, %v", fi.Mode(), fi.Size())
			}
			ents, err := os.ReadDir(dir + "/many")
			if err != nil || len(ents) != 300 {
				t.Errorf("ReadDir(many) = %d entries, %v", len(ents), err)
			}
			big, err := os.ReadFile(dir + "/big.bin")
			if err != nil || len(big) != 5<<20+123 {
				t.Fatalf("ReadFile(big) = %d, %v", len(big), err)
			}
			for i := range big {
				if big[i] != byte(i*7) {
					t.Fatalf("big.bin mismatch at %d", i)
				}
			}
			out, err := exec.Command(dir + "/sub/exec.sh").CombinedOutput()
			if err != nil || strings.TrimSpace(string(out)) != "hi" {
				t.Errorf("exec = %q, %v", out, err)
			}
			if err := os.WriteFile(dir+"/new", []byte("x"), 0o644); err == nil {
				t.Errorf("unexpected write success")
			}
			t.Logf("stats: %+v", srv.Stats())
		})
	}
}

var _ = time.Second
