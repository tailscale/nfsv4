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
)

var mountTest = flag.Bool("mount", os.Getenv("NFSV4_MOUNT_TEST") != "", "run tests that mount the server with the kernel NFS client (requires passwordless sudo)")

// mountServer starts srv on a loopback port and mounts it with the kernel
// client using the given extra mount options. It returns the mount
// point. The mount is removed when the test ends.
func mountServer(t *testing.T, srv *nfsv4.Server, opts string) string {
	t.Helper()
	skipUnlessMountTest(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return mountPort(t, ln.Addr().(*net.TCPAddr).Port, opts)
}

func skipUnlessMountTest(t *testing.T) {
	t.Helper()
	if !*mountTest {
		t.Skip("skipping kernel mount test without --mount or $NFSV4_MOUNT_TEST")
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skip("skipping kernel mount test: passwordless sudo unavailable")
	}
}

// mountPort mounts the NFS server on the given loopback port and returns
// the mount point, which is unmounted when the test ends.
func mountPort(t *testing.T, port int, opts string) string {
	t.Helper()
	dir := t.TempDir()
	o := fmt.Sprintf("port=%d,proto=tcp,ro,soft,timeo=50,retrans=2", port)
	if opts != "" {
		o += "," + opts
	}
	out, err := exec.Command("sudo", "-n", "mount", "-t", "nfs4", "-o", o, "127.0.0.1:/", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("mount: %v\n%s", err, out)
	}
	t.Cleanup(func() { unmount(t, dir) })
	return dir
}

// unmount unmounts dir if it's mounted.
func unmount(t *testing.T, dir string) {
	if exec.Command("mountpoint", "-q", dir).Run() != nil {
		return
	}
	out, err := exec.Command("sudo", "-n", "umount", "-f", dir).CombinedOutput()
	if err != nil {
		t.Logf("umount: %v, %s; trying lazy unmount", err, out)
		exec.Command("sudo", "-n", "umount", "-l", "-f", dir).Run()
	}
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
