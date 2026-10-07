// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package nfsv4_test

import (
	"flag"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/tailscale/nfsv4"
)

var mountTest = flag.Bool("mount", os.Getenv("NFSV4_MOUNT_TEST") != "", "run tests that mount the server with the kernel NFS client (requires root or passwordless sudo)")

// mountServer starts srv on a loopback port and mounts it with the kernel
// client using NFSv4 minor version vers ("4.1" or "4.2") and the given
// extra mount options. It returns the mount point. The mount is removed
// when the test ends.
func mountServer(t *testing.T, srv *nfsv4.Server, vers, opts string) string {
	t.Helper()
	skipUnlessMountTest(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return mountPort(t, ln.Addr().(*net.TCPAddr).Port, vers, opts)
}

// debugf returns a Server.Debugf func logging to t if $NFSV4_TEST_DEBUG is
// set, or else nil.
func debugf(t *testing.T) func(string, ...any) {
	if os.Getenv("NFSV4_TEST_DEBUG") == "" {
		return nil
	}
	return t.Logf
}

func skipUnlessMountTest(t *testing.T) {
	t.Helper()
	if !*mountTest {
		t.Skip("skipping kernel mount test without --mount or $NFSV4_MOUNT_TEST")
	}
	if os.Geteuid() != 0 {
		if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
			t.Skip("skipping kernel mount test: not root and passwordless sudo unavailable")
		}
	}
}

// asRoot returns a command running name with args as root.
func asRoot(name string, args ...string) *exec.Cmd {
	if os.Geteuid() == 0 {
		return exec.Command(name, args...)
	}
	return exec.Command("sudo", append([]string{"-n", name}, args...)...)
}

// mountPort mounts the NFS server on the given loopback port and returns
// the mount point, which is unmounted when the test ends.
func mountPort(t *testing.T, port int, vers, opts string) string {
	t.Helper()
	dir := t.TempDir()
	args := mountArgs(port, vers, opts, "127.0.0.1:/", dir)
	out, err := asRoot(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	t.Cleanup(func() { unmount(t, dir) })
	return dir
}

// isMounted reports whether something is mounted on dir.
func isMounted(dir string) bool {
	var st, pst syscall.Stat_t
	if syscall.Stat(dir, &st) != nil || syscall.Stat(filepath.Dir(dir), &pst) != nil {
		// A dead NFS mount may fail to stat; try unmounting.
		return true
	}
	return st.Dev != pst.Dev
}

// unmount unmounts dir if it's mounted.
func unmount(t *testing.T, dir string) {
	if !isMounted(dir) {
		return
	}
	out, err := asRoot(umountCmd, "-f", dir).CombinedOutput()
	if err != nil {
		t.Logf("umount: %v, %s", err, out)
		forceUnmount(dir)
	}
}

// supportedVersions are the NFSv4 minor versions the kernel client can
// mount.
func supportedVersions() []string {
	if isDarwin {
		return []string{"4.1"} // macOS doesn't do 4.2
	}
	return []string{"4.1", "4.2"}
}

// latestVersion is the newest NFSv4 minor version the kernel supports.
func latestVersion() string {
	v := supportedVersions()
	return v[len(v)-1]
}

func TestKernelMountBasics(t *testing.T) {
	for _, vers := range supportedVersions() {
		t.Run(vers, func(t *testing.T) {
			fs := newTestTree()
			srv := &nfsv4.Server{FS: fs, Logf: t.Logf}
			dir := mountServer(t, srv, vers, "")

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
