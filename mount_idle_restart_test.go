// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package nfsv4_test

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/internal/testfs"
	"github.com/tailscale/nfsv4/memfs"
)

const idleDeep = "deep/l1/l2/l3/l4/l5/l6/l7/l8"

var idleFiles = map[string]string{
	idleDeep + "/seen.txt":          "seen before the restart\n",
	idleDeep + "/unseen.txt":        "never looked at before the restart\n",
	"deep/l1/l2/l3/l4/side/new.txt": "in a directory never visited before the restart\n",
	"deep/l1/l2/l3/l4/other.txt":    "next to a directory visited before the restart\n",
}

// TestKernelIdleServerRestart checks that an idle client recovers when the
// server restarts, including when the restarted server's filehandles are
// all different (except the root's), so the client must notice its cached
// filehandles are stale and look everything up again.
func TestKernelIdleServerRestart(t *testing.T) {
	type instance struct {
		fs        nfsv4.FS
		staleHits func() int64
	}
	newRaw := func(gen uint64) instance {
		fs := testfs.New()
		fs.Gen = gen
		// Create files in a fixed order, so inode numbers (and so
		// filehandles, with gen 0) are the same in every instance.
		for _, p := range slices.Sorted(maps.Keys(idleFiles)) {
			fs.WriteFile("/"+p, []byte(idleFiles[p]), 0o444)
		}
		fs.DelegatePolicy = func(string, *nfsv4.Attrs) nfsv4.Delegation { return nfsv4.Delegation{Grant: true} }
		return instance{fs.WithDelegator(), fs.StaleHits.Load}
	}
	newNodefs := func(uint64) instance {
		m := memfs.New()
		for p, c := range idleFiles {
			m.WriteFile(p, []byte(c), 0o444)
		}
		m.SetImmutable("")
		return instance{m, func() int64 { return 0 }}
	}
	for _, tt := range []struct {
		name     string
		newFS    func(gen uint64) instance
		volatile bool
	}{
		{"stable-raw", func(uint64) instance { return newRaw(0) }, false},
		{"volatile-raw", newRaw, true},
		{"nodefs", newNodefs, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			skipUnlessMountTest(t)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := ln.Addr().(*net.TCPAddr).Port
			// A short lease, so the client's lease heartbeats fail
			// while the server is down.
			const lease = 5 * time.Second
			fs1 := tt.newFS(1)
			srv1 := &nfsv4.Server{FS: fs1.fs, Logf: t.Logf, LeaseTime: lease}
			go srv1.Serve(ln)
			dir := mountPort(t, port, latestVersion(), "actimeo=2")

			// Reach deep into the tree.
			mustRead(t, dir, idleDeep+"/seen.txt")
			mustList(t, dir, idleDeep, "seen.txt", "unseen.txt")
			mustList(t, dir, "deep/l1/l2/l3/l4", "l5", "other.txt", "side")

			// Restart the server while the client is idle, staying
			// down for longer than the lease time.
			time.Sleep(time.Second)
			srv1.Close()
			time.Sleep(lease + 3*time.Second)
			var ln2 net.Listener
			for range 50 {
				ln2, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
				if err == nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if err != nil {
				t.Fatal(err)
			}
			fs2 := tt.newFS(2)
			srv2 := &nfsv4.Server{FS: fs2.fs, Logf: t.Logf, LeaseTime: lease, Debugf: debugf(t)}
			go srv2.Serve(ln2)
			// Let the client idle a bit with the new server, past its
			// attribute cache timeout.
			time.Sleep(3 * time.Second)
			if err := dropPageCache(); err != nil {
				t.Logf("dropping page cache: %v", err)
			}

			// Read things seen before the restart and things never
			// seen, deep in directories visited before the restart.
			//
			// With volatile filehandles, the macOS client (unlike
			// Linux's) passes the first ESTALE to the application
			// before purging its caches and looking names up again,
			// so allow one there.
			allowStale := tt.volatile && isDarwin
			for _, p := range []string{
				idleDeep + "/seen.txt",
				idleDeep + "/unseen.txt",
				"deep/l1/l2/l3/l4/other.txt",
				"deep/l1/l2/l3/l4/side/new.txt",
			} {
				if allowStale {
					if _, err := os.ReadFile(dir + "/" + p); errors.Is(err, syscall.ESTALE) {
						t.Logf("ReadFile(%s): %v (expected once on macOS)", p, err)
						allowStale = false
					}
				}
				mustRead(t, dir, p)
			}
			mustList(t, dir, idleDeep, "seen.txt", "unseen.txt")

			st := srv2.Stats()
			stale := fs2.staleHits()
			t.Logf("new server: %d uses of stale filehandles; ops: %v", stale, st.Ops)
			if tt.volatile && stale == 0 {
				t.Errorf("the client never used a stale filehandle; the test didn't test re-resolution")
			}
			if !tt.volatile && stale != 0 {
				t.Errorf("%d stale filehandle uses with stable filehandles", stale)
			}
			unmount(t, dir)
			srv2.Close()
		})
	}
}

func mustRead(t *testing.T, dir, p string) {
	t.Helper()
	got, err := os.ReadFile(dir + "/" + p)
	if err != nil {
		t.Errorf("ReadFile(%s): %v", p, err)
		return
	}
	if string(got) != idleFiles[p] {
		t.Errorf("ReadFile(%s) = %q; want %q", p, got, idleFiles[p])
	}
}

func mustList(t *testing.T, dir, p string, want ...string) {
	t.Helper()
	ents, err := os.ReadDir(dir + "/" + p)
	if err != nil {
		t.Errorf("ReadDir(%s): %v", p, err)
		return
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("ReadDir(%s) = %q; want %q", p, names, want)
	}
}
