// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/nfsv4"
)

func TestKernelDelegations(t *testing.T) {
	fs := newTestTree()
	fs.WriteFile("/live/data.txt", []byte("version 1\n"), 0o644)
	fs.DelegatePolicy = func(path string, a *nfsv4.Attrs) nfsv4.Delegation {
		return nfsv4.Delegation{Grant: true}
	}
	srv := &nfsv4.Server{FS: fs.WithDelegator(), Logf: t.Logf}
	// actimeo=1 makes the client revalidate undelegated objects after a
	// second, so we can tell delegations are working.
	dir := mountServer(t, srv, "4.2", "actimeo=1")

	// Open and read files, and list directories, to get delegations.
	for _, p := range []string{"/hello.txt", "/sub/dir/file.go", "/live/data.txt"} {
		if _, err := os.ReadFile(dir + p); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"/", "/sub", "/sub/dir", "/many", "/live"} {
		if _, err := os.ReadDir(dir + p); err != nil {
			t.Fatal(err)
		}
	}
	// Stat again so the client revalidates directories and asks for
	// directory delegations (Linux requests them on GETATTR after
	// ACCESS).
	for _, p := range []string{"/sub", "/sub/dir", "/many", "/live"} {
		if _, err := os.Stat(dir + p); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(1500 * time.Millisecond)
	for _, p := range []string{"/sub", "/sub/dir", "/many", "/live", "/hello.txt"} {
		os.Stat(dir + p)
		os.ReadDir(dir + p)
	}
	st := srv.Stats()
	t.Logf("after warmup: %+v", st)
	if st.Delegations == 0 {
		t.Fatalf("no delegations granted")
	}
	dirDelegs := kernelDirDelegations()
	if !dirDelegs {
		t.Logf("kernel client doesn't support directory delegations; only checking file delegations")
	} else if st.Ops[nfsv4.OpGetDirDelegation] == 0 {
		t.Errorf("client never asked for a directory delegation")
	}

	// Now, with everything delegated, repeated access past the
	// attribute cache timeout shouldn't cause any GETATTR, LOOKUP,
	// ACCESS, or READDIR.
	time.Sleep(1500 * time.Millisecond)
	before := srv.Stats()
	for range 3 {
		for _, p := range []string{"/hello.txt", "/sub/dir/file.go", "/live/data.txt"} {
			if _, err := os.ReadFile(dir + p); err != nil {
				t.Fatal(err)
			}
		}
		for _, p := range []string{"/sub", "/sub/dir", "/many"} {
			if _, err := os.ReadDir(dir + p); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(1100 * time.Millisecond)
	}
	after := srv.Stats()
	quietOps := []nfsv4.Op{nfsv4.OpGetAttr, nfsv4.OpLookup, nfsv4.OpAccess, nfsv4.OpReadDir, nfsv4.OpOpen, nfsv4.OpRead}
	if !dirDelegs {
		// Without directory delegations, the client still
		// revalidates directories and the names in them, but
		// delegated files are opened and read locally.
		quietOps = []nfsv4.Op{nfsv4.OpOpen, nfsv4.OpRead}
	}
	for _, op := range quietOps {
		if d := after.Ops[op] - before.Ops[op]; d != 0 {
			t.Errorf("%v ops while delegated: %d", op, d)
		}
	}
	t.Logf("ops while delegated: %v", diffOps(before, after))

	// Recall a live file's delegations and change it. The client must
	// see the new contents.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	release, err := srv.Recall(ctx, fs.Handle("/live/data.txt"))
	if err != nil {
		t.Fatalf("Recall: %v", err)
	}
	fs.WriteFile("/live/data.txt", []byte("version 2\n"), 0o644)
	release()
	got, err := os.ReadFile(dir + "/live/data.txt")
	if err != nil || string(got) != "version 2\n" {
		t.Errorf("after recall: %q, %v", got, err)
	}

	// Add a file to a delegated directory. The client must see the new
	// entry.
	release, err = srv.Recall(ctx, fs.Handle("/sub/dir"))
	if err != nil {
		t.Fatalf("Recall: %v", err)
	}
	fs.WriteFile("/sub/dir/new.go", []byte("package new\n"), 0o444)
	release()
	ents, err := os.ReadDir(dir + "/sub/dir")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "file.go,new.go" {
		t.Errorf("after recall, ReadDir = %q", names)
	}
	if _, err := os.Stat(dir + "/sub/dir/new.go"); err != nil {
		t.Errorf("stat new file: %v", err)
	}
	st = srv.Stats()
	t.Logf("final: %+v", st)
	if st.Revocations != 0 {
		t.Errorf("revocations = %d", st.Revocations)
	}
}

func diffOps(a, b nfsv4.Stats) map[nfsv4.Op]uint64 {
	m := map[nfsv4.Op]uint64{}
	for op, n := range b.Ops {
		if d := n - a.Ops[op]; d > 0 {
			m[op] = d
		}
	}
	return m
}

// kernelDirDelegations reports whether the kernel NFS client supports and
// uses directory delegations (the nfsv4 module's
// directory_delegations parameter). The nfsv4 module must be loaded.
func kernelDirDelegations() bool {
	b, err := os.ReadFile("/sys/module/nfsv4/parameters/directory_delegations")
	return err == nil && strings.TrimSpace(string(b)) == "Y"
}
