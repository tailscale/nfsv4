// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package nfsv4_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/memfs"
)

// TestKernelLiveUpdates checks that clients see changes to live files,
// including changes that don't alter the file's size, with and without
// delegations.
func TestKernelLiveUpdates(t *testing.T) {
	for _, tt := range []struct {
		name      string
		deleg     bool
		monotonic bool
		vers      string
	}{
		{"nodeleg", false, false, "4.2"},
		{"deleg", true, false, "4.2"},
		{"deleg-monotonic", true, true, "4.2"},
		{"deleg-4.1", true, false, "4.1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if isDarwin {
				tt.vers = "4.1"
			}
			m := memfs.New()
			m.WriteFile("live/f.txt", []byte("value 000\n"), 0o444)
			if tt.deleg {
				m.SetCachePolicy("live", nfsv4.Delegation{Grant: true})
			}
			srv := &nfsv4.Server{FS: m, Logf: t.Logf, ChangeIsMonotonic: tt.monotonic}
			m.SetServer(srv)
			dir := mountServer(t, srv, tt.vers, "actimeo=1")
			for i := range 4 {
				want := fmt.Sprintf("value %03d\n", i)
				if i > 0 {
					if err := m.WriteFile("live/f.txt", []byte(want), 0o444); err != nil {
						t.Fatal(err)
					}
					if !tt.deleg {
						// Without delegations, the client
						// revalidates after its attribute cache
						// timeout.
						time.Sleep(2100 * time.Millisecond)
					}
				}
				start := time.Now()
				for {
					got, err := os.ReadFile(dir + "/live/f.txt")
					if err != nil {
						t.Fatal(err)
					}
					if string(got) == want {
						break
					}
					if !isDarwin || time.Since(start) > 10*time.Second {
						t.Fatalf("read %d: got %q; want %q", i, got, want)
					}
					time.Sleep(100 * time.Millisecond)
				}
				if d := time.Since(start); d > 0 && i > 0 {
					t.Logf("read %d: change visible after %v", i, d.Round(time.Millisecond))
				}
			}
		})
	}
}
