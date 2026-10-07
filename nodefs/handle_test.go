// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nodefs

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestEncodePathRoundTrip(t *testing.T) {
	tests := []string{
		"a",
		"a/b/c",
		"github.com/tailscale/tailscale@v1.2.3/cmd/tailscale/main.go",
		strings.Repeat("x", 126),
		strings.Repeat("x", 127),
		strings.Repeat("abcdefghij/", 20) + "file.txt",
		strings.Repeat("a/", 22) + "b",
		strings.Repeat(strings.Repeat("y", 255)+"/", 3) + "z",
	}
	for _, p := range tests {
		comps := splitPath(p)
		h := encodePath(p, comps)
		if h == nil {
			t.Errorf("%q: not encodable", p)
			continue
		}
		if len(h) > maxHandleLen {
			t.Errorf("%q: handle length %d", p, len(h))
		}
		dc, full, err := decodePath(h)
		if err != nil {
			t.Errorf("%q: decode: %v", p, err)
			continue
		}
		if len(dc) != len(comps) {
			t.Errorf("%q: decoded %d comps; want %d", p, len(dc), len(comps))
			continue
		}
		anyHashed := false
		for i, c := range dc {
			if c.hashed {
				anyHashed = true
				if c.hash != compHash(comps[i]) {
					t.Errorf("%q: comp %d hash mismatch", p, i)
				}
			} else if c.name != comps[i] {
				t.Errorf("%q: comp %d = %q; want %q", p, i, c.name, comps[i])
			}
		}
		if anyHashed && full != pathHash(p) {
			t.Errorf("%q: full hash mismatch", p)
		}
		if !anyHashed && len(h) != 1+len(p)+1 {
			t.Errorf("%q: verbatim handle length %d", p, len(h))
		}
	}
}

func TestEncodePathTooDeep(t *testing.T) {
	p := strings.Repeat("abcdefghij/", 40) + "b"
	if h := encodePath(p, splitPath(p)); h != nil {
		t.Errorf("got handle %x for a too-deep path; want nil", h)
	}
}

func TestDecodeGarbage(t *testing.T) {
	for _, h := range [][]byte{
		{}, {fmtPath}, {fmtPath, 5, 'a'}, {fmtPath, 0, 1, 2}, {fmtPath, 0, 1, 2, 3, 4},
		{fmtPath, 0, 1, 2, 3, 4, 1, 'a'},
	} {
		if _, _, err := decodePath(h); err == nil {
			t.Errorf("decodePath(%x) succeeded", h)
		}
	}
}

func FuzzEncodePath(f *testing.F) {
	f.Add("a/b/c", 3)
	f.Fuzz(func(t *testing.T, base string, depth int) {
		if base == "" || strings.ContainsAny(base, "/\x00") || len(base) > 255 || depth < 1 || depth > 50 {
			return
		}
		var comps []string
		for i := range depth {
			name := fmt.Sprintf("%s%d", base, i)
			comps = append(comps, name[:min(len(name), 255)])
		}
		p := strings.Join(comps, "/")
		h := encodePath(p, comps)
		if h == nil {
			return
		}
		if len(h) > maxHandleLen {
			t.Fatalf("handle too long: %d", len(h))
		}
		if bytes.Equal(h, rootHandle) {
			t.Fatalf("non-root path encoded as root")
		}
		dc, _, err := decodePath(h)
		if err != nil || len(dc) != len(comps) {
			t.Fatalf("decode: %v, %d comps", err, len(dc))
		}
	})
}
