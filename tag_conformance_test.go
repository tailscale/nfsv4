// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4_test

import (
	"fmt"
	"testing"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/internal/testfs"
	"github.com/tailscale/nfsv4/internal/xdr"
)

func TestTagConformance(t *testing.T) {
	c := newTestServer(t, &nfsv4.Server{
		FS: testfs.New(),
	})
	check := func(t *testing.T, tag string, minor uint32, withOp bool, want nfsv4.Status) {
		t.Helper()
		var e xdr.Encoder
		e.String(tag)
		e.Uint32(minor)
		if withOp {
			e.Uint32(1)
			e.Uint32(uint32(nfsv4.OpIllegal))
		} else {
			e.Uint32(0)
		}
		res, err := c.Call(1, e.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		d := xdr.NewDecoder(res)
		status := nfsv4.Status(d.Uint32())
		echo := d.String(1024)
		nres := d.Uint32()
		if status != want || echo != tag || nres != 0 || d.Err() != nil {
			t.Fatalf("status=%v tag=%x nres=%d err=%v; want status=%v tag=%x nres=0", status, echo, nres, d.Err(), want, tag)
		}
	}

	// RFC 3454 C.4 lists these 66 noncharacters. RFC 8881 Section 14.1.5
	// does not prohibit C.4. These code points have valid UTF-8 encodings.
	var noncharacters []rune
	for r := rune(0xfdd0); r <= 0xfdef; r++ {
		noncharacters = append(noncharacters, r)
	}
	for plane := rune(0); plane <= 16; plane++ {
		noncharacters = append(noncharacters, plane<<16|0xfffe, plane<<16|0xffff)
	}
	for _, minor := range []uint32{1, 2} {
		for _, r := range noncharacters {
			t.Run(fmt.Sprintf("%d/noncharacter-%04x", minor, r), func(t *testing.T) {
				check(t, string(r), minor, false, nfsv4.OK)
				check(t, "before"+string(r)+"after", minor, false, nfsv4.OK)
			})
		}
		// Check valid code points at encoding and noncharacter boundaries.
		for _, r := range []rune{0, 0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xfdcf, 0xfdf0, 0xfffd, 0x10000, 0x1f600, 0x10fffd} {
			t.Run(fmt.Sprintf("%d/valid-%04x", minor, r), func(t *testing.T) {
				check(t, string(r), minor, false, nfsv4.OK)
			})
		}
		// Check every malformed encoding in pynfs get_invalid_utf8strings.
		// Its U+FFFE entry is valid and is checked with the noncharacters.
		for _, tag := range []string{
			"\xc0\xc1", "\xe0\x8a", "\xc0\xaf", "\xfc\x80\x80\x80\x80\xaf",
			"\xfc\x80\x80\x80\x80\x80", "\xed\xa0\x80", "\xed\xbf\xbf", "\xe3\xc0\xc0", "\xc0\x90",
			"\x80", "\xbf", "\xfe", "\xff", "\xc0 ", "\xdf ", "\xe0 ", "\xef ",
			"\xf0 ", "\xf7 ", "\xf8 ", "\xfb ", "\xfc ", "\xfd ",
			"\xe2\x82", "\xf4\x90\x80\x80",
		} {
			t.Run(fmt.Sprintf("%d/invalid-%x", minor, tag), func(t *testing.T) {
				check(t, tag, minor, false, nfsv4.ErrInval)
				check(t, tag, minor, true, nfsv4.ErrInval)
				check(t, tag, 50, true, nfsv4.ErrMinorVersMismatch)
			})
		}
	}
}
