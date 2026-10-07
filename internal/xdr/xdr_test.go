// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package xdr

import (
	"bytes"
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var e Encoder
	e.Uint32(1)
	e.Int32(-2)
	e.Uint64(1 << 40)
	e.Int64(-3)
	e.Bool(true)
	e.Bool(false)
	e.Opaque([]byte("abcde"))
	e.String("xy")
	e.FixedOpaque([]byte{9, 9, 9})
	off := e.Reserve(4)
	e.PutUint32At(off, 42)

	if e.Len()%4 != 0 {
		t.Fatalf("encoded length %d not a multiple of 4", e.Len())
	}

	d := NewDecoder(e.Bytes())
	if got := d.Uint32(); got != 1 {
		t.Errorf("Uint32 = %v", got)
	}
	if got := d.Int32(); got != -2 {
		t.Errorf("Int32 = %v", got)
	}
	if got := d.Uint64(); got != 1<<40 {
		t.Errorf("Uint64 = %v", got)
	}
	if got := d.Int64(); got != -3 {
		t.Errorf("Int64 = %v", got)
	}
	if got := d.Bool(); !got {
		t.Errorf("Bool = %v", got)
	}
	if got := d.Bool(); got {
		t.Errorf("Bool = %v", got)
	}
	if got := d.Opaque(10); string(got) != "abcde" {
		t.Errorf("Opaque = %q", got)
	}
	if got := d.String(10); got != "xy" {
		t.Errorf("String = %q", got)
	}
	if got := d.FixedOpaque(3); !bytes.Equal(got, []byte{9, 9, 9}) {
		t.Errorf("FixedOpaque = %v", got)
	}
	if got := d.Uint32(); got != 42 {
		t.Errorf("reserved = %v", got)
	}
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}
	if d.Remaining() != 0 {
		t.Errorf("Remaining = %d", d.Remaining())
	}
}

func TestDecoderErrors(t *testing.T) {
	d := NewDecoder([]byte{0, 0, 0})
	if got := d.Uint32(); got != 0 {
		t.Errorf("got %v", got)
	}
	if !errors.Is(d.Err(), ErrShort) {
		t.Errorf("err = %v", d.Err())
	}
	// Sticky: later reads keep failing even though there are bytes.
	d.Uint32()
	if !errors.Is(d.Err(), ErrShort) {
		t.Errorf("err = %v", d.Err())
	}

	var e Encoder
	e.Opaque(make([]byte, 20))
	d = NewDecoder(e.Bytes())
	if d.Opaque(19) != nil || d.Err() == nil {
		t.Errorf("expected max length error")
	}

	e.Reset()
	e.Uint32(1 << 30)
	d = NewDecoder(e.Bytes())
	if n := d.ArrayLen(1<<31, 4); n != 0 || !errors.Is(d.Err(), ErrShort) {
		t.Errorf("ArrayLen = %v, %v", n, d.Err())
	}

	d = NewDecoder([]byte{0, 0, 0, 2})
	if d.Bool() || d.Err() == nil {
		t.Errorf("expected invalid bool error")
	}
}

func TestGrow(t *testing.T) {
	var e Encoder
	e.Uint32(7)
	off, b := e.Grow(5)
	copy(b, "hello")
	if off != 4 || e.Len() != 12 {
		t.Fatalf("off=%d len=%d", off, e.Len())
	}
	if !bytes.Equal(e.Bytes()[4:], []byte("hello\x00\x00\x00")) {
		t.Errorf("got %q", e.Bytes())
	}
}

func FuzzDecoder(f *testing.F) {
	f.Add([]byte{0, 0, 0, 3, 'a', 'b', 'c', 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		d := NewDecoder(b)
		for d.Err() == nil && d.Remaining() > 0 {
			d.Opaque(1 << 20)
			d.ArrayLen(1<<20, 4)
		}
	})
}
