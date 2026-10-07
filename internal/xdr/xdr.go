// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package xdr implements the subset of XDR (RFC 4506) encoding and decoding
// needed by ONC RPC and NFSv4.
//
// The Encoder appends to a byte slice. The Decoder reads from a byte slice and
// has a sticky error: after the first failure, all subsequent reads return
// zero values and Err reports the first error. This lets protocol decoders
// read a whole structure and check for errors once at the end.
package xdr

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrShort is returned when decoding runs past the end of the input.
var ErrShort = errors.New("xdr: short buffer")

// pad returns the number of padding bytes needed after n bytes of opaque data.
func pad(n int) int { return (4 - n&3) & 3 }

// Encoder appends XDR-encoded values to a buffer.
// The zero value is ready for use.
type Encoder struct {
	buf []byte
}

// NewEncoder returns an Encoder that appends to buf[:0].
func NewEncoder(buf []byte) *Encoder {
	return &Encoder{buf: buf[:0]}
}

// Bytes returns the encoded bytes. The slice aliases the Encoder's buffer.
func (e *Encoder) Bytes() []byte { return e.buf }

// Len returns the number of bytes encoded so far.
func (e *Encoder) Len() int { return len(e.buf) }

// Reset discards all encoded bytes but keeps the buffer.
func (e *Encoder) Reset() { e.buf = e.buf[:0] }

// Truncate discards all bytes after the first n.
func (e *Encoder) Truncate(n int) { e.buf = e.buf[:n] }

// Uint32 encodes an unsigned 32-bit integer.
func (e *Encoder) Uint32(v uint32) {
	e.buf = binary.BigEndian.AppendUint32(e.buf, v)
}

// Int32 encodes a signed 32-bit integer.
func (e *Encoder) Int32(v int32) { e.Uint32(uint32(v)) }

// Uint64 encodes an unsigned 64-bit integer (an XDR "unsigned hyper").
func (e *Encoder) Uint64(v uint64) {
	e.buf = binary.BigEndian.AppendUint64(e.buf, v)
}

// Int64 encodes a signed 64-bit integer (an XDR "hyper").
func (e *Encoder) Int64(v int64) { e.Uint64(uint64(v)) }

// Bool encodes a boolean as a 32-bit 0 or 1.
func (e *Encoder) Bool(v bool) {
	if v {
		e.Uint32(1)
	} else {
		e.Uint32(0)
	}
}

// FixedOpaque encodes fixed-length opaque data, padded to a multiple of 4.
func (e *Encoder) FixedOpaque(b []byte) {
	e.buf = append(e.buf, b...)
	e.buf = append(e.buf, make([]byte, pad(len(b)))...)
}

// Opaque encodes variable-length opaque data: a length followed by the
// padded bytes.
func (e *Encoder) Opaque(b []byte) {
	e.Uint32(uint32(len(b)))
	e.FixedOpaque(b)
}

// String encodes a string as variable-length opaque data.
func (e *Encoder) String(s string) {
	e.Uint32(uint32(len(s)))
	e.buf = append(e.buf, s...)
	e.buf = append(e.buf, make([]byte, pad(len(s)))...)
}

// Reserve appends n zero bytes and returns their offset, for callers that
// need to fill in a value (such as a count) after encoding what follows.
func (e *Encoder) Reserve(n int) int {
	off := len(e.buf)
	e.buf = append(e.buf, make([]byte, n)...)
	return off
}

// PutUint32At overwrites the 4 bytes at off with v.
func (e *Encoder) PutUint32At(off int, v uint32) {
	binary.BigEndian.PutUint32(e.buf[off:], v)
}

// Grow returns a slice of n bytes appended to the buffer, followed by
// padding, for callers that want to fill in opaque data in place (such as
// file contents read directly into a reply buffer). It returns the offset of
// the n bytes. Use Truncate and FixedOpaque length fixups if fewer bytes end
// up being used.
func (e *Encoder) Grow(n int) (off int, b []byte) {
	off = len(e.buf)
	e.buf = append(e.buf, make([]byte, n+pad(n))...)
	return off, e.buf[off : off+n]
}

// Decoder decodes XDR values from a byte slice.
type Decoder struct {
	b   []byte
	off int
	err error
}

// NewDecoder returns a Decoder reading from b.
func NewDecoder(b []byte) *Decoder {
	return &Decoder{b: b}
}

// Err returns the first error encountered, if any.
func (d *Decoder) Err() error { return d.err }

// SetErr sets the Decoder's sticky error, if not already set.
// Protocol decoders use it to report semantic errors (such as an
// out-of-range enum) through the same path as framing errors.
func (d *Decoder) SetErr(err error) {
	if d.err == nil {
		d.err = err
	}
}

// Offset returns the number of bytes consumed so far.
func (d *Decoder) Offset() int { return d.off }

// Remaining returns the number of unread bytes.
func (d *Decoder) Remaining() int { return len(d.b) - d.off }

// Rest returns the unread bytes without consuming them.
func (d *Decoder) Rest() []byte { return d.b[d.off:] }

func (d *Decoder) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || n > len(d.b)-d.off {
		d.err = ErrShort
		return nil
	}
	b := d.b[d.off : d.off+n]
	d.off += n
	return b
}

// Uint32 decodes an unsigned 32-bit integer.
func (d *Decoder) Uint32() uint32 {
	b := d.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

// Int32 decodes a signed 32-bit integer.
func (d *Decoder) Int32() int32 { return int32(d.Uint32()) }

// Uint64 decodes an unsigned 64-bit integer.
func (d *Decoder) Uint64() uint64 {
	b := d.take(8)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

// Int64 decodes a signed 64-bit integer.
func (d *Decoder) Int64() int64 { return int64(d.Uint64()) }

// Bool decodes a boolean. Values other than 0 and 1 are an error.
func (d *Decoder) Bool() bool {
	v := d.Uint32()
	if v > 1 {
		d.SetErr(fmt.Errorf("xdr: invalid bool %d", v))
		return false
	}
	return v == 1
}

// FixedOpaque decodes n bytes of fixed-length opaque data and its padding.
// The returned slice aliases the Decoder's input.
func (d *Decoder) FixedOpaque(n int) []byte {
	b := d.take(n)
	if b == nil && n > 0 {
		return nil
	}
	d.take(pad(n))
	if d.err != nil {
		return nil
	}
	return b
}

// Opaque decodes variable-length opaque data of at most max bytes.
// The returned slice aliases the Decoder's input.
func (d *Decoder) Opaque(max int) []byte {
	n := d.Uint32()
	if d.err != nil {
		return nil
	}
	if uint64(n) > uint64(max) {
		d.SetErr(fmt.Errorf("xdr: opaque length %d exceeds max %d", n, max))
		return nil
	}
	return d.FixedOpaque(int(n))
}

// String decodes a string of at most max bytes.
func (d *Decoder) String(max int) string {
	return string(d.Opaque(max))
}

// ArrayLen decodes an array length and checks it against max. It also
// rejects lengths that couldn't possibly fit in the remaining input given
// that each element occupies at least minElemSize bytes, so callers can
// safely preallocate.
func (d *Decoder) ArrayLen(max, minElemSize int) int {
	n := d.Uint32()
	if d.err != nil {
		return 0
	}
	if uint64(n) > uint64(max) {
		d.SetErr(fmt.Errorf("xdr: array length %d exceeds max %d", n, max))
		return 0
	}
	if minElemSize > 0 && uint64(n)*uint64(minElemSize) > uint64(d.Remaining()) {
		d.SetErr(ErrShort)
		return 0
	}
	return int(n)
}

// Pad returns the number of padding bytes XDR requires after n bytes of
// opaque data.
func Pad(n int) int { return pad(n) }
