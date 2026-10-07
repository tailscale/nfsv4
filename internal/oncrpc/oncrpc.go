// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package oncrpc implements the parts of ONC RPC version 2 (RFC 5531) needed
// by an NFSv4 server: TCP record marking, call and reply headers, and the
// AUTH_NONE and AUTH_SYS credential flavors.
package oncrpc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/tailscale/nfsv4/internal/xdr"
)

// Message types.
const (
	Call  = 0
	Reply = 1
)

// Reply status.
const (
	MsgAccepted = 0
	MsgDenied   = 1
)

// Accept status values for accepted replies.
const (
	Success      = 0
	ProgUnavail  = 1
	ProgMismatch = 2
	ProcUnavail  = 3
	GarbageArgs  = 4
	SystemErr    = 5
)

// Reject status values for denied replies.
const (
	RPCMismatch = 0
	AuthError   = 1
)

// Auth status values for AuthError rejections.
const (
	AuthOK           = 0
	AuthBadCred      = 1
	AuthRejectedCred = 2
	AuthBadVerf      = 3
	AuthRejectedVerf = 4
	AuthTooWeak      = 5
)

// Auth flavors.
const (
	AuthNone = 0
	AuthSys  = 1
)

const (
	lastFragment = 1 << 31
	maxAuthBody  = 400
)

// ErrRecordTooLarge is returned by ReadRecord when a record exceeds the
// maximum size.
var ErrRecordTooLarge = errors.New("oncrpc: record too large")

// ReadRecord reads one record-marked RPC message from r, reassembling
// fragments. It appends the message to buf[:0] and returns the result.
// Records larger than max bytes are rejected with ErrRecordTooLarge.
func ReadRecord(r io.Reader, buf []byte, max int) ([]byte, error) {
	buf = buf[:0]
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if err == io.ErrUnexpectedEOF || (err == io.EOF && len(buf) > 0) {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		h := binary.BigEndian.Uint32(hdr[:])
		n := int(h &^ lastFragment)
		if len(buf)+n > max {
			return nil, ErrRecordTooLarge
		}
		start := len(buf)
		buf = append(buf, make([]byte, n)...)
		if _, err := io.ReadFull(r, buf[start:]); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if h&lastFragment != 0 {
			return buf, nil
		}
	}
}

// RecordHeaderLen is the number of bytes callers must reserve at the start of
// a message buffer passed to FinishRecord.
const RecordHeaderLen = 4

// FinishRecord fills in the record marking header in the first
// RecordHeaderLen bytes of msg, which the caller must have reserved, marking
// msg as a single final fragment. It returns msg.
func FinishRecord(msg []byte) []byte {
	binary.BigEndian.PutUint32(msg, uint32(len(msg)-RecordHeaderLen)|lastFragment)
	return msg
}

// OpaqueAuth is an RPC credential or verifier.
type OpaqueAuth struct {
	Flavor uint32
	Body   []byte
}

func decodeAuth(d *xdr.Decoder) OpaqueAuth {
	return OpaqueAuth{
		Flavor: d.Uint32(),
		Body:   d.Opaque(maxAuthBody),
	}
}

func encodeAuth(e *xdr.Encoder, a OpaqueAuth) {
	e.Uint32(a.Flavor)
	e.Opaque(a.Body)
}

// CallHeader is the header of an RPC call message.
type CallHeader struct {
	XID  uint32
	Prog uint32
	Vers uint32
	Proc uint32
	Cred OpaqueAuth
	Verf OpaqueAuth
}

// ReplyHeader is the header of an RPC reply message.
type ReplyHeader struct {
	XID        uint32
	Stat       uint32 // MsgAccepted or MsgDenied
	AcceptStat uint32 // if Stat == MsgAccepted
	RejectStat uint32 // if Stat == MsgDenied
	Verf       OpaqueAuth
}

// MessageType returns the XID and message type (Call or Reply) of msg
// without decoding the rest.
func MessageType(msg []byte) (xid, mtype uint32, err error) {
	if len(msg) < 8 {
		return 0, 0, xdr.ErrShort
	}
	return binary.BigEndian.Uint32(msg), binary.BigEndian.Uint32(msg[4:]), nil
}

// ParseCall decodes the header of an RPC call message. It returns the header
// and the remaining bytes, which are the procedure's arguments. The returned
// values alias msg.
//
// If the RPC version isn't 2, it returns an error of type *VersionError,
// and the XID in the returned header is valid so that the caller can send
// an RPC_MISMATCH rejection.
func ParseCall(msg []byte) (CallHeader, []byte, error) {
	d := xdr.NewDecoder(msg)
	var h CallHeader
	h.XID = d.Uint32()
	if mt := d.Uint32(); d.Err() == nil && mt != Call {
		return h, nil, fmt.Errorf("oncrpc: message type %d is not a call", mt)
	}
	if v := d.Uint32(); d.Err() == nil && v != 2 {
		return h, nil, &VersionError{Version: v}
	}
	h.Prog = d.Uint32()
	h.Vers = d.Uint32()
	h.Proc = d.Uint32()
	h.Cred = decodeAuth(d)
	h.Verf = decodeAuth(d)
	if err := d.Err(); err != nil {
		return h, nil, err
	}
	return h, d.Rest(), nil
}

// VersionError is returned by ParseCall for calls using an RPC version
// other than 2.
type VersionError struct {
	Version uint32
}

func (e *VersionError) Error() string {
	return fmt.Sprintf("oncrpc: unsupported RPC version %d", e.Version)
}

// ParseReply decodes the header of an RPC reply message. It returns the
// header and the remaining bytes, which are the procedure's results if the
// call was accepted and successful.
func ParseReply(msg []byte) (ReplyHeader, []byte, error) {
	d := xdr.NewDecoder(msg)
	var h ReplyHeader
	h.XID = d.Uint32()
	if mt := d.Uint32(); d.Err() == nil && mt != Reply {
		return h, nil, fmt.Errorf("oncrpc: message type %d is not a reply", mt)
	}
	h.Stat = d.Uint32()
	switch h.Stat {
	case MsgAccepted:
		h.Verf = decodeAuth(d)
		h.AcceptStat = d.Uint32()
	case MsgDenied:
		h.RejectStat = d.Uint32()
	default:
		d.SetErr(fmt.Errorf("oncrpc: bad reply status %d", h.Stat))
	}
	if err := d.Err(); err != nil {
		return h, nil, err
	}
	return h, d.Rest(), nil
}

// EncodeCall appends an RPC call header to e.
func EncodeCall(e *xdr.Encoder, h CallHeader) {
	e.Uint32(h.XID)
	e.Uint32(Call)
	e.Uint32(2)
	e.Uint32(h.Prog)
	e.Uint32(h.Vers)
	e.Uint32(h.Proc)
	encodeAuth(e, h.Cred)
	encodeAuth(e, h.Verf)
}

// EncodeAcceptedReply appends the header of an accepted reply with the given
// accept status and an AUTH_NONE verifier. For Success, the caller then
// appends the procedure results. For ProgMismatch, the caller must append
// the low and high supported versions.
func EncodeAcceptedReply(e *xdr.Encoder, xid, acceptStat uint32) {
	e.Uint32(xid)
	e.Uint32(Reply)
	e.Uint32(MsgAccepted)
	encodeAuth(e, OpaqueAuth{Flavor: AuthNone})
	e.Uint32(acceptStat)
}

// EncodeRPCMismatch appends a denied reply saying only RPC version 2 is
// supported.
func EncodeRPCMismatch(e *xdr.Encoder, xid uint32) {
	e.Uint32(xid)
	e.Uint32(Reply)
	e.Uint32(MsgDenied)
	e.Uint32(RPCMismatch)
	e.Uint32(2)
	e.Uint32(2)
}

// EncodeAuthError appends a denied reply with the given auth status.
func EncodeAuthError(e *xdr.Encoder, xid, authStat uint32) {
	e.Uint32(xid)
	e.Uint32(Reply)
	e.Uint32(MsgDenied)
	e.Uint32(AuthError)
	e.Uint32(authStat)
}

// AuthSysCred is an AUTH_SYS (formerly AUTH_UNIX) credential.
type AuthSysCred struct {
	Stamp       uint32
	MachineName string
	UID         uint32
	GID         uint32
	GIDs        []uint32
}

// ParseAuthSys decodes the body of an AUTH_SYS credential.
func ParseAuthSys(body []byte) (AuthSysCred, error) {
	d := xdr.NewDecoder(body)
	var c AuthSysCred
	c.Stamp = d.Uint32()
	c.MachineName = d.String(255)
	c.UID = d.Uint32()
	c.GID = d.Uint32()
	n := d.ArrayLen(16, 4)
	if n > 0 {
		c.GIDs = make([]uint32, n)
		for i := range c.GIDs {
			c.GIDs[i] = d.Uint32()
		}
	}
	if err := d.Err(); err != nil {
		return AuthSysCred{}, err
	}
	if d.Remaining() != 0 {
		return AuthSysCred{}, errors.New("oncrpc: trailing bytes in AUTH_SYS credential")
	}
	return c, nil
}

// Encode returns the AUTH_SYS credential body for c.
func (c AuthSysCred) Encode() []byte {
	var e xdr.Encoder
	c.EncodeTo(&e)
	return e.Bytes()
}

// EncodeTo appends the AUTH_SYS credential body for c to e.
func (c AuthSysCred) EncodeTo(e *xdr.Encoder) {
	e.Uint32(c.Stamp)
	e.String(c.MachineName)
	e.Uint32(c.UID)
	e.Uint32(c.GID)
	e.Uint32(uint32(len(c.GIDs)))
	for _, g := range c.GIDs {
		e.Uint32(g)
	}
}
