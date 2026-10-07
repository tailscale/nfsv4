// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package oncrpc

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/tailscale/nfsv4/internal/xdr"
)

func TestRecordFragments(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 3})
	buf.WriteString("abc")
	buf.Write([]byte{0x80, 0, 0, 2})
	buf.WriteString("de")
	buf.Write([]byte{0x80, 0, 0, 1})
	buf.WriteString("f")

	rec, err := ReadRecord(&buf, nil, 100)
	if err != nil || string(rec) != "abcde" {
		t.Fatalf("got %q, %v", rec, err)
	}
	rec, err = ReadRecord(&buf, rec, 100)
	if err != nil || string(rec) != "f" {
		t.Fatalf("got %q, %v", rec, err)
	}
	if _, err := ReadRecord(&buf, nil, 100); err != io.EOF {
		t.Fatalf("err = %v; want EOF", err)
	}
}

func TestRecordErrors(t *testing.T) {
	big := []byte{0x80, 0, 1, 0}
	if _, err := ReadRecord(bytes.NewReader(big), nil, 100); !errors.Is(err, ErrRecordTooLarge) {
		t.Errorf("err = %v", err)
	}
	short := []byte{0x80, 0, 0, 10, 'a'}
	if _, err := ReadRecord(bytes.NewReader(short), nil, 100); err != io.ErrUnexpectedEOF {
		t.Errorf("err = %v", err)
	}
	// A non-final fragment followed by EOF.
	partial := []byte{0, 0, 0, 1, 'a'}
	if _, err := ReadRecord(bytes.NewReader(partial), nil, 100); err != io.ErrUnexpectedEOF {
		t.Errorf("err = %v", err)
	}
}

func TestCallRoundTrip(t *testing.T) {
	cred := AuthSysCred{Stamp: 1, MachineName: "box", UID: 1000, GID: 100, GIDs: []uint32{4, 5}}
	h := CallHeader{
		XID:  42,
		Prog: 100003,
		Vers: 4,
		Proc: 1,
		Cred: OpaqueAuth{Flavor: AuthSys, Body: cred.Encode()},
		Verf: OpaqueAuth{Flavor: AuthNone, Body: []byte{}},
	}
	e := xdr.NewEncoder(make([]byte, RecordHeaderLen))
	e.Reserve(RecordHeaderLen)
	EncodeCall(e, h)
	e.Uint32(0xdeadbeef)
	msg := FinishRecord(e.Bytes())

	rec, err := ReadRecord(bytes.NewReader(msg), nil, 1000)
	if err != nil {
		t.Fatal(err)
	}
	xid, mt, err := MessageType(rec)
	if err != nil || xid != 42 || mt != Call {
		t.Fatalf("MessageType = %v, %v, %v", xid, mt, err)
	}
	got, args, err := ParseCall(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, h) {
		t.Errorf("got %+v; want %+v", got, h)
	}
	if !bytes.Equal(args, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("args = %x", args)
	}
	gotCred, err := ParseAuthSys(got.Cred.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotCred, cred) {
		t.Errorf("cred = %+v; want %+v", gotCred, cred)
	}
}

func TestReplyRoundTrip(t *testing.T) {
	var e xdr.Encoder
	EncodeAcceptedReply(&e, 7, Success)
	e.Uint32(99)
	h, rest, err := ParseReply(e.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if h.XID != 7 || h.Stat != MsgAccepted || h.AcceptStat != Success {
		t.Errorf("got %+v", h)
	}
	if len(rest) != 4 {
		t.Errorf("rest = %x", rest)
	}

	e.Reset()
	EncodeAuthError(&e, 8, AuthTooWeak)
	h, _, err = ParseReply(e.Bytes())
	if err != nil || h.Stat != MsgDenied || h.RejectStat != AuthError {
		t.Errorf("got %+v, %v", h, err)
	}
}

func TestBadRPCVersion(t *testing.T) {
	var e xdr.Encoder
	e.Uint32(5)
	e.Uint32(Call)
	e.Uint32(3)
	h, _, err := ParseCall(e.Bytes())
	var ve *VersionError
	if !errors.As(err, &ve) || ve.Version != 3 || h.XID != 5 {
		t.Errorf("got %+v, %v", h, err)
	}
}
