// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"
	"testing"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/internal/testfs"
	"github.com/tailscale/nfsv4/memfs"
)

func TestFSConformancePutFH(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		t.Run(fmt.Sprint(minor), func(t *testing.T) {
			fs := memfs.New()
			if err := fs.WriteFile("removed", nil, 0o644); err != nil {
				t.Fatal(err)
			}
			removed := fs.Handle("removed")
			if err := fs.Remove("removed"); err != nil {
				t.Fatal(err)
			}
			c := newSessionClient(t, &nfsv4.Server{
				FS: fs,
			}, false)
			c.MinorVersion = minor
			for _, tt := range []struct {
				name string
				fh   nfsv4.FileHandle
				want nfsv4.Status
			}{
				{"bogus", []byte("abc"), nfsv4.ErrBadHandle},
				{"empty", nil, nfsv4.ErrBadHandle},
				{"oversized", bytes.Repeat([]byte("a"), nfsv4.MaxFileHandleSize+1), nfsv4.ErrBadXDR},
				{"removed", removed, nfsv4.ErrStale},
				{"root", fs.Handle(""), nfsv4.OK},
			} {
				t.Run(tt.name, func(t *testing.T) {
					b, slot := c.Seq()
					b.Op(nfsv4.OpPutFH).Opaque(tt.fh)
					r, err := c.DoSeq(b, slot)
					if err != nil {
						t.Fatal(err)
					}
					expect(t, r, nfsv4.OpPutFH, tt.want)
				})
			}
		})
	}
}

// putfhConformanceFS uses handles that do not have the nodefs format.
type putfhConformanceFS struct {
	nfsv4.FS
	err       error
	attrWants []nfsv4.AttrMask
}

func (fs *putfhConformanceFS) GetAttr(r *nfsv4.Request, fh nfsv4.FileHandle, want nfsv4.AttrMask) (*nfsv4.Attrs, error) {
	fs.attrWants = append(fs.attrWants, want)
	if fs.err != nil {
		return nil, fs.err
	}
	return &nfsv4.Attrs{
		Type: nfsv4.TypeDir,
	}, nil
}

func TestFSConformanceOpaqueHandles(t *testing.T) {
	type errorCase struct {
		name    string
		err     error
		want    nfsv4.Status
		wantLog bool
	}
	cases := []errorCase{
		{"OK", nil, nfsv4.OK, false},
		{"permission", fs.ErrPermission, nfsv4.ErrServerFault, true},
		{"errno_io", syscall.EIO, nfsv4.ErrServerFault, true},
		{"errno_stale", syscall.ESTALE, nfsv4.ErrStale, false},
		{"errno_delay", syscall.EAGAIN, nfsv4.ErrDelay, false},
		{"canceled", context.Canceled, nfsv4.ErrDelay, false},
		{"deadline", context.DeadlineExceeded, nfsv4.ErrDelay, false},
		{"unknown", errors.New("backend failure"), nfsv4.ErrServerFault, true},
	}
	for _, tt := range []struct {
		st   nfsv4.Status
		want nfsv4.Status
	}{
		{nfsv4.ErrBadHandle, nfsv4.ErrBadHandle},
		{nfsv4.ErrStale, nfsv4.ErrStale},
		{nfsv4.ErrDelay, nfsv4.ErrDelay},
		{nfsv4.ErrMoved, nfsv4.ErrMoved},
		{nfsv4.ErrWrongSec, nfsv4.ErrWrongSec},
		{nfsv4.ErrServerFault, nfsv4.ErrServerFault},
		{nfsv4.ErrBadXDR, nfsv4.ErrServerFault},
		{nfsv4.ErrAccess, nfsv4.ErrServerFault},
		{nfsv4.ErrIO, nfsv4.ErrServerFault},
		{nfsv4.ErrPerm, nfsv4.ErrServerFault},
		{nfsv4.ErrNotSupp, nfsv4.ErrServerFault},
		{nfsv4.ErrNoEnt, nfsv4.ErrServerFault},
		{nfsv4.ErrInval, nfsv4.ErrServerFault},
		{nfsv4.ErrBadSession, nfsv4.ErrServerFault},
		{nfsv4.ErrDeadSession, nfsv4.ErrServerFault},
		{nfsv4.Status(0xffffffff), nfsv4.ErrServerFault},
	} {
		cases = append(cases, errorCase{
			name:    tt.st.String(),
			err:     fmt.Errorf("backend: %w", tt.st),
			want:    tt.want,
			wantLog: tt.st != tt.want,
		})
	}
	for _, minor := range []uint32{1, 2} {
		for _, tt := range cases {
			t.Run(fmt.Sprintf("%d/%s", minor, tt.name), func(t *testing.T) {
				fs := &putfhConformanceFS{
					FS:  testfs.New(),
					err: tt.err,
				}
				logs := make(chan string, 1)
				c := newSessionClient(t, &nfsv4.Server{
					FS: fs,
					Logf: func(format string, args ...any) {
						msg := fmt.Sprintf(format, args...)
						if strings.Contains(msg, "PUTFH") {
							logs <- msg
						}
					},
				}, false)
				c.MinorVersion = minor
				b, slot := c.Seq()
				b.Op(nfsv4.OpPutFH).Opaque([]byte("abc"))
				b.Op(nfsv4.OpGetFH)
				r, err := c.DoSeq(b, slot)
				if err != nil {
					t.Fatal(err)
				}
				expect(t, r, nfsv4.OpPutFH, tt.want)
				if tt.want == nfsv4.OK {
					must(t, r, nfsv4.OpGetFH)
					if got := r.D.Opaque(nfsv4.MaxFileHandleSize); !bytes.Equal(got, []byte("abc")) {
						t.Fatalf("GETFH = %q", got)
					}
				} else if r.Status != tt.want || r.NumRes != 2 {
					t.Fatalf("failed PUTFH: status=%v numres=%d; want %v and 2", r.Status, r.NumRes, tt.want)
				}
				if tt.wantLog {
					select {
					case msg := <-logs:
						if !strings.Contains(msg, tt.err.Error()) || !strings.Contains(msg, "SERVERFAULT") {
							t.Fatalf("incomplete PUTFH diagnostic: %s", msg)
						}
					default:
						t.Error("missing PUTFH diagnostic for unsupported backend status")
					}
				}
			})
		}
	}
}

func TestFSConformancePutFHAttrCache(t *testing.T) {
	fs := &putfhConformanceFS{
		FS: testfs.New(),
	}
	c := newSessionClient(t, &nfsv4.Server{
		FS: fs,
	}, false)
	b, slot := c.Seq()
	b.Op(nfsv4.OpPutFH).Opaque([]byte("abc"))
	encodeBitmap(b.Op(nfsv4.OpGetAttr), nfsv4.AttrType)
	encodeBitmap(b.Op(nfsv4.OpGetAttr), nfsv4.AttrSpaceUsed)
	r, err := c.DoSeq(b, slot)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != nfsv4.OK {
		t.Fatal(r.Status)
	}
	if len(fs.attrWants) != 2 {
		t.Fatalf("GetAttr calls = %d; want 2", len(fs.attrWants))
	}
	space := nfsv4.MakeAttrMask(nfsv4.AttrSpaceUsed)
	if fs.attrWants[0].ContainsAll(space) || !fs.attrWants[1].ContainsAll(space) {
		t.Fatal("PUTFH attributes must not hide attributes that were not requested")
	}
}
