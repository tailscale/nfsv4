// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"testing"
)

func TestStatusOf(t *testing.T) {
	tests := []struct {
		err    error
		want   Status
		wantOK bool
	}{
		{nil, OK, true},
		{ErrStale, ErrStale, true},
		{fmt.Errorf("wrapped: %w", ErrBadHandle), ErrBadHandle, true},
		{fs.ErrNotExist, ErrNoEnt, true},
		{&os.PathError{Op: "open", Path: "x", Err: syscall.ENOENT}, ErrNoEnt, true},
		{syscall.EACCES, ErrAccess, true},
		{syscall.EBADMSG, ErrIO, false},
		{errors.New("boom"), ErrIO, false},
	}
	for _, tt := range tests {
		got, ok := statusOf(tt.err)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("statusOf(%v) = %v, %v; want %v, %v", tt.err, got, ok, tt.want, tt.wantOK)
		}
	}
	if got := ErrNoEnt.Error(); got != "NFS4ERR_NOENT" {
		t.Errorf("Error() = %q", got)
	}
	if got := OpExchangeID.String(); got != "EXCHANGE_ID" {
		t.Errorf("String() = %q", got)
	}
	if got := AttrMountedOnFileID.String(); got != "mounted_on_fileid" {
		t.Errorf("String() = %q", got)
	}
}
