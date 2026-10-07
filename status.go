// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4

import (
	"context"
	"errors"
	"io/fs"
	"syscall"
)

// statusOf maps an error returned by an FS implementation to the NFSv4
// status sent to the client. It reports ok=false for errors that have no
// natural mapping, which the server logs and reports as ErrIO.
func statusOf(err error) (st Status, ok bool) {
	if err == nil {
		return OK, true
	}
	var s Status
	if errors.As(err, &s) {
		return s, true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if s, ok := errnoStatus[errno]; ok {
			return s, true
		}
		return ErrIO, false
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ErrNoEnt, true
	case errors.Is(err, fs.ErrPermission):
		return ErrAccess, true
	case errors.Is(err, fs.ErrExist):
		return ErrExist, true
	case errors.Is(err, fs.ErrInvalid):
		return ErrInval, true
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return ErrDelay, true
	}
	return ErrIO, false
}

var errnoStatus = map[syscall.Errno]Status{
	syscall.EPERM:        ErrPerm,
	syscall.ENOENT:       ErrNoEnt,
	syscall.EIO:          ErrIO,
	syscall.ENXIO:        ErrNXIO,
	syscall.EACCES:       ErrAccess,
	syscall.EEXIST:       ErrExist,
	syscall.EXDEV:        ErrXDev,
	syscall.ENOTDIR:      ErrNotDir,
	syscall.EISDIR:       ErrIsDir,
	syscall.EINVAL:       ErrInval,
	syscall.EFBIG:        ErrFBig,
	syscall.ENOSPC:       ErrNoSpc,
	syscall.EROFS:        ErrROFS,
	syscall.EMLINK:       ErrMLink,
	syscall.ENAMETOOLONG: ErrNameTooLong,
	syscall.ENOTEMPTY:    ErrNotEmpty,
	syscall.EDQUOT:       ErrDQuot,
	syscall.ESTALE:       ErrStale,
	syscall.ELOOP:        ErrSymlink,
	syscall.EAGAIN:       ErrDelay,
	syscall.ENOTSUP:      ErrNotSupp,
	syscall.ENOSYS:       ErrNotSupp,
}
