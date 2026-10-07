// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4

import "fmt"

// Status is an NFSv4 status code (nfsstat4).
//
// Status implements error, so FS implementations can return Status values
// such as ErrNoEnt directly to control exactly what the client sees. OK
// should not be returned as an error.
type Status uint32

func (s Status) Error() string { return s.String() }

func (s Status) String() string {
	if n, ok := statusNames[s]; ok {
		return n
	}
	return fmt.Sprintf("NFS4ERR_%d", uint32(s))
}

// Op is an NFSv4 COMPOUND operation number (nfs_opnum4).
type Op uint32

func (o Op) String() string {
	if n, ok := opNames[o]; ok {
		return n
	}
	return fmt.Sprintf("OP_%d", uint32(o))
}

// CBOp is an NFSv4 callback operation number (nfs_cb_opnum4).
type CBOp uint32

func (o CBOp) String() string {
	if n, ok := cbOpNames[o]; ok {
		return n
	}
	return fmt.Sprintf("CB_OP_%d", uint32(o))
}

// Attr is an NFSv4 file attribute number (FATTR4_*).
type Attr uint32

func (a Attr) String() string {
	if n, ok := attrNames[a]; ok {
		return n
	}
	return fmt.Sprintf("attr_%d", uint32(a))
}

// FileType is an NFSv4 file type (nfs_ftype4).
type FileType uint32

// File types.
const (
	TypeReg       FileType = 1 // NF4REG: regular file
	TypeDir       FileType = 2 // NF4DIR: directory
	TypeBlock     FileType = 3 // NF4BLK: block device
	TypeChar      FileType = 4 // NF4CHR: character device
	TypeSymlink   FileType = 5 // NF4LNK: symbolic link
	TypeSocket    FileType = 6 // NF4SOCK: socket
	TypeFIFO      FileType = 7 // NF4FIFO: named pipe
	TypeAttrDir   FileType = 8 // NF4ATTRDIR: named attribute directory (unused)
	TypeNamedAttr FileType = 9 // NF4NAMEDATTR: named attribute (unused)
)

func (t FileType) String() string {
	switch t {
	case TypeReg:
		return "reg"
	case TypeDir:
		return "dir"
	case TypeBlock:
		return "block"
	case TypeChar:
		return "char"
	case TypeSymlink:
		return "symlink"
	case TypeSocket:
		return "socket"
	case TypeFIFO:
		return "fifo"
	case TypeAttrDir:
		return "attrdir"
	case TypeNamedAttr:
		return "namedattr"
	}
	return fmt.Sprintf("FileType(%d)", uint32(t))
}

// Access bits, as used by the ACCESS operation (ACCESS4_*).
const (
	AccessRead    uint32 = 0x01 // read data or list directory
	AccessLookup  uint32 = 0x02 // look up names in a directory
	AccessModify  uint32 = 0x04 // rewrite data or modify directory entries
	AccessExtend  uint32 = 0x08 // append data or add directory entries
	AccessDelete  uint32 = 0x10 // delete directory entries
	AccessExecute uint32 = 0x20 // execute a file
)

// Filehandle expiration types, as reported by the fh_expire_type attribute
// (FH4_*).
const (
	FHPersistent       uint32 = 0x00
	FHNoExpireWithOpen uint32 = 0x01
	FHVolatileAny      uint32 = 0x02
	FHVolMigration     uint32 = 0x04
	FHVolRename        uint32 = 0x08
)

// Values of the change_attr_type attribute (change_attr_type4).
const (
	changeMonotonicIncr = 0
	changeUndefined     = 4
)

// Protocol limits.
const (
	// MaxFileHandleSize is the maximum length of a filehandle (NFS4_FHSIZE).
	MaxFileHandleSize = 128

	maxOpaque     = 1024 // NFS4_OPAQUE_LIMIT
	verifierSize  = 8    // NFS4_VERIFIER_SIZE
	sessionIDSize = 16   // NFS4_SESSIONID_SIZE
	stateOtherLen = 12   // NFS4_OTHER_SIZE
)

// Protocol flags not exposed in the public API.
const (
	exchgidSuppMovedRefer   = 0x00000001
	exchgidSuppMovedMigr    = 0x00000002
	exchgidBindPrincStateID = 0x00000100
	exchgidUseNonPNFS       = 0x00010000
	exchgidMaskPNFS         = 0x00070000
	exchgidUpdConfirmedRecA = 0x40000000
	exchgidConfirmedR       = 0x80000000

	createSessionPersist      = 0x1
	createSessionConnBackChan = 0x2
	createSessionConnRDMA     = 0x4

	seqStatusCBPathDown              = 0x00000001
	seqStatusExpiredAllStateRevoked  = 0x00000008
	seqStatusExpiredSomeStateRevoked = 0x00000010
	seqStatusAdminStateRevoked       = 0x00000020
	seqStatusRecallableStateRevoked  = 0x00000040
	seqStatusRestartReclaimNeeded    = 0x00000100
	seqStatusCBPathDownSession       = 0x00000200
	seqStatusBackchannelFault        = 0x00000400

	shareAccessRead  = 0x1
	shareAccessWrite = 0x2
	shareAccessBoth  = 0x3

	shareAccessWantDelegMask    = 0xFF00
	shareAccessWantNoPreference = 0x0000
	shareAccessWantReadDeleg    = 0x0100
	shareAccessWantWriteDeleg   = 0x0200
	shareAccessWantAnyDeleg     = 0x0300
	shareAccessWantNoDeleg      = 0x0400
	shareAccessWantCancel       = 0x0500
	shareAccessWantFlagsMask    = 0x30000 // WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL | WANT_PUSH_DELEG_WHEN_UNCONTENDED

	openResultLocktypePOSIX = 0x4

	opentypeNoCreate = 0
	opentypeCreate   = 1

	createUnchecked  = 0
	createGuarded    = 1
	createExclusive  = 2
	createExclusive4 = 3

	claimNull         = 0
	claimPrevious     = 1
	claimDelegateCur  = 2
	claimDelegatePrev = 3
	claimFH           = 4
	claimDelegCurFH   = 5
	claimDelegPrevFH  = 6

	delegNone    = 0
	delegRead    = 1
	delegWrite   = 2
	delegNoneExt = 3

	wndNotWanted    = 0
	wndContention   = 1
	wndResource     = 2
	wndNotSuppFtype = 3
	wndCancelled    = 7
	wndIsDir        = 8

	lockTypeRead   = 1
	lockTypeWrite  = 2
	lockTypeReadW  = 3
	lockTypeWriteW = 4

	sp4None = 0

	cdfcFore       = 0x1
	cdfcBack       = 0x2
	cdfcForeOrBoth = 0x3
	cdfcBackOrBoth = 0x7
	cdfsFore       = 0x1
	cdfsBack       = 0x2
	cdfsBoth       = 0x3

	gddOK      = 0
	gddUnavail = 1

	secinfoStyleCurrentFH = 0
	secinfoStyleParent    = 1

	seekData = 0 // NFS4_CONTENT_DATA
	seekHole = 1 // NFS4_CONTENT_HOLE
)
