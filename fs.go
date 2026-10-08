// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4

import (
	"context"
	"net"
	"time"
)

// FileHandle is an NFSv4 filehandle: opaque bytes, at most MaxFileHandleSize
// (128) bytes long, chosen by the FS implementation.
//
// Clients treat filehandles as opaque identifiers and hold onto them
// indefinitely, including across server restarts. The server advertises its
// filehandles as persistent (FH4_PERSISTENT, unless configured otherwise), so
// an FS should be able to resolve any filehandle it ever handed out for as
// long as the object exists, even after the process restarts.
// Return ErrStale for filehandles that no longer resolve; clients recover
// from that by looking the name up again from the parent directory. The root
// filehandle must never become stale: neither the Linux nor the macOS client
// can recover a mount whose root filehandle stops working.
//
// FS implementations that don't want to think about any of this can use the
// nodefs package, which manages filehandles itself.
type FileHandle []byte

// FS is a read-only filesystem served over NFSv4 by a Server.
//
// Methods are called concurrently. Methods that operate on a filehandle
// should return ErrStale or ErrBadHandle for unknown filehandles.
// Errors may be Status values (such as ErrNoEnt) or other errors that are
// mapped to a Status (see Server.Logf for errors that have no natural mapping).
// PUTFH uses GetAttr to validate handles and returns ErrServerFault if the
// mapped error is not valid for that operation.
//
// Optional behavior is provided by implementing additional interfaces:
// Delegator (cache control), Opener, Accesser, and StatFSer.
type FS interface {
	// Root returns the root filehandle. It's called for each PUTROOTFH
	// operation, so it should be cheap. It must return the same filehandle
	// for the lifetime of the filesystem, including across restarts.
	Root(r *Request) (FileHandle, error)

	// GetAttr returns the attributes of fh.
	//
	// The want mask says which attributes the client asked for. It's a
	// hint: implementations may use it to skip expensive work, but may
	// also return attributes that weren't asked for. It always includes
	// the basic attributes (type, change, size, fileid, mode, numlinks,
	// owner, owner_group, and the times), so it's mostly useful for
	// skipping work for clients that only want those. Attributes the
	// server computes itself (such as lease_time) are never in want.
	GetAttr(r *Request, fh FileHandle, want AttrMask) (*Attrs, error)

	// Lookup looks up name in the directory dir and returns its
	// filehandle. If convenient, it may also return the child's
	// attributes, saving a subsequent GetAttr call; otherwise attrs may be
	// nil.
	//
	// Lookup must return ErrNoEnt if the name doesn't exist and ErrNotDir
	// if dir isn't a directory (or ErrSymlink if it's a symlink). The
	// names "." and ".." are never passed to Lookup.
	Lookup(r *Request, dir FileHandle, name string) (fh FileHandle, attrs *Attrs, err error)

	// LookupParent returns the parent directory of the directory dir.
	// It's never called for the root. Implementations that can't
	// determine parents may return ErrNotSupp, but some client
	// operations (such as resolving ".." from an open-by-handle
	// directory, or NFS re-exports) won't work.
	LookupParent(r *Request, dir FileHandle) (FileHandle, error)

	// ReadDir lists the directory dir, calling emit for each entry in
	// order, starting after the position described by args.Cookie. It
	// stops early, returning nil, if emit returns false, which means the
	// client's reply buffer is full. Not returning "." or ".." entries is
	// the FS's responsibility.
	//
	// See ReadDirArgs and DirEntry for the cookie and verifier rules.
	ReadDir(r *Request, dir FileHandle, args ReadDirArgs, emit func(DirEntry) bool) (ReadDirResult, error)

	// Read reads up to len(p) bytes of the regular file fh starting at
	// offset off into p, returning the number of bytes read and whether
	// the read reached the end of the file. Reading at or past the end
	// of the file returns 0, true, nil. Returning fewer bytes than
	// requested without eof is allowed; the client will issue another
	// read.
	//
	// p is the server's reply buffer, so data is written directly into
	// the reply with no extra copy. Read must return ErrIsDir for
	// directories and ErrInval for other non-regular files.
	Read(r *Request, fh FileHandle, off uint64, p []byte) (n int, eof bool, err error)

	// ReadLink returns the target of the symlink fh. It must return
	// ErrInval if fh isn't a symlink (ErrIsDir for directories).
	ReadLink(r *Request, fh FileHandle) (string, error)
}

// ReadDirArgs are the arguments to FS.ReadDir.
type ReadDirArgs struct {
	// Cookie is where to resume listing. Zero means the beginning of the
	// directory. Otherwise it's a DirEntry.Cookie value the FS returned
	// earlier, and listing resumes with the entry after that one.
	Cookie uint64

	// Verifier is the ReadDirResult.Verifier value the FS returned along
	// with Cookie, or zero when Cookie is zero. An FS whose cookies can be
	// invalidated by directory changes uses the verifier to detect stale
	// cookies, returning ErrNotSame (or ErrBadCookie) for them.
	Verifier uint64

	// Want is the set of attributes the client wants for each entry, as
	// in FS.GetAttr. If it includes AttrFileHandle, the client wants
	// each entry's filehandle. If it is empty, the client wants only
	// names and cookies.
	Want AttrMask
}

// ReadDirResult is the result of FS.ReadDir.
type ReadDirResult struct {
	// Verifier is the cookie verifier the client should send back with
	// future cookies from this listing. Zero is fine for FSes with
	// stable cookies.
	Verifier uint64
}

// DirEntry is a directory entry returned by FS.ReadDir.
type DirEntry struct {
	// Name is the entry's name.
	Name string

	// Cookie identifies the entry's position, such that listing again
	// with ReadDirArgs.Cookie set to this value resumes with the next
	// entry. Cookies must be at least 3; the values 0, 1, and 2 are
	// reserved by the protocol.
	Cookie uint64

	// Handle is the entry's filehandle. It's required if the client asked
	// for any attributes (ReadDirArgs.Want is non-empty).
	Handle FileHandle

	// Attrs are the entry's attributes, if already known. If nil and the
	// client wants attributes, the server calls FS.GetAttr(Handle).
	Attrs *Attrs
}

// Attrs are the per-object attributes of a file, directory, or other
// filesystem object.
//
// Attributes that describe the filesystem as a whole (such as maxname or
// lease_time) are not here; they come from the Server configuration, and
// space and file counts come from the optional StatFSer interface.
type Attrs struct {
	// Type is the object's type. It's required.
	Type FileType

	// Change is the change attribute: an opaque value that must change
	// whenever the object's contents or attributes change (for
	// directories: whenever entries are added, removed, or renamed).
	// Clients compare it to decide whether their cached data is still
	// valid, so an object that never changes should keep a constant
	// Change, and a live object should always report a new value after
	// changing, even if its size and modification time are unchanged.
	Change uint64

	// Size is the size in bytes. For symlinks, it should be the length of
	// the target.
	Size uint64

	// SpaceUsed is the number of bytes of storage used. If zero, the
	// server reports Size.
	SpaceUsed uint64

	// FileID is the object's unique number within its filesystem (its
	// "inode number"). It must be unique, and as stable as the object's
	// filehandle: clients that see a different FileID for a filehandle
	// they know (such as after a server restart) consider the object
	// gone and return ESTALE to applications.
	FileID uint64

	// MountedOnFileID is the mounted_on_fileid attribute. If zero, the
	// server reports FileID, which is what's wanted unless the object is
	// the root of a filesystem mounted on another object (see FSID).
	MountedOnFileID uint64

	// Mode holds the permission bits (0o7777). Type bits are ignored.
	Mode uint32

	// NumLinks is the number of hard links. If zero, the server reports
	// 1 (or 2 for directories).
	NumLinks uint32

	// UID and GID are the numeric owner and group. They're sent as
	// decimal strings, which both the Linux and macOS clients accept with
	// AUTH_SYS.
	UID, GID uint32

	// Owner and Group, if non-empty, are sent as the owner and
	// owner_group attributes verbatim instead of UID and GID (for
	// instance "alice@example.com").
	Owner, Group string

	// RawDev is the device number for block and character devices.
	RawDev Device

	// ModTime is the time of the last modification of the contents.
	ModTime time.Time

	// ChangeTime is the time of the last change of contents or
	// attributes (time_metadata, ctime). If zero, ModTime is reported.
	ChangeTime time.Time

	// AccessTime is the time of last access. If zero, ModTime is
	// reported.
	AccessTime time.Time

	// BirthTime is the creation time. If zero, it's omitted.
	BirthTime time.Time

	// FSID, if non-nil, is the identifier of the filesystem containing
	// this object. If nil, the Server's FSID is reported.
	//
	// Clients treat a directory whose FSID differs from its parent's as
	// the root of a different filesystem and make it a separate
	// (automatic) mount point. Most FS implementations should leave this
	// nil.
	FSID *FSID
}

// Device is a block or character device number.
type Device struct {
	Major, Minor uint32
}

// FSID is a filesystem identifier (the fsid attribute).
type FSID struct {
	Major, Minor uint64
}

// Request describes the context of an FS method call: one COMPOUND
// procedure from a client.
type Request struct {
	ctx context.Context

	// Cred is the RPC credential of the caller.
	Cred Cred

	// RemoteAddr and LocalAddr are the connection's addresses.
	RemoteAddr, LocalAddr net.Addr

	// Client is the client that sent the request. It's nil only for
	// requests that aren't part of a session, which never reach an FS.
	Client *ClientInfo

	// MinorVersion is the NFSv4 minor version (1 or 2) of the request.
	MinorVersion uint32
}

// Context returns the request's context. It's canceled when the client's
// connection closes or the server shuts down.
func (r *Request) Context() context.Context { return r.ctx }

// Cred is an RPC credential.
type Cred struct {
	// Flavor is the RPC auth flavor: 0 (AUTH_NONE) or 1 (AUTH_SYS).
	Flavor uint32

	// UID, GID, and GIDs are the user's numeric identity for AUTH_SYS.
	// For AUTH_NONE they're 65534 ("nobody") and nil.
	UID, GID uint32
	GIDs     []uint32

	// MachineName is the AUTH_SYS machine name (usually the client's
	// hostname).
	MachineName string
}

// ClientInfo describes an NFSv4 client, as identified by the EXCHANGE_ID
// operation.
type ClientInfo struct {
	// ID is the server-assigned client ID.
	ID uint64

	// OwnerID is the client's self-chosen unique identifier
	// (co_ownerid). The Linux client uses a string like
	// "Linux NFSv4.1 hostname".
	OwnerID []byte

	// ImplDomain, ImplName, and ImplDate describe the client
	// implementation (such as "kernel.org" and "Linux 7.0.0 ..."), if the
	// client sent them.
	ImplDomain string
	ImplName   string
	ImplDate   time.Time
}

// Delegation is a cache-control decision made by a Delegator.
//
// An NFSv4 read delegation is a promise from the server that an object
// won't change without the client being told first (with a recall). While
// a client holds a delegation it can cache the object without
// revalidating: the Linux client stops sending GETATTR, LOOKUP, and
// ACCESS revalidations for delegated files and directories, and for a
// delegated directory also trusts its cached directory listing and
// child names. The macOS client uses delegations to extend its attribute
// cache lifetime to the acregmax mount option's value and doesn't use
// directory delegations.
//
// The zero value grants no delegation; the client then revalidates on its
// own schedule (governed by its acregmin/acregmax/acdirmin/acdirmax mount
// options).
type Delegation struct {
	// Grant says whether to grant a read delegation.
	Grant bool

	// MaxAge, if non-zero, limits how long a delegation may be held. The
	// server recalls it after this long. Zero means the delegation is
	// held until it's recalled with Server.Recall (for immutable
	// objects: forever) or the client returns it voluntarily.
	MaxAge time.Duration
}

// Delegator is an optional interface an FS can implement to control
// client caching by granting delegations.
//
// Delegations require a working callback channel to the client, which
// NFSv4.1 clients normally establish over their own connection. The server
// only consults the Delegator when one exists.
//
// An FS that grants delegations for an object that can change must change it
// only while its delegations are recalled; see Server.Recall. For immutable
// objects there's nothing to do.
type Delegator interface {
	// Delegate decides whether to grant a read delegation for fh, a
	// regular file being opened or a directory for which the client asked
	// for a directory delegation. attrs are the object's current
	// attributes.
	Delegate(r *Request, fh FileHandle, attrs *Attrs) Delegation
}

// Opener is an optional interface an FS can implement to observe or veto
// opens of regular files.
//
// Clients open files before reading them, but may also read without an open
// (using special stateids), and clients holding a delegation open files
// locally without telling the server, so Open and Close are not a reliable
// way to track file usage.
type Opener interface {
	// Open is called when a client opens fh, a regular file, for
	// reading. Returning an error fails the open.
	Open(r *Request, fh FileHandle, attrs *Attrs) error

	// Close is called when the client closes the open state for fh,
	// or when the server discards it (such as when a client's lease
	// expires).
	Close(fh FileHandle)
}

// Accesser is an optional interface an FS can implement to decide the
// results of ACCESS operations, which clients use for permission checks.
//
// Without it, the server computes access from the Mode, UID, and GID
// attributes and the request's credential, never granting AccessModify,
// AccessExtend, or AccessDelete.
type Accesser interface {
	// Access returns which of the requested access bits (AccessRead
	// etc.) are allowed for fh.
	Access(r *Request, fh FileHandle, attrs *Attrs, requested uint32) (allowed uint32, err error)
}

// StatFSer is an optional interface an FS can implement to report
// filesystem space and file counts (the attributes behind df(1)).
// Without it, all values are reported as zero.
type StatFSer interface {
	StatFS(r *Request, fh FileHandle) (*FSStat, error)
}

// FSStat holds filesystem-wide space and file counts.
type FSStat struct {
	SpaceTotal, SpaceFree, SpaceAvail uint64 // bytes
	FilesTotal, FilesFree, FilesAvail uint64
}
