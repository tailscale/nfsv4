// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package nfsv4 implements a read-only NFSv4.1 server for virtual
// filesystems.
//
// The server speaks NFSv4 minor versions 1 and 2 (RFC 8881, RFC 7862) over
// TCP, which the Linux and macOS (since macOS 26) kernels can mount
// directly on any port, with no portmapper, mountd, or root privileges on
// the server side. Write operations fail with ErrROFS.
//
// # Layers
//
// The FS interface is close to the protocol: it deals in opaque,
// caller-chosen filehandles (up to 128 bytes), NFSv4 attributes, READDIR
// cookies, and NFSv4 status codes. Callers that want full control over
// filehandle encoding implement it directly.
//
// Callers that don't want to think about filehandles use package nodefs,
// which implements FS on top of a tree of directory, file, and symlink
// nodes, deriving filehandles from paths so that they survive server
// restarts without any persistent state. Package memfs (in-memory) and
// package osfs (a local directory) are built on nodefs.
//
// # Cache control
//
// NFSv4 has no notion of "cache this for N seconds" or "valid forever" on
// the wire. Clients cache attributes and directory entries for a time set
// by their own mount options (acregmin, acregmax, acdirmin, acdirmax,
// actimeo) and revalidate using the change attribute (Attrs.Change).
//
// The server-side lever is delegations: an FS implementing Delegator can
// grant clients read delegations on files (when they're opened) and on
// directories (when the client asks for a directory delegation). A
// delegation is a promise that the object won't change without the client
// being told first. While holding one, the Linux client doesn't revalidate
// at all: no GETATTR, LOOKUP, ACCESS, or READDIR for delegated directories
// and their entries, and no GETATTR or OPEN round trips for delegated
// files. That makes delegations the way to mark immutable subtrees as
// valid forever.
//
// For objects that can change, either don't grant delegations (clients then
// revalidate on their own schedule), or grant them and use Server.Recall
// around changes. Delegation.MaxAge bounds how long a delegation lives.
//
// Client behavior worth knowing about:
//
//   - The Linux client (as of 7.0) asks for directory delegations when it
//     revalidates a directory it has checked access to (the
//     nfs4.directory_delegations module parameter, on by default), and
//     holds them until they're recalled or the directory's inode is
//     evicted from its cache.
//   - The Linux client returns file delegations for files it hasn't used
//     in a while (about one to two lease periods after the last close),
//     and returns the least recently used ones when it holds more than
//     the nfs.delegation_watermark module parameter (5000 by default).
//     Reopening a file whose delegation was returned costs one OPEN round
//     trip, which also revalidates it.
//   - The macOS client doesn't use directory delegations, and file
//     delegations only extend its attribute cache lifetime to acregmax.
//     Long-lived caching on macOS mostly comes from mount options.
//   - Delegations need a callback channel. NFSv4.1 clients run it over
//     their own TCP connection to the server, so it works through NAT and
//     userspace networking. Delegations aren't granted to clients without
//     one.
//
// # Filehandles and restarts
//
// The server advertises persistent filehandles. Clients keep using
// filehandles across server restarts (the server's client state is lost,
// and clients transparently reclaim it). Opens are always reclaimable,
// since read-only opens can't conflict. A filehandle the FS no longer
// recognizes should get ErrStale, from which the Linux and macOS clients
// recover by looking names up again from the parent directory, but that
// doesn't work for open files or processes whose working directory is in
// the mount, and never for the root filehandle.
//
// # Not supported
//
// Not supported: writes, NFSv4.0, Kerberos (only AUTH_SYS and AUTH_NONE are
// accepted, and credentials are passed to the FS for its own checks), ACLs,
// named attributes and extended attributes, pNFS, referrals, and
// directory change notifications (directory delegations are recalled
// instead). Byte-range locks are always granted, since locks on read-only
// files never conflict.
package nfsv4
