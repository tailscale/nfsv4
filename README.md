# nfsv4

[![status: experimental](https://img.shields.io/badge/status-experimental-blue)](https://tailscale.com/kb/1167/release-stages/#experimental)
[![Go Reference](https://pkg.go.dev/badge/github.com/tailscale/nfsv4.svg)](https://pkg.go.dev/github.com/tailscale/nfsv4)

`github.com/tailscale/nfsv4` is a Go library for writing read-only NFSv4.1
servers for virtual filesystems, such as
[gomodfs](https://github.com/tailscale/gomodfs).

It's designed to give the filesystem control rather than hide the protocol:

* **Cache control.** Filesystems decide per object whether clients may cache it
  without revalidating, using NFSv4.1 read delegations on files *and
  directories*. Immutable subtrees can be cached by clients forever; live
  objects can be revalidated by clients or recalled by the server when they
  change.
* **Filehandles your way.** Implement `nfsv4.FS` with your own opaque
  filehandles (up to 128 bytes), or use `nodefs` and never think about them:
  it derives filehandles from paths so they survive server restarts with no
  persistent state.
* **No root, no rpcbind.** NFSv4 needs only one TCP port, any port. Clients
  mount it directly.

## Mounting

```
# Linux
sudo mount -t nfs4 -o vers=4.2,port=2049,ro HOST:/ /mnt

# macOS 26+ (vers=4.1 is required, as plain vers=4 means 4.0; without
# rsize, macOS reads only 32 KiB at a time; "soft" isn't allowed)
sudo mount -t nfs -o vers=4.1,port=2049,rdonly,rsize=1048576 HOST:/ /mnt
```

Try it with the demo server:

```
go run ./cmd/nfs4serve                 # in-memory demo filesystem
go run ./cmd/nfs4serve -dir ~/go/pkg/mod -immutable
```

## Using it

With [`nodefs`](https://pkg.go.dev/github.com/tailscale/nfsv4/nodefs), implement a tree of nodes:

```go
type myDir struct{ /* ... */ }

func (d *myDir) Attr(r *nfsv4.Request) (*nfsv4.Attrs, error) {
	return &nfsv4.Attrs{Type: nfsv4.TypeDir, Mode: 0o555, Change: 1}, nil
}
func (d *myDir) Lookup(r *nfsv4.Request, name string) (nodefs.Node, error) { /* ... */ }
func (d *myDir) ReadDir(r *nfsv4.Request) ([]nodefs.DirEntry, error)       { /* ... */ }

// Optional: let clients cache this directory forever.
func (d *myDir) CachePolicy(r *nfsv4.Request) nfsv4.Delegation {
	return nfsv4.Delegation{Grant: true}
}

// Files implement ReadAt(r, p, off); symlinks implement Readlink(r).

srv := &nfsv4.Server{FS: nodefs.New(root, nil)}
ln, _ := net.Listen("tcp", ":2049")
srv.Serve(ln)
```

To change an object that clients may hold delegations for, recall them
first, then change it, then release:

```go
release, err := fs.Recall(ctx, srv, "live/status.txt")
if err != nil {
	return err
}
updateStatus()
release()
```

See [memfs](./memfs) for a complete example, and the package documentation
for the details of client caching behavior.

## Status

Tested against the Linux 7.0 kernel client (NFSv4.1 and 4.2) and the macOS
26 client (NFSv4.1). The tests that mount with the kernel need root or
passwordless sudo and run with `go test -mount` (or `NFSV4_MOUNT_TEST=1`).
Among other things, they check:

* reads, directory listings, symlinks, and executing files
* that with delegations, the Linux client sends *no* requests at all for
  repeated access to delegated files and directories, even with
  `actimeo=1`
* that changes to live files and directories are seen promptly
* that a mount survives a server restart with a fresh `nodefs` (no state
  carried over), including open files and processes whose working
  directory is deep inside the mount

Read-only only: no writes, no NFSv4.0, no Kerberos, no ACLs or extended
attributes, no pNFS.
