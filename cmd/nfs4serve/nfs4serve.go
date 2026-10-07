// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The nfs4serve command serves a local directory, or a demo in-memory
// filesystem, read-only over NFSv4.1.
//
// It doesn't need root: it listens on an unprivileged port (2049 by
// default, which is above 1024), and clients mount it on that port
// directly, with no portmapper or mountd.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/memfs"
	"github.com/tailscale/nfsv4/osfs"
)

var (
	listen    = flag.String("listen", "127.0.0.1:2049", "address to listen on")
	dir       = flag.String("dir", "", "directory to serve; if empty, serve a demo in-memory filesystem")
	immutable = flag.Bool("immutable", false, "with --dir, promise the directory never changes, letting clients cache it forever")
	verbose   = flag.Bool("v", false, "log every operation")
	lease     = flag.Duration("lease", 0, "lease time (default 90s)")
)

func main() {
	flag.Parse()
	srv := &nfsv4.Server{LeaseTime: *lease}
	if *verbose {
		srv.Debugf = log.Printf
	}
	var demo *memfs.FS
	if *dir != "" {
		fs, err := osfs.New(*dir, &osfs.Options{Immutable: *immutable})
		if err != nil {
			log.Fatal(err)
		}
		srv.FS = fs
	} else {
		demo = newDemo()
		demo.SetServer(srv)
		srv.FS = demo
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	host := ln.Addr().(*net.TCPAddr).IP.String()
	if ip := ln.Addr().(*net.TCPAddr).IP; ip.IsUnspecified() {
		host = "HOST"
	}
	log.Printf("serving on %v", ln.Addr())
	fmt.Fprintf(os.Stderr, `
Mount with:
  Linux: sudo mount -t nfs4 -o vers=4.2,port=%d,ro %s:/ /mnt
  macOS: sudo mount -t nfs -o vers=4.1,port=%d,rdonly %s:/ /mnt

`, port, host, port, host)

	if demo != nil {
		go updateDemo(demo)
	}
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		srv.Close()
	}()
	if err := srv.Serve(ln); err != nil && err != nfsv4.ErrServerClosed {
		log.Fatal(err)
	}
}

func newDemo() *memfs.FS {
	m := memfs.New()
	m.WriteFile("README", []byte(strings.TrimSpace(`
This is a demo filesystem served by github.com/tailscale/nfsv4.

immutable/ never changes, so clients are given delegations to cache it
forever. live/clock.txt changes every few seconds; clients holding a
delegation for it are sent a recall when it does.
`)+"\n"), 0o444)
	for i := range 10 {
		m.WriteFile(fmt.Sprintf("immutable/dir%d/file.txt", i), []byte(fmt.Sprintf("file %d\n", i)), 0o444)
	}
	m.Symlink("dir0/file.txt", "immutable/link")
	m.SetImmutable("immutable")
	m.WriteFile("live/clock.txt", []byte(time.Now().Format(time.RFC3339)+"\n"), 0o444)
	m.SetCachePolicy("live", nfsv4.Delegation{Grant: true})
	return m
}

func updateDemo(m *memfs.FS) {
	for range time.Tick(5 * time.Second) {
		if err := m.WriteFile("live/clock.txt", []byte(time.Now().Format(time.RFC3339)+"\n"), 0o444); err != nil {
			log.Printf("updating clock: %v", err)
		}
	}
}
