// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/memfs"
)

// deepDir is a directory path too long to encode verbatim in a
// filehandle, so nodefs hashes its trailing components.
var deepDir = strings.Repeat("a-rather-long-directory-name/", 6) + "leaf"

func newRestartTree() *memfs.FS {
	m := memfs.New()
	m.WriteFile("top.txt", []byte("top\n"), 0o644)
	big := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
	m.WriteFile(deepDir+"/big.dat", big, 0o644)
	m.WriteFile(deepDir+"/rel.txt", []byte("relative\n"), 0o644)
	m.WriteFile("short/dir/file.txt", []byte("short\n"), 0o644)
	return m
}

// TestKernelServerRestart checks that a mount keeps working across a
// server restart with a fresh nodefs.FS (and so no memory of previously
// issued filehandles), including open files and working directories
// inside the mount.
func TestKernelServerRestart(t *testing.T) {
	skipUnlessMountTest(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	srv1 := &nfsv4.Server{FS: newRestartTree(), Logf: t.Logf}
	go srv1.Serve(ln)
	dir := mountPort(t, port, "vers=4.2")

	// Hold an open file deep in the tree and read part of it.
	f, err := os.Open(dir + "/" + deepDir + "/big.dat")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 4096)
	if _, err := io.ReadFull(f, buf); err != nil {
		t.Fatal(err)
	}

	// Start a process whose working directory is deep in the mount,
	// which reads a file by relative path once told to.
	cmd := exec.Command("sh", "-c", "read x; cat rel.txt; cat ../leaf/rel.txt; ls")
	cmd.Dir = dir + "/" + deepDir
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// Restart the server with a brand new FS on the same port.
	srv1.Close()
	var ln2 net.Listener
	for range 50 {
		ln2, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	srv2 := &nfsv4.Server{FS: newRestartTree(), Logf: t.Logf}
	go srv2.Serve(ln2)

	// The open file keeps working. (Drop the page cache first so the
	// reads really go to the new server.)
	exec.Command("sudo", "-n", "sh", "-c", "echo 3 > /proc/sys/vm/drop_caches").Run()
	rest, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("reading open file after restart: %v", err)
	}
	if len(rest) != 1<<20-4096 {
		t.Errorf("read %d bytes after restart; want %d", len(rest), 1<<20-4096)
	}
	if !bytes.HasPrefix(rest, []byte("0123456789abcdef")) {
		t.Errorf("unexpected data after restart: %q", rest[:16])
	}

	// The process in the deep working directory keeps working.
	io.WriteString(stdin, "go\n")
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Errorf("subprocess: %v\n%s", err, out.Bytes())
	}
	if got := out.String(); got != "relative\nrelative\nbig.dat\nrel.txt\n" {
		t.Errorf("subprocess output = %q", got)
	}

	// And plain path lookups work.
	got, err := os.ReadFile(dir + "/short/dir/file.txt")
	if err != nil || string(got) != "short\n" {
		t.Errorf("ReadFile = %q, %v", got, err)
	}
	t.Logf("new server stats after %v: %+v", time.Since(start), srv2.Stats())

	// Unmount before stopping the server, so unmounting doesn't wait
	// for the server to time out.
	f.Close()
	unmount(t, dir)
	srv2.Close()
}
