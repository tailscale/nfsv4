// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The nfstestserve command serves test data and a local control socket.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tailscale/nfsv4"
	"github.com/tailscale/nfsv4/memfs"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:23049", "NFS address")
	control := flag.String("control", "", "Unix control socket path (required)")
	flag.Parse()
	if *control == "" {
		log.Fatal("-control is required")
	}
	m := memfs.New()
	must := func(err error) {
		if err != nil {
			log.Fatal(err)
		}
	}
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 251)
	}
	for _, tree := range []string{"immutable", "delegated", "live"} {
		must(m.WriteFile(tree+"/blob", data, 0o444))
		must(m.WriteFile(tree+"/deep/a/b/text", []byte("before\n"), 0o444))
		must(m.Symlink("deep/a/b/text", tree+"/link"))
		for i := 0; i < 256; i++ {
			name := "entry" + string(rune('A'+i/26)) + string(rune('a'+i%26))
			must(m.WriteFile(tree+"/listing/"+name, []byte(name), 0o444))
		}
	}
	m.SetImmutable("immutable")
	m.SetCachePolicy("delegated", nfsv4.Delegation{
		Grant: true,
	})
	srv := &nfsv4.Server{
		FS:        m,
		LeaseTime: 10 * time.Second,
		Debugf:    log.Printf,
		Logf:      log.Printf,
	}
	m.SetServer(srv)
	ln, err := net.Listen("tcp", *listen)
	must(err)
	if err := os.Remove(*control); err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}
	ctl, err := net.Listen("unix", *control)
	must(err)
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(srv.Stats()) })
	mux.HandleFunc("/write", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("path")
		if r.Method != "POST" || !(strings.HasPrefix(p, "delegated/") || strings.HasPrefix(p, "live/")) || strings.Contains(p, "..") {
			http.Error(w, "invalid mutation", 400)
			return
		}
		data, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if err == nil {
			log.Printf("mutation start: %s", p)
			err = m.WriteFile(p, data, 0o444)
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		log.Printf("mutation complete: %s", p)
		json.NewEncoder(w).Encode(srv.Stats())
	})
	mux.HandleFunc("/remove", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("path")
		if r.Method != "POST" || !(strings.HasPrefix(p, "delegated/") || strings.HasPrefix(p, "live/")) || strings.Contains(p, "..") {
			http.Error(w, "invalid mutation", 400)
			return
		}
		log.Printf("remove start: %s", p)
		if err := m.Remove(p); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		log.Printf("remove complete: %s", p)
		json.NewEncoder(w).Encode(srv.Stats())
	})
	go http.Serve(ctl, mux)
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		ctl.Close()
		srv.Close()
	}()
	log.Printf("ready on %s", ln.Addr())
	if err := srv.Serve(ln); err != nil && err != nfsv4.ErrServerClosed {
		log.Fatal(err)
	}
}
