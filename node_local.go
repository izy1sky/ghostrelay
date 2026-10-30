package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// A node keeps three small files next to its settings file, so the local page
// (bare `relay`) can show and steer it whether it runs as a service, under the
// page, or in a terminal:
//
//	node.status.json     connected or not, since when; rewritten every 5 s
//	node.activity.jsonl  what agents did on this machine (rotated at 1 MiB)
//	node.paused          while it exists, the node stays disconnected
//
// If the settings file itself disappears (relay leave), the node stops.
//
// A node started with flags only (no settings file) keeps none of them.

func sidecar(cfg, suffix string) string { return strings.TrimSuffix(cfg, ".json") + suffix }

type nodeStatus struct {
	State   string    `json:"state"` // connecting | connected | paused | disconnected (by the hub)
	Since   time.Time `json:"since"`
	Server  string    `json:"server"`
	Error   string    `json:"error,omitempty"`
	Version string    `json:"version"`
	Updated time.Time `json:"updated"`
}

// statusStale is how old node.status.json may get before the node counts as
// not running: three missed heartbeats.
const statusStale = 15 * time.Second

type activity struct {
	T     time.Time `json:"t"`
	Op    string    `json:"op"`
	What  string    `json:"what"`
	OK    bool      `json:"ok"`
	Error string    `json:"error,omitempty"`
}

type nodeLocal struct {
	cfg string
	mu  sync.Mutex
	st  nodeStatus
}

func newNodeLocal(cfg, server string) *nodeLocal {
	l := &nodeLocal{cfg: cfg, st: nodeStatus{Server: server, Version: version}}
	if cfg != "" {
		go func() {
			for range time.Tick(5 * time.Second) {
				l.mu.Lock()
				l.writeLocked()
				l.mu.Unlock()
			}
		}()
	}
	return l
}

func (l *nodeLocal) paused() bool {
	if l == nil || l.cfg == "" {
		return false
	}
	_, err := os.Stat(sidecar(l.cfg, ".paused"))
	return err == nil
}

// gone reports whether the settings file was removed, by relay leave.
func (l *nodeLocal) gone() bool {
	if l == nil || l.cfg == "" {
		return false
	}
	_, err := os.Stat(l.cfg)
	return errors.Is(err, os.ErrNotExist)
}

func (l *nodeLocal) state() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.st.State
}

func (l *nodeLocal) set(state, errText string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.st.State != state {
		l.st.State, l.st.Since = state, time.Now()
	}
	l.st.Error = errText
	l.writeLocked()
}

func (l *nodeLocal) writeLocked() {
	if l.cfg == "" || l.gone() {
		return
	}
	l.st.Updated = time.Now()
	writeJSON0600(sidecar(l.cfg, ".status.json"), l.st)
}

// quietOps are polling and transfer plumbing: recording them would bury the
// calls a person wants to see.
var quietOps = map[string]bool{"fs_stat": true, "fs_walk": true, "job_logs": true, "jobs_list": true,
	"get_chunk": true, "put_chunk": true, "put_close": true, "put_abort": true}

func (l *nodeLocal) record(op string, raw json.RawMessage, err error) {
	if l == nil || l.cfg == "" || quietOps[op] {
		return
	}
	var a struct {
		Command, Cwd, Path, Src, Dst, Pattern, ID string
		Argv                                      []string
	}
	json.Unmarshal(raw, &a)
	what := a.Path
	switch {
	case a.Command != "":
		what = a.Command
	case len(a.Argv) > 0:
		what = strings.Join(a.Argv, " ")
	case a.Src != "":
		what = a.Src + " → " + a.Dst
	case a.Pattern != "":
		what = a.Pattern + " in " + firstNonEmpty(a.Path, ".")
	case a.ID != "":
		what = a.ID
	}
	if op == "exec" && a.Cwd != "" {
		what += "   (in " + a.Cwd + ")"
	}
	if op == "put_open" {
		op = "receive"
	}
	rec := activity{T: time.Now(), Op: op, What: what, OK: err == nil}
	if err != nil {
		rec.Error = err.Error()
	}
	b, _ := json.Marshal(rec)
	l.mu.Lock()
	defer l.mu.Unlock()
	path := sidecar(l.cfg, ".activity.jsonl")
	if st, err := os.Stat(path); err == nil && st.Size() > 1<<20 {
		os.Rename(path, path+".1")
	}
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		f.Write(append(b, '\n'))
		f.Close()
	}
}

// ---- relay pause / resume / leave ---------------------------------------------------

// setPaused creates or removes the pause file; a running node notices within 2 s.
func setPaused(cfg string, paused bool) error {
	p := sidecar(cfg, ".paused")
	if !paused {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if _, err := os.Stat(cfg); err != nil {
		return fmt.Errorf("this computer isn't shared (no %s)", cfg)
	}
	return writePrivate(p, []byte("Paused with relay pause or the relay page. Delete this file, or run relay resume, to resume.\n"))
}

// leaveNode stops sharing this computer for good: it removes the background
// service, if any, and the settings, so a node still running in a terminal
// stops by itself within 2 s.
func leaveNode(cfg string) error {
	if s, err := newService("node", cfg); err == nil && s.installed() {
		if err := s.uninstall(); err != nil {
			return err
		}
	}
	for _, suffix := range []string{".json", ".status.json", ".paused", ".activity.jsonl", ".activity.jsonl.1"} {
		if err := os.Remove(sidecar(cfg, suffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func runNodeSwitch(cmd string, args []string) {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfg := fs.String("config", defaultNodeConfig(), "this node's settings, written by relay join")
	fs.Parse(args)
	var err error
	switch cmd {
	case "pause":
		if err = setPaused(*cfg, true); err == nil {
			fmt.Println("paused: agents can't reach this computer until relay resume (a running node disconnects within 2 s)")
		}
	case "resume":
		if err = setPaused(*cfg, false); err == nil {
			fmt.Println("resumed: the node reconnects within a few seconds, if it's running (relay service status)")
		}
	case "leave":
		if _, statErr := os.Stat(*cfg); statErr != nil {
			log.Fatalf("this computer isn't shared (no %s)", *cfg)
		}
		if err = leaveNode(*cfg); err == nil {
			fmt.Println("left the hub: the background service (if any) is removed and the settings deleted. To share again: relay join <code>, or relay")
		}
	}
	if err != nil {
		log.Fatal(err)
	}
}
