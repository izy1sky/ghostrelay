package main

import (
	"encoding/json"
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
// A node started with flags only (no settings file) keeps none of them.

func sidecar(cfg, suffix string) string { return strings.TrimSuffix(cfg, ".json") + suffix }

type nodeStatus struct {
	State   string    `json:"state"` // connecting | connected | paused
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
	if l.cfg == "" {
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
