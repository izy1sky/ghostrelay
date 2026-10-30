package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// The console at /admin/: machines, adding one, approvals and grants,
// connecting an agent, and the activity log. Every API below needs the admin
// token, like approvals always have.

//go:embed ui/console.html
var consolePage string

func (s *server) handleNodes(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	type nodeOut struct {
		NodeInfo
		Remote      string    `json:"remote"`
		ConnectedAt time.Time `json:"connected_at"`
	}
	out := []nodeOut{}
	for _, nc := range s.nodeList() {
		out = append(out, nodeOut{nc.info, nc.remote, nc.connectedAt})
	}
	writeJSON(w, map[string]any{"connected": out, "disconnected": s.blocked.list()})
}

// handleSetup gives the console what it shows on "Add a machine" and
// "Connect an agent": the join code and the agent token are secrets, and the
// admin token already grants more than either.
func (s *server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	p := s.pol.Load()
	var agents []string
	for _, a := range p.agents {
		agents = append(agents, a.Name)
	}
	res := map[string]any{
		"version": version, "url": s.pubURL, "listen": s.listen, "tls": s.tls,
		"agent_token": s.agentToken, "named_agents": agents,
		"policy": map[string]any{"file": s.policyPath, "default": p.defaultAction, "rules": len(p.rules), "none": p.none},
	}
	if s.pubURL != "" {
		res["join_code"] = encodeJoin(joinInfo{Server: s.pubURL, Token: s.nodeToken})
		res["warning"] = portMismatch(s.listen, s.pubURL)
	}
	writeJSON(w, res)
}

// handleActivity returns the newest audit records first (?limit=, max 1000).
func (s *server) handleActivity(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 300
	}
	out := []json.RawMessage{}
	if b, err := readTail(s.auditPath, 1<<20); err == nil {
		lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
		for i := len(lines) - 1; i >= 0 && len(out) < limit; i-- {
			if json.Valid(lines[i]) {
				out = append(out, lines[i])
			}
		}
	}
	writeJSON(w, out)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// ---- disconnecting machines -------------------------------------------------------

// closeDisconnected is the WebSocket close code a node gets when the console
// disconnected it: it stops retrying quickly and says so on its own page.
const closeDisconnected websocket.StatusCode = 4003

// blockStore holds the machines the console disconnected; they stay out until
// it lets them back in. Machines are known by name: all nodes share one node
// token, so this tidies up and pauses machines, it doesn't lock out someone
// hostile. For that, give the hub new tokens (relay init --force).
type blockStore struct {
	mu   sync.Mutex
	file string // "" keeps the list in memory only
	m    map[string]blockedNode
}

type blockedNode struct {
	Name string    `json:"name"`
	By   string    `json:"by,omitempty"`
	At   time.Time `json:"at"`
}

func newBlockStore(file string) (*blockStore, error) {
	b := &blockStore{file: file, m: map[string]blockedNode{}}
	if file == "" {
		return b, nil
	}
	data, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return b, nil
	}
	if err != nil {
		return nil, err
	}
	var list []blockedNode
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("%s: %v", file, err)
	}
	for _, n := range list {
		b.m[n.Name] = n
	}
	return b, nil
}

func (b *blockStore) has(name string) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.m[name]
	return ok
}

func (b *blockStore) list() []blockedNode {
	out := []blockedNode{}
	if b == nil {
		return out
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, n := range b.m {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (b *blockStore) set(name, by string, on bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if on {
		b.m[name] = blockedNode{Name: name, By: by, At: time.Now()}
	} else {
		delete(b.m, name)
	}
	if b.file == "" {
		return nil
	}
	list := make([]blockedNode, 0, len(b.m))
	for _, n := range b.m {
		list = append(list, n)
	}
	return writeJSON0600(b.file, list)
}

func (s *server) handleDisconnect(w http.ResponseWriter, r *http.Request) { s.setBlocked(w, r, true) }
func (s *server) handleAllow(w http.ResponseWriter, r *http.Request)      { s.setBlocked(w, r, false) }

func (s *server) setBlocked(w http.ResponseWriter, r *http.Request, on bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.adminAuth(w, r) {
		return
	}
	var req struct{ Name, By string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil || !validName.MatchString(req.Name) {
		http.Error(w, "bad request: give the machine's name", http.StatusBadRequest)
		return
	}
	by := firstNonEmpty(req.By, "admin") + "@" + r.RemoteAddr
	if err := s.blocked.set(req.Name, by, on); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	event := "node_allowed"
	if on {
		event = "node_disconnected_by_admin"
		s.mu.RLock()
		nc := s.nodes[req.Name]
		s.mu.RUnlock()
		if nc != nil {
			nc.closeWith(closeDisconnected, "disconnected by the hub's owner")
		}
	}
	s.audit.write(map[string]any{"event": event, "node": req.Name, "by": by})
	w.Write([]byte("ok\n"))
}
