package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
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

// ---- named agents -------------------------------------------------------------------

// handleAgentCreate makes a token for a new named agent, adds its sha256 to the
// policy file and returns the token. The hub never stores the token itself, so
// this response is the only time anyone sees it.
func (s *server) handleAgentCreate(w http.ResponseWriter, r *http.Request) {
	var req struct{ Name, By string }
	if !s.agentRequest(w, r, &req) {
		return
	}
	tok := newToken()
	sum := sha256.Sum256([]byte(tok))
	err := s.editAgents(func(list []agentConf) ([]agentConf, error) {
		if req.Name == "default" || slices.ContainsFunc(list, func(a agentConf) bool { return a.Name == req.Name }) {
			return nil, fmt.Errorf("there is already an agent called %q", req.Name)
		}
		return append(list, agentConf{Name: req.Name, TokenSHA256: hex.EncodeToString(sum[:]),
			Comment: "added in the console on " + time.Now().Format("2006-01-02")}), nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit.write(map[string]any{"event": "agent_created", "agent": req.Name, "by": firstNonEmpty(req.By, "admin") + "@" + r.RemoteAddr})
	writeJSON(w, map[string]string{"name": req.Name, "token": tok})
}

func (s *server) handleAgentRemove(w http.ResponseWriter, r *http.Request) {
	var req struct{ Name, By string }
	if !s.agentRequest(w, r, &req) {
		return
	}
	err := s.editAgents(func(list []agentConf) ([]agentConf, error) {
		i := slices.IndexFunc(list, func(a agentConf) bool { return a.Name == req.Name })
		if i < 0 {
			return nil, fmt.Errorf("no agent called %q in the policy", req.Name)
		}
		return slices.Delete(list, i, i+1), nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit.write(map[string]any{"event": "agent_removed", "agent": req.Name, "by": firstNonEmpty(req.By, "admin") + "@" + r.RemoteAddr})
	w.Write([]byte("ok\n"))
}

func (s *server) agentRequest(w http.ResponseWriter, r *http.Request, req *struct{ Name, By string }) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if !s.adminAuth(w, r) {
		return false
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(req); err != nil || !validName.MatchString(req.Name) {
		http.Error(w, "give the agent a name: letters, digits, - _ . (up to 64)", http.StatusBadRequest)
		return false
	}
	return true
}

// editAgents changes the "agents" list of the policy file and leaves every
// other part of it as written, byte for byte. The result must parse as a
// policy before it is saved, and it takes effect at once.
func (s *server) editAgents(edit func([]agentConf) ([]agentConf, error)) error {
	if s.policyPath == "" {
		return errors.New("this hub runs without a policy file, so it has no named agents (start it with --policy)")
	}
	s.agentsMu.Lock()
	defer s.agentsMu.Unlock()
	data, err := os.ReadFile(s.policyPath)
	if err != nil {
		return err
	}
	keys, vals, err := topLevel(data)
	if err != nil {
		return fmt.Errorf("%s: %v", s.policyPath, err)
	}
	var list []agentConf
	if raw, ok := vals["agents"]; ok {
		if err := json.Unmarshal(raw, &list); err != nil {
			return fmt.Errorf("%s: agents: %v", s.policyPath, err)
		}
	}
	if list, err = edit(list); err != nil {
		return err
	}
	if _, ok := vals["agents"]; !ok && len(list) > 0 {
		at := slices.Index(keys, "rules") // agents read best above the rules
		if at < 0 {
			at = len(keys)
		}
		keys = slices.Insert(keys, at, "agents")
	}
	var b bytes.Buffer
	b.WriteString("{\n")
	first := true
	for _, k := range keys {
		raw := vals[k]
		if k == "agents" {
			if len(list) == 0 {
				continue
			}
			raw = agentsJSON(list)
		}
		if !first {
			b.WriteString(",\n")
		}
		first = false
		kb, _ := json.Marshal(k)
		fmt.Fprintf(&b, "  %s: %s", kb, raw)
	}
	b.WriteString("\n}\n")
	p, err := parsePolicy(b.Bytes())
	if err != nil {
		return fmt.Errorf("the edited policy wouldn't load, so it wasn't saved: %v", err)
	}
	if err := writePrivate(s.policyPath, b.Bytes()); err != nil {
		return err
	}
	s.pol.Store(p)
	return nil
}

// agentsJSON writes one agent per line, like the rest of a hand-edited policy.
func agentsJSON(list []agentConf) json.RawMessage {
	var b bytes.Buffer
	b.WriteString("[\n")
	for i, a := range list {
		line, _ := json.Marshal(a)
		b.WriteString("    ")
		b.Write(line)
		if i < len(list)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("  ]")
	return b.Bytes()
}

// topLevel splits a JSON object into its keys, in order, and their values as
// written.
func topLevel(data []byte) ([]string, map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, nil, errors.New("not a JSON object")
	}
	var keys []string
	vals := map[string]json.RawMessage{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		k, _ := t.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, nil, err
		}
		if _, dup := vals[k]; !dup {
			keys = append(keys, k)
		}
		vals[k] = raw
	}
	return keys, vals, nil
}
