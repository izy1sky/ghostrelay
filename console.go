package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
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
	writeJSON(w, out)
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
