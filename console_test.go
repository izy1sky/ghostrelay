package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConsoleAPIs(t *testing.T) {
	s := testServer(t, policyPresets["workspace"])
	s.nodeToken, s.agentToken = "nodetok", "agenttok"
	s.pubURL, s.listen = "http://203.0.113.5:4747", ":8787"
	s.auditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	os.WriteFile(s.auditPath, []byte(`{"event":"node_connected","node":"a"}`+"\n"+`not json`+"\n"+`{"event":"tool_call","tool":"exec"}`+"\n"), 0o600)

	get := func(h http.HandlerFunc, path, tok string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		w := httptest.NewRecorder()
		h(w, r)
		return w
	}
	for _, h := range []http.HandlerFunc{s.handleSetup, s.handleNodes, s.handleActivity} {
		if w := get(h, "/admin/api/x", ""); w.Code != http.StatusUnauthorized {
			t.Errorf("no admin token: %d", w.Code)
		}
	}

	var setup map[string]any
	json.Unmarshal(get(s.handleSetup, "/admin/api/setup", "admin").Body.Bytes(), &setup)
	j, err := decodeJoin(setup["join_code"].(string))
	if err != nil || j.Server != s.pubURL || j.Token != "nodetok" || setup["agent_token"] != "agenttok" {
		t.Errorf("setup: %v %v", setup, err)
	}
	if !strings.Contains(setup["warning"].(string), "port 4747") {
		t.Errorf("url and listen ports differ, the console should say so: %v", setup["warning"])
	}

	var acts []map[string]any
	json.Unmarshal(get(s.handleActivity, "/admin/api/activity", "admin").Body.Bytes(), &acts)
	if len(acts) != 2 || acts[0]["event"] != "tool_call" {
		t.Errorf("activity, newest first and skipping bad lines: %v", acts)
	}

	var nodes []any
	if w := get(s.handleNodes, "/admin/api/nodes", "admin"); json.Unmarshal(w.Body.Bytes(), &nodes) != nil || len(nodes) != 0 {
		t.Errorf("nodes: %s", w.Body)
	}
}
