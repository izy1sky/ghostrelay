package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
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

	var nodes struct{ Connected, Disconnected []any }
	if w := get(s.handleNodes, "/admin/api/nodes", "admin"); json.Unmarshal(w.Body.Bytes(), &nodes) != nil || len(nodes.Connected) != 0 || nodes.Disconnected == nil {
		t.Errorf("nodes: %s", w.Body)
	}
}

// Disconnecting a machine in the console drops its link with code 4003 and
// keeps it out until the console allows it again, also across restarts.
func TestDisconnectMachine(t *testing.T) {
	s := testServer(t, policyPresets["workspace"])
	s.nodeToken, s.nodes = "nodetok", map[string]*nodeConn{}
	file := filepath.Join(t.TempDir(), "blocked.json")
	s.blocked, _ = newBlockStore(file)
	srv := httptest.NewServer(http.HandlerFunc(s.handleNode))
	defer srv.Close()

	dial := func() (*websocket.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), &websocket.DialOptions{
			HTTPHeader: http.Header{"Authorization": {"Bearer nodetok"}}})
		if err != nil {
			return nil, err
		}
		wsjson.Write(ctx, c, &Msg{Type: msgHello, Info: &NodeInfo{Name: "box"}})
		var m Msg
		return c, wsjson.Read(ctx, c, &m)
	}
	post := func(h http.HandlerFunc, body string) int {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer admin")
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code
	}

	c, err := dial()
	if err != nil {
		t.Fatalf("first connect: %v", err)
	}
	if code := post(s.handleDisconnect, `{"name":"box","by":"test"}`); code != http.StatusOK {
		t.Fatalf("disconnect: %d", code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err = c.Read(ctx)
	if websocket.CloseStatus(err) != closeDisconnected {
		t.Errorf("connected node should be closed with 4003: %v", err)
	}
	if _, err := dial(); websocket.CloseStatus(err) != closeDisconnected {
		t.Errorf("reconnecting must be refused with 4003: %v", err)
	}
	if again, _ := newBlockStore(file); !again.has("box") {
		t.Error("the list must survive a restart")
	}
	post(s.handleAllow, `{"name":"box"}`)
	if c, err := dial(); err != nil {
		t.Errorf("allowed again: %v", err)
	} else {
		c.CloseNow()
	}
}
