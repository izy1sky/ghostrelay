package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testApp(t *testing.T) (*app, http.Handler) {
	home := t.TempDir()
	a := &app{key: "k3y", nodeCfg: filepath.Join(home, "node.json"), serverCfg: filepath.Join(home, "server", "server.json"),
		children: map[string]*child{}, svcCache: map[string]svcEntry{}}
	return a, a.routes(4780)
}

func call(h http.Handler, method, path, key, host string, body any) *httptest.ResponseRecorder {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Host = host
	if key != "" {
		r.Header.Set("X-Relay-Key", key)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// The page drives init, join and services, so only this computer's own
// browser tab, holding the key from the printed link, may call it.
func TestAppGuards(t *testing.T) {
	_, h := testApp(t)
	if w := call(h, "GET", "/api/state", "", "127.0.0.1:4780", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("no key: %d", w.Code)
	}
	if w := call(h, "GET", "/api/state", "wrong", "127.0.0.1:4780", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong key: %d", w.Code)
	}
	if w := call(h, "GET", "/api/state", "k3y", "evil.example:4780", nil); w.Code != http.StatusForbidden {
		t.Errorf("rebinding host: %d", w.Code)
	}
	if w := call(h, "GET", "/", "", "evil.example:4780", nil); w.Code != http.StatusForbidden {
		t.Errorf("page on a rebinding host: %d", w.Code)
	}
	w := call(h, "GET", "/api/state", "k3y", "localhost:4780", nil)
	var st struct {
		Node nodeView `json:"node"`
		Hub  hubView  `json:"hub"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &st) != nil || st.Node.Configured || st.Hub.Configured {
		t.Errorf("state: %d %s", w.Code, w.Body)
	}
	if w := call(h, "GET", "/", "", "127.0.0.1:4780", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "ghostrelay") {
		t.Errorf("page: %d", w.Code)
	}
}

func TestAppJoinCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !checkBearer(r, "good") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		http.Error(w, "upgrade required", http.StatusUpgradeRequired)
	}))
	defer srv.Close()
	_, h := testApp(t)
	check := func(code string) map[string]string {
		var res map[string]string
		json.Unmarshal(call(h, "POST", "/api/join/check", "k3y", "127.0.0.1:4780", map[string]string{"code": code}).Body.Bytes(), &res)
		return res
	}
	if r := check(encodeJoin(joinInfo{srv.URL, "good"})); r["server"] != srv.URL || r["problem"] != "" {
		t.Errorf("good code: %v", r)
	}
	if r := check(encodeJoin(joinInfo{srv.URL, "old"})); !strings.Contains(r["problem"], "rejected") {
		t.Errorf("old code: %v", r)
	}
	if r := check("hello"); !strings.Contains(r["error"], "not a join code") {
		t.Errorf("not a code: %v", r)
	}
}

func TestCheckFolderPath(t *testing.T) {
	dir := t.TempDir()
	if res, err := checkFolderPath(dir); err != nil || res.(map[string]string)["warning"] != "" {
		t.Errorf("project folder: %v %v", res, err)
	}
	root := filepath.VolumeName(dir) + string(filepath.Separator)
	if res, err := checkFolderPath(root); err != nil || !strings.Contains(res.(map[string]string)["warning"], "whole drive") {
		t.Errorf("drive root %s: %v %v", root, res, err)
	}
	if home, err := os.UserHomeDir(); err == nil {
		if res, err := checkFolderPath("~"); err != nil || !strings.Contains(res.(map[string]string)["warning"], "home folder") {
			t.Errorf("home: %v %v", res, err)
		}
		_ = home
	}
	f := filepath.Join(dir, "file.txt")
	os.WriteFile(f, nil, 0o600)
	if _, err := checkFolderPath(f); err == nil {
		t.Error("a file must not pass as a folder")
	}
}

func TestAppPauseAndLeave(t *testing.T) {
	a, h := testApp(t)
	writeJSON0600(a.nodeCfg, map[string]any{"server": "http://s:1", "token": "t", "name": "box", "root": []string{t.TempDir()}})
	os.WriteFile(sidecar(a.nodeCfg, ".activity.jsonl"), []byte("{}\n"), 0o600)

	call(h, "POST", "/api/node/pause", "k3y", "127.0.0.1:4780", map[string]bool{"paused": true})
	l := &nodeLocal{cfg: a.nodeCfg}
	if !l.paused() {
		t.Fatal("pause didn't reach the node's pause file")
	}
	call(h, "POST", "/api/node/pause", "k3y", "127.0.0.1:4780", map[string]bool{"paused": false})
	if l.paused() {
		t.Fatal("resume didn't remove the pause file")
	}
	if w := call(h, "POST", "/api/node/leave", "k3y", "127.0.0.1:4780", map[string]any{}); w.Code != http.StatusOK {
		t.Fatalf("leave: %d %s", w.Code, w.Body)
	}
	for _, s := range []string{".json", ".activity.jsonl"} {
		if _, err := os.Stat(sidecar(a.nodeCfg, s)); err == nil {
			t.Errorf("leave left %s behind", s)
		}
	}
}

func TestNodeLocalActivity(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "node.json")
	l := &nodeLocal{cfg: cfg}
	l.record("exec", json.RawMessage(`{"command":"python train.py","cwd":"D:/work"}`), nil)
	l.record("job_logs", json.RawMessage(`{"id":"j1"}`), nil) // polling: not recorded
	l.record("fs_move", json.RawMessage(`{"src":"a.txt","dst":"b.txt"}`), os.ErrNotExist)
	b, _ := os.ReadFile(sidecar(cfg, ".activity.jsonl"))
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 records, got %d: %s", len(lines), b)
	}
	var e1, e2 activity
	json.Unmarshal([]byte(lines[0]), &e1)
	json.Unmarshal([]byte(lines[1]), &e2)
	if e1.What != "python train.py   (in D:/work)" || !e1.OK || e2.What != "a.txt → b.txt" || e2.OK || e2.Error == "" {
		t.Errorf("records: %+v %+v", e1, e2)
	}

	a := &app{nodeCfg: cfg}
	res, _ := a.nodeActivity(nil)
	if got := res.([]activity); len(got) != 2 || got[0].Op != "fs_move" {
		t.Errorf("newest first: %+v", got)
	}

	var none *nodeLocal // a node started with flags only keeps no files
	none.set("connected", "")
	none.record("exec", nil, nil)
	if none.paused() {
		t.Error("nil nodeLocal paused")
	}
}

func TestReadTail(t *testing.T) {
	f := filepath.Join(t.TempDir(), "log")
	os.WriteFile(f, []byte("first line\nsecond\nthird\n"), 0o600)
	b, _ := readTail(f, 10)
	if string(b) != "third\n" {
		t.Errorf("tail starts at a line: %q", b)
	}
	b, _ = readTail(f, 1000)
	if !strings.HasPrefix(string(b), "first") {
		t.Errorf("whole file: %q", b)
	}
}
