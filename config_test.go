package main

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "node.json")
	os.WriteFile(cfg, []byte(`{"#": "comment", "server": "http://s:1", "name": "box",
		"root": ["work", "/abs"], "allow-exec": true, "max-jobs": 4}`), 0o600)

	fs := flag.NewFlagSet("node", flag.ContinueOnError)
	server := fs.String("server", "", "")
	name := fs.String("name", "", "")
	var roots multiFlag
	fs.Var(&roots, "root", "")
	exec := fs.Bool("allow-exec", false, "")
	jobs := fs.Int("max-jobs", 16, "")
	fs.Parse([]string{"--name", "cli"})
	if err := applyConfig(fs, cfg); err != nil {
		t.Fatal(err)
	}
	if *server != "http://s:1" || *name != "cli" || !*exec || *jobs != 4 {
		t.Errorf("got server=%q name=%q exec=%v jobs=%d (the command line must win over the file)", *server, *name, *exec, *jobs)
	}
	if len(roots) != 2 || roots[0] != filepath.Join(dir, "work") || roots[1] != "/abs" {
		t.Errorf("roots = %v; relative ones resolve against the file's folder", roots)
	}

	os.WriteFile(cfg, []byte(`{"sever": "typo"}`), 0o600)
	if err := applyConfig(fs, cfg); err == nil || !strings.Contains(err.Error(), "sever") {
		t.Errorf("unknown key: %v", err)
	}
}

func TestJoinCode(t *testing.T) {
	j := joinInfo{Server: "https://relay.example.com:8787", Token: "abc"}
	code := encodeJoin(j)
	if !strings.HasPrefix(code, joinPrefix) {
		t.Fatal(code)
	}
	got, err := decodeJoin("  " + code + "\n")
	if err != nil || got != j {
		t.Errorf("round trip: %+v %v", got, err)
	}
	for _, bad := range []string{"", "abc", joinPrefix + "!!!", joinPrefix + "e30"} {
		if _, err := decodeJoin(bad); err == nil {
			t.Errorf("decodeJoin(%q) accepted", bad)
		}
	}
}

func TestPolicyPresetsParse(t *testing.T) {
	for name, p := range policyPresets {
		if _, err := parsePolicy([]byte(p)); err != nil {
			t.Errorf("preset %s: %v", name, err)
		}
	}
}

func TestCheckNodeToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !checkBearer(r, "good") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		http.Error(w, "upgrade required", http.StatusUpgradeRequired)
	}))
	defer srv.Close()
	if err := checkNodeToken(srv.URL, "good"); err != nil {
		t.Errorf("good token: %v", err)
	}
	if err := checkNodeToken(srv.URL, "bad"); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Errorf("bad token: %v", err)
	}
	if err := checkNodeToken("http://127.0.0.1:1", "good"); err == nil || !strings.Contains(err.Error(), "cannot reach") {
		t.Errorf("no server: %v", err)
	}
}
