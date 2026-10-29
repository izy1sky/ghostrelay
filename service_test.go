package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testService(t *testing.T, role string) *service {
	home := filepath.Join(t.TempDir(), "odd & 'home' 100%")
	t.Setenv("RELAY_HOME", home)
	cfg := filepath.Join(home, "node.json")
	if role == "server" {
		cfg = filepath.Join(home, "server", "server.json")
	}
	if err := writeJSON0600(cfg, map[string]any{"name": "box"}); err != nil {
		t.Fatal(err)
	}
	s, err := newService(role, "")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestServiceNames(t *testing.T) {
	n := testService(t, "node")
	if n.id != "ghostrelay-node-box" || n.label() != "dev.ghostrelay.node.box" {
		t.Errorf("node: id %q label %q", n.id, n.label())
	}
	if got := n.args(); got[0] != "node" || got[2] != n.cfg || got[4] != n.logPath {
		t.Errorf("args %v", got)
	}
	if s := testService(t, "server"); s.id != "ghostrelay-server" || s.label() != "dev.ghostrelay.server" {
		t.Errorf("server: id %q label %q", s.id, s.label())
	}
	if _, err := newService("node", filepath.Join(t.TempDir(), "missing.json")); err == nil || !strings.Contains(err.Error(), "relay join") {
		t.Errorf("missing settings: %v", err)
	}
}

func TestLaunchdPlist(t *testing.T) {
	s := testService(t, "node")
	p := s.launchdPlist()
	if !strings.Contains(p, "<string>--config</string>") || !strings.Contains(p, "odd &amp; &#39;home&#39; 100%") {
		t.Errorf("plist args or escaping:\n%s", p)
	}
	if runtime.GOOS == "darwin" {
		f := filepath.Join(t.TempDir(), "x.plist")
		os.WriteFile(f, []byte(p), 0o644)
		if out, err := exec.Command("plutil", "-lint", f).CombinedOutput(); err != nil {
			t.Errorf("plutil: %v %s", err, out)
		}
	}
}

func TestSystemdUnit(t *testing.T) {
	s := testService(t, "node")
	u := s.systemdUnit()
	if !strings.Contains(u, `"--config"`) || !strings.Contains(u, "100%%") || strings.Contains(u, "100% ") {
		t.Errorf("unit quoting:\n%s", u)
	}
	if !strings.Contains(u, "Restart=always") || !strings.Contains(u, "WantedBy=default.target") {
		t.Errorf("unit:\n%s", u)
	}
}

func TestTaskScript(t *testing.T) {
	s := testService(t, "node")
	sc := s.taskScript()
	if !strings.Contains(sc, "''home''") || !strings.Contains(sc, "-AtLogOn") || !strings.Contains(sc, "'ghostrelay-node-box'") {
		t.Errorf("script:\n%s", sc)
	}
}
