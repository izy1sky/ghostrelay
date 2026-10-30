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

// suffixed matches "<base>-<6 hex>": with RELAY_HOME set, names carry a hash
// of that folder, so a test setup can't drive the services of ~/.relay.
func suffixed(id, base string) bool {
	rest, ok := strings.CutPrefix(id, base+"-")
	return ok && len(rest) == 6 && strings.Trim(rest, "0123456789abcdef") == ""
}

func TestServiceNames(t *testing.T) {
	n := testService(t, "node")
	if !suffixed(n.id, "ghostrelay-node-box") || !strings.HasPrefix(n.label(), "dev.ghostrelay.node.box-") {
		t.Errorf("node: id %q label %q", n.id, n.label())
	}
	if got := n.args(); got[0] != "node" || got[2] != n.cfg || got[4] != n.logPath {
		t.Errorf("args %v", got)
	}
	if s := testService(t, "server"); !suffixed(s.id, "ghostrelay-server") {
		t.Errorf("server: id %q label %q", s.id, s.label())
	}
	if other := testService(t, "node"); other.id == n.id {
		t.Errorf("two settings folders, one name: both %q", n.id)
	}
	cfg := filepath.Join(t.TempDir(), "node.json")
	writeJSON0600(cfg, map[string]any{"name": "box"})
	t.Setenv("RELAY_HOME", "")
	if d, err := newService("node", cfg); err != nil || d.id != "ghostrelay-node-box" || d.label() != "dev.ghostrelay.node.box" {
		t.Errorf("default home keeps plain names: %+v %v", d, err)
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
	if !strings.Contains(sc, "''home''") || !strings.Contains(sc, "-AtLogOn") || !strings.Contains(sc, "'"+s.id+"'") {
		t.Errorf("script:\n%s", sc)
	}
}

func TestTaskState(t *testing.T) {
	for in, want := range map[string]string{
		"Running 267009": "running",
		"Ready 0":        "ready",
		"Ready 267011":   "ready (has not run yet)",
		"Ready 1":        "ready (last exit code 1; see relay service logs)",
	} {
		if got := taskState(in); got != want {
			t.Errorf("taskState(%q) = %q, want %q", in, got, want)
		}
	}
}
