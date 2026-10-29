package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestGlob(t *testing.T) {
	cases := []struct {
		glob, s string
		want    bool
	}{
		{"D:/work/**", "D:/work", true},
		{"D:/work/**", "D:/work/a/b.txt", true},
		{"D:/work/**", "D:/workshop/x", false},
		{"**/.git/**", "D:/work/repo/.git/config", true},
		{"**/.git/**", "D:/work/repo/.github/x", false},
		{"**/*.env", "/srv/app/.env", true},
		{"**/*.env", "/srv/app/prod.env", true},
		{"/srv/*.txt", "/srv/a.txt", true},
		{"/srv/*.txt", "/srv/sub/a.txt", false},
		{"win*", "win-gpu", true},
		{"*", "", true},
		{"a.b", "aXb", false},
	}
	for _, c := range cases {
		res, err := compileGlobs([]string{c.glob}, false)
		if err != nil {
			t.Fatal(err)
		}
		if got := res[0].MatchString(c.s); got != c.want {
			t.Errorf("glob %q on %q = %v, want %v", c.glob, c.s, got, c.want)
		}
	}
}

func TestNormPath(t *testing.T) {
	win := NodeInfo{OS: "windows", Roots: []string{`D:\work`}}
	nix := NodeInfo{OS: "linux", Roots: []string{"/srv/data"}}
	cases := []struct {
		info NodeInfo
		in   string
		want string
	}{
		{win, "", "D:/work"},
		{win, `sub\a.txt`, "D:/work/sub/a.txt"},
		{win, `C:\Windows\System32`, "C:/Windows/System32"},
		{win, `..\..\Windows`, "D:/Windows"},
		{nix, "", "/srv/data"},
		{nix, "a/../b", "/srv/data/b"},
		{nix, "../../etc/passwd", "/etc/passwd"},
		{nix, "/etc/hosts", "/etc/hosts"},
		{nix, `a\b`, `/srv/data/a\b`},
	}
	for _, c := range cases {
		if got := normPath(c.in, c.info); got != c.want {
			t.Errorf("normPath(%q, %s) = %q, want %q", c.in, c.info.OS, got, c.want)
		}
	}
}

const testPolicy = `{
  "default": "deny",
  "agents": [{"name": "laptop", "token_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}],
  "rules": [
    {"tools": ["nodes_list", "node_info", "fs_read", "fs_list"], "action": "allow"},
    {"tools": ["fs_write", "fs_edit"], "paths": ["**/.git/**", "**/*.env"], "action": "deny", "reason": "secrets and git internals"},
    {"tools": ["exec"], "commands": ["(?i)\\b(rm|del|Remove-Item|format|shutdown)\\b"], "action": "ask"},
    {"nodes": ["win"], "tools": ["exec"], "paths": ["D:/work/**"], "action": "allow"},
    {"agents": ["laptop"], "tools": ["fs_write", "fs_edit"], "paths": ["D:/work/**"], "action": "allow"},
    {"tools": ["fs_write", "fs_edit"], "action": "ask"}
  ]
}`

func TestEval(t *testing.T) {
	p, err := parsePolicy([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	win := &nodeConn{info: NodeInfo{Name: "win", OS: "windows", Roots: []string{`D:\work`}}}
	mac := &nodeConn{info: NodeInfo{Name: "mac", OS: "darwin", Roots: []string{"/Users/me/proj"}}}
	cases := []struct {
		agent, tool string
		args        map[string]string
		nc          *nodeConn
		want        string
		rule        int
	}{
		{"default", "nodes_list", nil, nil, actAllow, 1},
		{"default", "fs_read", map[string]string{"path": `C:\secret.txt`}, win, actAllow, 1},
		{"laptop", "fs_write", map[string]string{"path": "repo/.git/config"}, win, actDeny, 2},
		{"laptop", "fs_write", map[string]string{"path": `d:\WORK\notes.md`}, win, actAllow, 5}, // case-insensitive on Windows
		{"default", "fs_write", map[string]string{"path": "notes.md"}, win, actAsk, 6},
		{"default", "exec", map[string]string{"command": "git status"}, win, actAllow, 4},
		{"default", "exec", map[string]string{"command": "Remove-Item -Recurse x"}, win, actAsk, 3},
		{"default", "exec", map[string]string{"command": "git status", "cwd": `C:\`}, win, actDeny, 0},
		{"default", "exec", map[string]string{"command": "ls"}, mac, actDeny, 0},
		{"default", "fs_write", map[string]string{"path": "/Users/me/proj/.env"}, mac, actDeny, 2},
	}
	for _, c := range cases {
		raw, _ := json.Marshal(c.args)
		q := buildReq(c.agent, c.tool, raw, c.nc)
		v := p.eval(q)
		if v.Action != c.want || v.Rule != c.rule {
			t.Errorf("%s: got %s, want %s (rule %d)", q.summary(), v, c.want, c.rule)
		}
	}
}

func TestAgentByToken(t *testing.T) {
	p, err := parsePolicy([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := p.agentByToken("test"); !ok || name != "laptop" { // sha256("test")
		t.Errorf("agentByToken(test) = %q, %v", name, ok)
	}
	if _, ok := p.agentByToken("nope"); ok {
		t.Error("unknown token matched")
	}
}

func TestParseRejects(t *testing.T) {
	bad := map[string]string{
		"typo field":   `{"rules":[{"tool":["exec"],"action":"allow"}]}`,
		"bad action":   `{"rules":[{"action":"maybe"}]}`,
		"unknown tool": `{"rules":[{"tools":["exce"],"action":"allow"}]}`,
		"bad regex":    `{"rules":[{"commands":["("],"action":"deny"}]}`,
		"bad hash":     `{"agents":[{"name":"a","token_sha256":"abc"}],"rules":[]}`,
		"reserved":     `{"agents":[{"name":"default","token_sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}],"rules":[]}`,
		"bad default":  `{"default":"yes","rules":[]}`,
	}
	for name, src := range bad {
		if _, err := parsePolicy([]byte(src)); err == nil {
			t.Errorf("%s: accepted %s", name, src)
		}
	}
	p, err := parsePolicy([]byte(`{"rules":[]}`))
	if err != nil || p.defaultAction != actDeny {
		t.Errorf("empty policy should default to deny, got %v %v", p, err)
	}
}

func TestExamplePolicyParses(t *testing.T) {
	data, err := os.ReadFile("policy.example.json")
	if err != nil {
		t.Skip("no example policy")
	}
	if _, err := parsePolicy(data); err != nil && !strings.Contains(err.Error(), "token_sha256") {
		t.Fatal(err)
	}
}
