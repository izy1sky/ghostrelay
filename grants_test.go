package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func execReq(cmd string, argv bool) policyReq {
	return policyReq{Agent: "default", Node: "win", Tool: "exec", HasCommand: true, Command: cmd, Argv: argv,
		HasPath: true, Path: "D:/work"}
}

func TestProgramOf(t *testing.T) {
	for _, c := range []struct {
		cmd  string
		argv bool
		want string
		ok   bool
	}{
		{"python build.py", false, "python", true},
		{`"C:\Program Files\Python\python.exe" -V`, false, "python", true},
		{"/usr/bin/git status", false, "git", true},
		{"python x.py; rm -rf ~", false, "", false},
		{"python x.py && del *", false, "", false},
		{"python $(evil)", false, "", false},
		{"git log | sh", false, "", false},
		{`"C:\Py thon\python.exe" a "b c"`, true, "python", true},
		{"dotnet build", true, "dotnet", true},
	} {
		got, ok := programOf(execReq(c.cmd, c.argv))
		if got != c.want || ok != c.ok {
			t.Errorf("programOf(%q, argv=%v) = %q, %v; want %q, %v", c.cmd, c.argv, got, ok, c.want, c.ok)
		}
	}
}

func TestGrantCovers(t *testing.T) {
	g := grant{Agent: "default", Node: "win", Tools: []string{"exec", "fs_write"}, Programs: []string{"python"},
		Paths: []string{"D:/work/**"}}
	if err := g.compile(); err != nil {
		t.Fatal(err)
	}
	fold := func(q policyReq) policyReq { q.FoldCase = true; return q }
	for _, c := range []struct {
		name string
		q    policyReq
		want bool
	}{
		{"python in the folder", execReq("python build.py", false), true},
		{"other program", execReq("node build.js", false), false},
		{"chained shell command", execReq("python a.py; rm -rf ~", false), false},
		{"other agent", func() policyReq { q := execReq("python a", false); q.Agent = "ci"; return q }(), false},
		{"other node", func() policyReq { q := execReq("python a", false); q.Node = "mac"; return q }(), false},
		{"listed program, any cwd", func() policyReq { q := execReq("python a", false); q.Path = "D:/other"; return q }(), true},
		{"write in the folder", policyReq{Agent: "default", Node: "win", Tool: "fs_write", HasPath: true, Path: "D:/work/a/b.txt"}, true},
		{"case-insensitive disk", fold(policyReq{Agent: "default", Node: "win", Tool: "fs_write", HasPath: true, Path: "d:/WORK/x"}), true},
		{"case-sensitive disk", policyReq{Agent: "default", Node: "win", Tool: "fs_write", HasPath: true, Path: "d:/WORK/x"}, false},
		{"tool not granted", policyReq{Agent: "default", Node: "win", Tool: "fs_remove", HasPath: true, Path: "D:/work/x"}, false},
	} {
		if got := g.covers(c.q); got != c.want {
			t.Errorf("%s: covers = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestGrantWithoutProgramsLimitsCwd(t *testing.T) {
	g := grant{Agent: "default", Node: "win", Paths: []string{"D:/work/**"}}
	g.compile()
	in, out := execReq("anything", false), execReq("anything", false)
	out.Path = "D:/other"
	if !g.covers(in) || g.covers(out) {
		t.Errorf("folder-only grant: in=%v out=%v", g.covers(in), g.covers(out))
	}
}

func TestDescribe(t *testing.T) {
	for _, c := range []struct {
		g    grant
		want string
	}{
		{grant{Node: "w"}, "everything on w"},
		{grant{Node: "w", Paths: []string{"/a/**"}}, "everything in /a/** on w"},
		{grant{Node: "w", Tools: []string{"exec"}, Programs: []string{"py"}}, "exec of py on w"},
		{grant{Node: "w", Tools: []string{"exec"}, Programs: []string{"py"}, Paths: []string{"/a/**"}}, "exec of py on w"},
		{grant{Node: "w", Programs: []string{"py"}, Paths: []string{"/a/**"}}, "exec of py; any other tool in /a/** on w"},
		{grant{Node: "w", Tools: []string{"exec", "fs_remove"}, Programs: []string{"py"}, Paths: []string{"/a/**"}}, "exec of py; fs_remove in /a/** on w"},
		{grant{Node: "w", Tools: []string{"fs_write", "fs_edit"}, Paths: []string{"/a/**"}}, "fs_write, fs_edit in /a/** on w"},
	} {
		if got := c.g.describe(); got != c.want {
			t.Errorf("describe(%+v) = %q, want %q", c.g, got, c.want)
		}
	}
}

func TestSimilarGrants(t *testing.T) {
	gs := similarGrants([]policyReq{execReq("python build.py", false)})
	if len(gs) != 1 || gs[0].describe() != "exec of python on win" {
		t.Errorf("exec: %+v", gs)
	}
	w := func(p string) policyReq {
		return policyReq{Agent: "default", Node: "b", Tool: "fs_write", HasPath: true, Path: p}
	}
	gs = similarGrants([]policyReq{w("/data/copy/a/x.bin"), w("/data/copy/b/y.bin"), w("/data/copy/z.txt")})
	if len(gs) != 1 || gs[0].Paths[0] != "/data/copy/**" || len(gs[0].Tools) != 3 {
		t.Errorf("writes: %+v", gs)
	}
	if gs := similarGrants([]policyReq{execReq("python a; rm b", false)}); gs != nil {
		t.Errorf("chained command must have no similar grant: %+v", gs)
	}
	if gs := nodeGrants([]policyReq{w("/x"), execReq("ls", false)}); len(gs) != 2 || gs[0].describe() != "everything on b" {
		t.Errorf("node grants: %+v", gs)
	}
}

func TestGrantStorePersistsAndExpires(t *testing.T) {
	file := filepath.Join(t.TempDir(), "grants.json")
	st, _ := newGrantStore(file)
	g, err := st.add(grant{Agent: "default", Node: "win", Programs: []string{"python"}, Tools: []string{"exec"},
		Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	st.add(grant{Agent: "default", Node: "win", Expires: time.Now().Add(-time.Second)}) // already expired
	if ids := st.cover([]policyReq{execReq("python x", false)}); len(ids) != 1 || ids[0] != g.ID {
		t.Errorf("cover = %v", ids)
	}
	if ids := st.cover([]policyReq{execReq("python x", false), execReq("rm x", false)}); ids != nil {
		t.Errorf("one uncovered request must leave the call uncovered: %v", ids)
	}
	again, err := newGrantStore(file)
	if err != nil || len(again.active()) != 1 {
		t.Fatalf("reload: %v %d", err, len(again.active()))
	}
	if _, err := again.revoke(g.ID); err != nil || len(again.active()) != 0 {
		t.Errorf("revoke: %v", err)
	}
}

func testServer(t *testing.T, policyJSON string) *server {
	p, err := parsePolicy([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := openAudit(filepath.Join(t.TempDir(), "audit.jsonl"))
	st, _ := newGrantStore(filepath.Join(t.TempDir(), "grants.json"))
	s := &server{adminToken: "admin", audit: a, grants: st, pending: map[string]*pendingCall{}, always: map[string]bool{}}
	s.pol.Store(p)
	return s
}

func TestAuthorizeWithGrants(t *testing.T) {
	s := testServer(t, policyPresets["workspace"])
	never := make(chan struct{})
	deny := policyReq{Agent: "default", Node: "win", Tool: "fs_write", HasPath: true, Path: "D:/work/.git/config"}
	s.grantFrom([]grant{{Node: "win"}}, "default", "test", "", time.Hour) // everything on win
	if _, err := s.authorizeMany(never, []policyReq{deny}, deny); err == nil || !strings.Contains(err.Error(), "rule 2") {
		t.Errorf("a deny rule must beat a grant: %v", err)
	}
	if note, err := s.authorizeMany(never, []policyReq{execReq("python build.py", false)}, execReq("", false)); err != nil || !strings.Contains(note, "grant g") {
		t.Errorf("granted call: %q %v", note, err)
	}
	other := execReq("python build.py", false)
	other.Agent = "ci"
	s.adminToken = "" // so an uncovered call fails at once instead of waiting
	if _, err := s.authorizeMany(never, []policyReq{other}, other); err == nil || !strings.Contains(err.Error(), "requires approval") {
		t.Errorf("a grant is for one agent only: %v", err)
	}
}

// One approval with "similar" lets the next call like it through.
func TestApproveSimilarThenNoAsk(t *testing.T) {
	s := testServer(t, policyPresets["workspace"])
	never := make(chan struct{})
	first, second := execReq("python build.py", false), execReq("python test.py --fast", false)
	done := make(chan error, 1)
	go func() { _, err := s.authorizeMany(never, []policyReq{first}, first); done <- err }()

	var id string
	for i := 0; i < 100 && id == ""; i++ {
		time.Sleep(10 * time.Millisecond)
		s.amu.Lock()
		for k, pc := range s.pending {
			id = k
			if pc.Similar != "exec of python on win" {
				t.Errorf("similar = %q", pc.Similar)
			}
		}
		s.amu.Unlock()
	}
	body, _ := json.Marshal(map[string]any{"id": id, "decision": "similar", "minutes": 30, "by": "test"})
	req := httptest.NewRequest("POST", "/admin/api/decide", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin")
	w := httptest.NewRecorder()
	s.handleDecide(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("decide: %d %s", w.Code, w.Body)
	}
	if err := <-done; err != nil {
		t.Fatalf("first call: %v", err)
	}
	if note, err := s.authorizeMany(never, []policyReq{second}, second); err != nil || !strings.Contains(note, "grant") {
		t.Errorf("second call should be covered: %q %v", note, err)
	}
	gs := s.grants.active()
	if len(gs) != 1 || time.Until(gs[0].Expires) > 31*time.Minute || gs[0].Uses != 1 {
		t.Errorf("grants: %+v", gs)
	}
}

func TestWorkspacePreset(t *testing.T) {
	p, err := parsePolicy([]byte(policyPresets["workspace"]))
	if err != nil {
		t.Fatal(err)
	}
	for cmd, want := range map[string]string{
		"git status --short": actAllow, "ls -la": actAllow, "python --version": actAllow, "where python": actAllow,
		"git -C /etc status": actAsk, "ls /etc": actAsk, "cat /etc/passwd": actAsk, "python build.py": actAsk,
		"ls; rm -rf x": actAsk, "git log | sh": actAsk,
	} {
		if v := p.eval(execReq(cmd, false)); v.Action != want {
			t.Errorf("%q: %s, want %s", cmd, v, want)
		}
	}
	w := func(tool, p string) policyReq { return policyReq{Tool: tool, HasPath: true, Path: p} }
	for q, want := range map[policyReq]string{
		w("fs_write", "/w/a.txt"): actAllow, w("fs_mkdir", "/w/x"): actAllow, w("fs_remove", "/w/a"): actAsk,
		w("fs_write", "/w/.git/config"): actDeny, w("fs_edit", "/w/.env"): actDeny,
	} {
		if v := p.eval(q); v.Action != want {
			t.Errorf("%s %s: %s, want %s", q.Tool, q.Path, v, want)
		}
	}
}
