package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fsAgent(t *testing.T) *nodeAgent {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	ci := probeCaseInsensitive(root)
	return &nodeAgent{roots: []string{root}, shell: detectShell(),
		info: NodeInfo{AllowExec: true, MaxOutput: 1 << 20, MaxTimeout: 30, RootsCaseInsensitive: []bool{ci}}}
}

func TestProbeCaseInsensitiveMatchesFilesystem(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "lower.txt"), nil, 0o644)
	_, err := os.Stat(filepath.Join(dir, "LOWER.TXT"))
	if got, want := probeCaseInsensitive(dir), err == nil; got != want {
		t.Errorf("probe = %v, filesystem says %v", got, want)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".relay-case-probe-*")); len(left) != 0 {
		t.Errorf("probe left files: %v", left)
	}
}

func TestShellKind(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Program Files\PowerShell\7\pwsh.exe`: "powershell", "powershell.exe": "powershell",
		"/bin/bash": "bash", "/usr/local/bin/bash": "bash", "/bin/sh": "sh", "/bin/dash": "sh",
	} {
		if got := shellKind(in); got != want {
			t.Errorf("shellKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExecArgv(t *testing.T) {
	a := fsAgent(t)
	// Arguments reach the program verbatim: no shell splitting or expansion.
	argv := []string{"printf", "%s|", "a b", "$HOME", "中文"}
	if runtime.GOOS == "windows" {
		t.Skip("printf is Unix-only; the Windows smoke test covers argv there")
	}
	res, err := a.doExec(context.Background(), ExecArgs{Argv: argv})
	if err != nil {
		t.Fatal(err)
	}
	r := res.(*ExecResult)
	if r.Stdout != "a b|$HOME|中文|" || r.ExitCode != 0 {
		t.Errorf("argv exec = %+v", r)
	}
	r2, _ := a.doExec(context.Background(), ExecArgs{Argv: []string{"sh", "-c", "exit 9"}})
	if r2.(*ExecResult).ExitCode != 9 {
		t.Errorf("exit code = %d", r2.(*ExecResult).ExitCode)
	}
	if _, err := a.doExec(context.Background(), ExecArgs{Argv: []string{"true"}, Command: "true"}); err == nil {
		t.Error("both argv and command accepted")
	}
	if _, err := a.doExec(context.Background(), ExecArgs{}); err == nil {
		t.Error("neither argv nor command accepted")
	}
	if r, err := a.doExec(context.Background(), ExecArgs{Argv: []string{"no-such-program-xyz"}}); err == nil {
		t.Errorf("missing program: %+v", r)
	}
}

func TestRemoveSymlinkKeepsTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	a := fsAgent(t)
	r := a.roots[0]
	os.MkdirAll(filepath.Join(r, "real"), 0o755)
	os.WriteFile(filepath.Join(r, "real/keep.txt"), []byte("x"), 0o644)
	os.Symlink(filepath.Join(r, "real"), filepath.Join(r, "link"))
	res, err := a.doRemove(RemoveArgs{Path: "link", Recursive: true})
	if err != nil || res["symlink"] != true {
		t.Fatalf("remove link = %v, %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(r, "real/keep.txt")); err != nil {
		t.Error("removing the link deleted its target")
	}
	// A link pointing outside the roots can be removed, but not read through.
	outside := t.TempDir()
	os.Symlink(outside, filepath.Join(r, "out"))
	if _, err := a.doRead(ReadArgs{Path: "out/x"}); err == nil {
		t.Error("read through escaping link")
	}
	if _, err := a.doRemove(RemoveArgs{Path: "out"}); err != nil {
		t.Errorf("remove escaping link: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Error("outside dir was touched")
	}
}

func TestRemoveRules(t *testing.T) {
	a := fsAgent(t)
	r := a.roots[0]
	os.MkdirAll(filepath.Join(r, "d/sub"), 0o755)
	os.WriteFile(filepath.Join(r, "d/sub/f"), nil, 0o644)
	if _, err := a.doRemove(RemoveArgs{Path: "d"}); err == nil || !strings.Contains(err.Error(), "recursive") {
		t.Errorf("non-empty dir without recursive: %v", err)
	}
	if _, err := a.doRemove(RemoveArgs{Path: "d", Recursive: true}); err != nil {
		t.Error(err)
	}
	for _, p := range []string{r, ".", "d/.."} {
		if _, err := a.doRemove(RemoveArgs{Path: p, Recursive: true}); err == nil || !strings.Contains(err.Error(), "node root") {
			t.Errorf("remove root %q: %v", p, err)
		}
	}
	if _, err := a.doMove(MoveArgs{Src: ".", Dst: "elsewhere"}); err == nil || !strings.Contains(err.Error(), "node root") {
		t.Errorf("move root: %v", err)
	}
	if _, err := a.doRemove(RemoveArgs{Path: "../x"}); err == nil {
		t.Error("removed outside the root")
	}
}

func TestMove(t *testing.T) {
	a := fsAgent(t)
	r := a.roots[0]
	os.WriteFile(filepath.Join(r, "a.txt"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(r, "b.txt"), []byte("b"), 0o644)
	if _, err := a.doMove(MoveArgs{Src: "a.txt", Dst: "b.txt"}); err == nil {
		t.Error("overwrote without overwrite")
	}
	if _, err := a.doMove(MoveArgs{Src: "a.txt", Dst: "new/dir/c.txt"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(r, "new/dir/c.txt")); string(b) != "a" {
		t.Error("move lost content")
	}
	// Case-only rename works on case-insensitive filesystems too.
	if _, err := a.doMove(MoveArgs{Src: "b.txt", Dst: "B.txt"}); err != nil {
		t.Errorf("case-only rename: %v", err)
	}
	if _, err := a.doMove(MoveArgs{Src: r, Dst: "x"}); err == nil {
		t.Error("moved the root")
	}
}

func TestGlobAndGrep(t *testing.T) {
	a := fsAgent(t)
	r := a.roots[0]
	os.MkdirAll(filepath.Join(r, "src/pkg"), 0o755)
	os.WriteFile(filepath.Join(r, "src/main.go"), []byte("package main\n// TODO: one\n"), 0o644)
	os.WriteFile(filepath.Join(r, "src/pkg/util.go"), []byte("package pkg\r\n// todo: two\r\n"), 0o644)
	os.WriteFile(filepath.Join(r, "src/pkg/data.bin"), []byte("TODO\x00binary"), 0o644)
	os.WriteFile(filepath.Join(r, "README.md"), []byte("TODO: docs\n"), 0o644)

	g, err := a.doGlob(GlobArgs{Pattern: "**/*.go"})
	if err != nil || strings.Join(g.Matches, ",") != "src/main.go,src/pkg/util.go" {
		t.Errorf("glob = %+v, %v", g, err)
	}
	g, _ = a.doGlob(GlobArgs{Path: "src", Pattern: "*"})
	if strings.Join(g.Matches, ",") != "main.go,pkg/" {
		t.Errorf("glob src/* = %v", g.Matches)
	}
	gr, err := a.doGrep(GrepArgs{Pattern: "todo", IgnoreCase: true, Glob: "**/*.go"})
	if err != nil || len(gr.Matches) != 2 || gr.Matches[1].Text != "// todo: two" || gr.Matches[1].Line != 2 {
		t.Errorf("grep = %+v, %v", gr, err)
	}
	gr, _ = a.doGrep(GrepArgs{Pattern: "TODO"})
	if len(gr.Matches) != 2 || gr.Skipped != 1 { // README + main.go; data.bin skipped as binary
		t.Errorf("grep all = %+v", gr)
	}
	gr, _ = a.doGrep(GrepArgs{Path: "README.md", Pattern: "docs"})
	if len(gr.Matches) != 1 || gr.Matches[0].File != "README.md" {
		t.Errorf("grep one file = %+v", gr)
	}
}

func TestStatHash(t *testing.T) {
	a := fsAgent(t)
	os.WriteFile(filepath.Join(a.roots[0], "f"), []byte("hello"), 0o640)
	st, err := a.doStat(StatArgs{Path: "f", Hash: true})
	sum := sha256.Sum256([]byte("hello"))
	if err != nil || !st.Exists || st.Size != 5 || st.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("stat = %+v, %v", st, err)
	}
	st, _ = a.doStat(StatArgs{Path: "missing"})
	if st.Exists {
		t.Error("missing file exists")
	}
}

func TestFoldsCaseFromProbe(t *testing.T) {
	p, err := parsePolicy([]byte(`{"default":"allow","rules":[{"tools":["fs_write"],"paths":["**/.git/**"],"action":"deny"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		info NodeInfo
		want string
	}{
		// macOS on its default case-insensitive APFS: .GIT is .git, so it must be denied.
		{"mac insensitive", NodeInfo{Name: "m", OS: "darwin", Roots: []string{"/Users/me/w"}, RootsCaseInsensitive: []bool{true}}, actDeny},
		// A case-sensitive Linux volume: .GIT is a different directory.
		{"linux sensitive", NodeInfo{Name: "l", OS: "linux", Roots: []string{"/srv/w"}, RootsCaseInsensitive: []bool{false}}, actAllow},
		// Linux with an ext4 casefold root.
		{"linux casefold", NodeInfo{Name: "l", OS: "linux", Roots: []string{"/srv/w"}, RootsCaseInsensitive: []bool{true}}, actDeny},
		// Pre-0.5 node that did not probe: platform default.
		{"old mac node", NodeInfo{Name: "m", OS: "darwin", Roots: []string{"/Users/me/w"}}, actDeny},
		{"windows", NodeInfo{Name: "w", OS: "windows", Roots: []string{`D:\w`}, RootsCaseInsensitive: []bool{true}}, actDeny},
	}
	for _, c := range cases {
		nc := &nodeConn{info: c.info}
		q := buildReq("a", "fs_write", mustJSON(map[string]string{"path": "repo/.GIT/config"}), nc)
		if v := p.eval(q); v.Action != c.want {
			t.Errorf("%s: %s -> %s, want %s", c.name, q.Path, v.Action, c.want)
		}
	}
	// Per-root: the second root is case-sensitive.
	nc := &nodeConn{info: NodeInfo{OS: "darwin", Roots: []string{"/a", "/Volumes/cs"}, RootsCaseInsensitive: []bool{true, false}}}
	if foldsCase(nc.info, "/Volumes/cs/x") || !foldsCase(nc.info, "/a/x") {
		t.Error("per-root case folding")
	}
}

func TestMoveNeedsBothPaths(t *testing.T) {
	p, _ := parsePolicy([]byte(`{"default":"allow","rules":[{"tools":["fs_move"],"paths":["/w/locked/**"],"action":"deny"}]}`))
	nc := &nodeConn{info: NodeInfo{Name: "n", OS: "linux", Roots: []string{"/w"}, RootsCaseInsensitive: []bool{false}}}
	qs := buildReqs("a", "fs_move", mustJSON(map[string]string{"src": "free/a", "dst": "locked/a"}), nc)
	if v, _ := p.evalAll(qs); len(qs) != 2 || v.Action != actDeny {
		t.Errorf("move into locked dir: %d reqs, %s", len(qs), v)
	}
	qs = buildReqs("a", "exec", mustJSON(map[string]any{"argv": []string{"git", "commit", "-m", "a b"}}), nc)
	if qs[0].Command != `git commit -m "a b"` {
		t.Errorf("argv command string = %q", qs[0].Command)
	}
}
