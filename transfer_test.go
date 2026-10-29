//go:build !windows

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func transferAgent(t *testing.T) *nodeAgent {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	u, err := newUploads(filepath.Join(t.TempDir(), "uploads"))
	if err != nil {
		t.Fatal(err)
	}
	return &nodeAgent{roots: []string{root}, uploads: u}
}

func TestStrandedUploadsCleaned(t *testing.T) {
	a := transferAgent(t)
	open, err := a.doPutOpen(PutOpenArgs{Path: "half.bin"})
	if err != nil {
		t.Fatal(err)
	}
	a.doPutChunk(PutChunkArgs{UploadID: open.UploadID, Data: []byte("partial")})
	// Simulate a crash: a new node process starts on the same state dir.
	if _, err := newUploads(a.uploads.dir); err != nil {
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(filepath.Join(a.roots[0], ".relay-up-*")); len(left) != 0 {
		t.Errorf("temp files left after restart: %v", left)
	}
}

func TestChunkRoundTrip(t *testing.T) {
	a := transferAgent(t)
	data := make([]byte, 3*maxChunk/2+17) // binary, crosses a chunk boundary
	rand.Read(data)
	os.WriteFile(filepath.Join(a.roots[0], "src.bin"), data, 0o755)

	open, err := a.doPutOpen(PutOpenArgs{Path: "out/dst.bin", Mode: 0o755})
	if err != nil {
		t.Fatal(err)
	}
	var off int64
	for {
		c, err := a.doGetChunk(GetChunkArgs{Path: "src.bin", Offset: off, Length: maxChunk})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.doPutChunk(PutChunkArgs{UploadID: open.UploadID, Offset: off, Data: c.Data}); err != nil {
			t.Fatal(err)
		}
		off += int64(len(c.Data))
		if c.EOF {
			break
		}
	}
	sum := sha256.Sum256(data)
	res, err := a.doPutClose(PutCloseArgs{UploadID: open.UploadID, SHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(res.Path)
	if !bytes.Equal(got, data) {
		t.Fatal("content differs")
	}
	if st, _ := os.Stat(res.Path); st.Mode().Perm() != 0o755 {
		t.Errorf("mode = %v", st.Mode().Perm())
	}
	if left, _ := filepath.Glob(filepath.Join(a.roots[0], "out", ".relay-up-*")); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}

func TestPutRejects(t *testing.T) {
	a := transferAgent(t)
	os.WriteFile(filepath.Join(a.roots[0], "exists.txt"), []byte("keep"), 0o644)
	if _, err := a.doPutOpen(PutOpenArgs{Path: "exists.txt"}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("overwrite refusal: %v", err)
	}
	if _, err := a.doPutOpen(PutOpenArgs{Path: "../escape.txt"}); err == nil {
		t.Error("jail escape accepted")
	}
	open, _ := a.doPutOpen(PutOpenArgs{Path: "x.txt"})
	if _, err := a.doPutChunk(PutChunkArgs{UploadID: open.UploadID, Offset: 5, Data: []byte("hi")}); err == nil {
		t.Error("out-of-order chunk accepted")
	}
	a.doPutChunk(PutChunkArgs{UploadID: open.UploadID, Offset: 0, Data: []byte("hi")})
	if _, err := a.doPutClose(PutCloseArgs{UploadID: open.UploadID, SHA256: strings.Repeat("0", 64)}); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("bad hash: %v", err)
	}
	if _, err := os.Stat(filepath.Join(a.roots[0], "x.txt")); err == nil {
		t.Error("file written despite hash mismatch")
	}
	if left, _ := filepath.Glob(filepath.Join(a.roots[0], ".relay-up-*")); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}

func TestWalkSkipsSymlinks(t *testing.T) {
	a := transferAgent(t)
	r := a.roots[0]
	os.MkdirAll(filepath.Join(r, "d/empty"), 0o755)
	os.WriteFile(filepath.Join(r, "d/a.txt"), []byte("a"), 0o644)
	os.Symlink("/etc", filepath.Join(r, "d/link"))
	w, err := a.doWalk(StatArgs{Path: "d"})
	if err != nil {
		t.Fatal(err)
	}
	var rels []string
	for _, e := range w.Entries {
		rels = append(rels, e.Rel)
	}
	if strings.Join(rels, ",") != "a.txt,empty" || len(w.Skipped) != 1 || w.Skipped[0] != "link" {
		t.Errorf("entries=%v skipped=%v", rels, w.Skipped)
	}
}

func TestTransferHelpers(t *testing.T) {
	if got := baseName(`D:\work\a.txt`, "windows"); got != "a.txt" {
		t.Errorf("windows base = %q", got)
	}
	if got := baseName("/srv/a\\b.txt", "linux"); got != `a\b.txt` {
		t.Errorf("unix base = %q", got)
	}
	if got := joinNode(`D:\work\`, "x/y.txt"); got != `D:\work/x/y.txt` {
		t.Errorf("join = %q", got)
	}
	if got := humanBytes(1536); got != "1.5 KiB" {
		t.Errorf("human = %q", got)
	}
}

func TestEvalAllStrictest(t *testing.T) {
	p, _ := parsePolicy([]byte(`{"default":"allow","rules":[
		{"tools":["fs_write"],"paths":["**/.git/**"],"action":"deny"},
		{"tools":["fs_write"],"paths":["/dst/big/**"],"action":"ask"}]}`))
	nc := &nodeConn{info: NodeInfo{Name: "n", OS: "linux", Roots: []string{"/dst"}}}
	w := func(path string) policyReq {
		return buildReq("a", "fs_write", mustJSON(map[string]string{"path": path}), nc)
	}
	if v, _ := p.evalAll([]policyReq{w("/dst/x"), w("/dst/big/y")}); v.Action != actAsk {
		t.Errorf("want ask, got %s", v)
	}
	if v, q := p.evalAll([]policyReq{w("/dst/big/y"), w("/dst/repo/.git/config"), w("/dst/z")}); v.Action != actDeny || q.Path != "/dst/repo/.git/config" {
		t.Errorf("want deny on .git, got %s %s", v, q.Path)
	}
	if _, err := parsePolicy([]byte(`{"rules":[{"tools":["transfer"],"action":"allow"}]}`)); err == nil {
		t.Error("rule on transfer accepted")
	}
}
