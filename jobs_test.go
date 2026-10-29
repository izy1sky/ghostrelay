//go:build !windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTrimPartialRune(t *testing.T) {
	s := []byte("ab中") // 中 is 3 bytes
	cases := map[int]string{5: "ab中", 4: "ab", 3: "ab", 2: "ab", 1: "a"}
	for n, want := range cases {
		if got := string(trimPartialRune(s[:n])); got != want {
			t.Errorf("trim(%q) = %q, want %q", s[:n], got, want)
		}
	}
}

func TestReadChunk(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log")
	os.WriteFile(p, []byte("hello 世界\n"), 0o600)
	r, err := readChunk(p, 0, 8, false) // cuts inside 世
	if err != nil {
		t.Fatal(err)
	}
	if r.Data != "hello " || r.NextOffset != 6 || !r.More {
		t.Errorf("first chunk = %+v", r)
	}
	r, _ = readChunk(p, r.NextOffset, 100, false)
	if r.Data != "世界\n" || r.More {
		t.Errorf("second chunk = %+v", r)
	}
	r, _ = readChunk(p, 0, 7, true)
	if r.Data != "世界\n" {
		t.Errorf("tail = %+v", r)
	}
	r, _ = readChunk(p, 999, 10, false)
	if r.Data != "" || r.NextOffset != int64(len("hello 世界\n")) {
		t.Errorf("past end = %+v", r)
	}
}

func testAgent(t *testing.T, maxJobs int, maxTimeout time.Duration) *nodeAgent {
	root := t.TempDir()
	jm, err := newJobManager(filepath.Join(t.TempDir(), "jobs"), maxJobs, maxTimeout)
	if err != nil {
		t.Fatal(err)
	}
	a := &nodeAgent{roots: []string{root}, shell: detectShell(), jobs: jm,
		info: NodeInfo{AllowExec: true, MaxOutput: 1 << 20, MaxTimeout: 60}}
	return a
}

func startJob(t *testing.T, a *nodeAgent, cmd string, timeout int) *JobInfo {
	t.Helper()
	res, err := a.doExec(context.Background(), ExecArgs{Command: cmd, Background: true, TimeoutSec: timeout, Owner: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	return res.(*JobInfo)
}

func TestJobLifecycle(t *testing.T) {
	a := testAgent(t, 2, time.Minute)
	ji := startJob(t, a, "echo one; sleep 0.3; echo two >&2; exit 7", 0)
	if ji.State != jobRunning || ji.Owner != "tester" {
		t.Fatalf("start = %+v", ji)
	}
	// Long-poll until it finishes, collecting output by offset.
	var out strings.Builder
	var off int64
	for i := 0; i < 20; i++ {
		r, err := a.jobs.logs(context.Background(), JobLogsArgs{ID: ji.ID, Offset: off, WaitSec: 2}, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		out.WriteString(r.Data)
		off = r.NextOffset
		if r.Job.State != jobRunning && !r.More {
			if r.Job.State != jobExited || r.Job.ExitCode == nil || *r.Job.ExitCode != 7 {
				t.Fatalf("final = %+v", r.Job)
			}
			break
		}
	}
	if out.String() != "one\ntwo\n" {
		t.Errorf("output = %q", out.String())
	}
}

func TestJobKillAndTimeout(t *testing.T) {
	a := testAgent(t, 3, time.Minute)
	k := startJob(t, a, "sleep 30 & sleep 30", 0)
	to := startJob(t, a, "sleep 30", 1)
	ji, err := a.jobs.kill(k.ID)
	if err != nil || ji.State != jobKilled {
		t.Fatalf("kill = %+v, %v", ji, err)
	}
	r, err := a.jobs.logs(context.Background(), JobLogsArgs{ID: to.ID, WaitSec: 5}, 1<<20)
	if err != nil || r.Job.State != jobTimedOut {
		t.Fatalf("timeout = %+v, %v", r, err)
	}
	if len(a.jobs.list().Jobs) != 2 {
		t.Errorf("list = %+v", a.jobs.list())
	}
}

func TestJobLimit(t *testing.T) {
	a := testAgent(t, 1, time.Minute)
	ji := startJob(t, a, "sleep 30", 0)
	defer a.jobs.kill(ji.ID)
	if _, err := a.doExec(context.Background(), ExecArgs{Command: "true", Background: true}); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Errorf("second job: %v", err)
	}
}
