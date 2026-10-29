package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"unicode/utf8"
)

// Background jobs live on the node, independent of any link: a dropped
// connection or a server restart leaves them running, and the next link can
// read their output. stdout and stderr go, interleaved, to one log file.
// A node restart forgets its jobs (and deletes their logs).

const (
	jobRunning  = "running"
	jobExited   = "exited"
	jobKilled   = "killed"
	jobTimedOut = "timed_out"

	keepFinishedJobs = 50
	finishedJobTTL   = 24 * time.Hour
	maxJobWait       = 60 // seconds job_logs may long-poll
)

type job struct {
	id, command, cwd, owner string
	logPath                 string
	pid                     int
	started                 time.Time
	cmd                     *exec.Cmd
	done                    chan struct{}

	mu       sync.Mutex
	state    string
	exitCode int
	ended    time.Time
	killed   bool
	timedOut bool
}

type jobManager struct {
	dir        string
	maxRunning int
	maxTimeout time.Duration

	mu   sync.Mutex
	jobs map[string]*job
}

func newJobManager(dir string, maxRunning int, maxTimeout time.Duration) (*jobManager, error) {
	// Logs from a previous node process belong to jobs it can no longer track.
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &jobManager{dir: dir, maxRunning: maxRunning, maxTimeout: maxTimeout, jobs: map[string]*job{}}, nil
}

func (j *job) info() JobInfo {
	j.mu.Lock()
	defer j.mu.Unlock()
	ji := JobInfo{ID: j.id, Command: j.command, Cwd: j.cwd, Owner: j.owner, PID: j.pid, State: j.state,
		Started: j.started.UTC().Format(time.RFC3339)}
	end := time.Now()
	if j.state != jobRunning {
		code := j.exitCode
		ji.ExitCode = &code
		ji.Ended = j.ended.UTC().Format(time.RFC3339)
		end = j.ended
	}
	ji.DurationMs = end.Sub(j.started).Milliseconds()
	if st, err := os.Stat(j.logPath); err == nil {
		ji.OutputBytes = st.Size()
	}
	return ji
}

func (j *job) running() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state == jobRunning
}

func (m *jobManager) get(id string) (*job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if j := m.jobs[id]; j != nil {
		return j, nil
	}
	return nil, fmt.Errorf("no job %q on this node (finished jobs are kept for %s, at most %d; a node restart forgets all jobs)", id, finishedJobTTL, keepFinishedJobs)
}

// start launches cmd (already built by the caller, with its working directory
// checked) in the background.
func (m *jobManager) start(cmd *exec.Cmd, args ExecArgs, cwd string) (*JobInfo, error) {
	m.mu.Lock()
	m.pruneLocked()
	running := 0
	for _, j := range m.jobs {
		if j.running() {
			running++
		}
	}
	if running >= m.maxRunning {
		m.mu.Unlock()
		return nil, fmt.Errorf("%d jobs already running on this node (max %d); wait or kill one", running, m.maxRunning)
	}
	idb := make([]byte, 4)
	rand.Read(idb)
	id := "j" + hex.EncodeToString(idb)
	m.mu.Unlock()

	logPath := filepath.Join(m.dir, id+".log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	// The child writes straight to the file, so no pipe has to stay open in
	// this process and output survives anything that happens to the link.
	cmd.Stdout, cmd.Stderr = f, f
	setProcGroup(cmd)
	if err := cmd.Start(); err != nil {
		f.Close()
		os.Remove(logPath)
		return nil, err
	}
	f.Close()

	j := &job{id: id, command: args.Command, cwd: cwd, owner: args.Owner, logPath: logPath,
		pid: cmd.Process.Pid, started: time.Now(), cmd: cmd, done: make(chan struct{}), state: jobRunning}
	m.mu.Lock()
	m.jobs[id] = j
	m.mu.Unlock()

	timeout := m.maxTimeout
	if args.TimeoutSec > 0 {
		timeout = min(timeout, time.Duration(args.TimeoutSec)*time.Second)
	}
	timer := time.AfterFunc(timeout, func() {
		j.mu.Lock()
		j.timedOut = true
		j.mu.Unlock()
		killTree(cmd)
	})
	go func() {
		err := cmd.Wait()
		timer.Stop()
		j.mu.Lock()
		defer j.mu.Unlock()
		j.ended = time.Now()
		j.exitCode = -1
		var ee *exec.ExitError
		if err == nil {
			j.exitCode = 0
		} else if errors.As(err, &ee) {
			j.exitCode = ee.ExitCode()
		}
		switch {
		case j.timedOut:
			j.state = jobTimedOut
		case j.killed:
			j.state = jobKilled
		default:
			j.state = jobExited
		}
		close(j.done)
	}()
	ji := j.info()
	return &ji, nil
}

func (m *jobManager) kill(id string) (*JobInfo, error) {
	j, err := m.get(id)
	if err != nil {
		return nil, err
	}
	j.mu.Lock()
	wasRunning := j.state == jobRunning
	if wasRunning {
		j.killed = true
	}
	j.mu.Unlock()
	if wasRunning {
		killTree(j.cmd)
		select {
		case <-j.done:
		case <-time.After(5 * time.Second):
		}
	}
	ji := j.info()
	return &ji, nil
}

func (m *jobManager) list() *JobsListResult {
	m.mu.Lock()
	m.pruneLocked()
	jobs := make([]*job, 0, len(m.jobs))
	for _, j := range m.jobs {
		jobs = append(jobs, j)
	}
	m.mu.Unlock()
	sort.Slice(jobs, func(a, b int) bool { return jobs[a].started.Before(jobs[b].started) })
	res := &JobsListResult{Jobs: []JobInfo{}}
	for _, j := range jobs {
		res.Jobs = append(res.Jobs, j.info())
	}
	return res
}

// pruneLocked drops finished jobs past the TTL, and the oldest beyond the cap.
func (m *jobManager) pruneLocked() {
	var finished []*job
	for _, j := range m.jobs {
		j.mu.Lock()
		if j.state != jobRunning {
			finished = append(finished, j)
		}
		j.mu.Unlock()
	}
	sort.Slice(finished, func(a, b int) bool { return finished[a].ended.After(finished[b].ended) })
	for i, j := range finished {
		if i >= keepFinishedJobs || time.Since(j.ended) > finishedJobTTL {
			delete(m.jobs, j.id)
			os.Remove(j.logPath)
		}
	}
}

// logs returns output from offset (or the last max bytes with tail). With
// wait_sec it waits until there is new output or the job ends.
func (m *jobManager) logs(ctx context.Context, args JobLogsArgs, maxOutput int) (*JobLogsResult, error) {
	j, err := m.get(args.ID)
	if err != nil {
		return nil, err
	}
	limit := args.MaxBytes
	if limit <= 0 || limit > maxOutput {
		limit = min(64<<10, maxOutput)
	}
	wait := time.Duration(min(max(args.WaitSec, 0), maxJobWait)) * time.Second
	deadline := time.Now().Add(wait)
	for {
		res, err := readChunk(j.logPath, args.Offset, limit, args.Tail)
		if err != nil {
			return nil, err
		}
		if res.Data != "" || !j.running() || time.Now().After(deadline) {
			res.Job = j.info()
			return res, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-j.done:
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func readChunk(path string, offset int64, limit int, tail bool) (*JobLogsResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if tail {
		offset = max(size-int64(limit), 0)
	}
	offset = min(max(offset, 0), size)
	buf := make([]byte, min(int64(limit), size-offset))
	n, err := f.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	// Keep a lone partial rune rather than return nothing and never advance.
	if t := trimPartialRune(buf[:n]); len(t) > 0 || n == 0 {
		buf = t
	} else {
		buf = buf[:n]
	}
	return &JobLogsResult{
		Data:       string(buf),
		Offset:     offset,
		NextOffset: offset + int64(len(buf)),
		More:       offset+int64(len(buf)) < size,
	}, nil
}

// trimPartialRune drops an incomplete UTF-8 sequence at the end of a chunk;
// those bytes are returned by the next read instead.
func trimPartialRune(b []byte) []byte {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if !utf8.FullRune(b[i:]) {
				return b[:i]
			}
			break
		}
	}
	return b
}
