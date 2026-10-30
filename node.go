package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type nodeAgent struct {
	url     string
	token   string
	info    NodeInfo
	roots   []string // absolute, symlinks resolved
	shell   string
	sem     chan struct{}
	jobs    *jobManager
	uploads *uploads
	local   *nodeLocal
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func runNode(args []string) {
	host, _ := os.Hostname()
	fs := flag.NewFlagSet("node", flag.ExitOnError)
	serverURL := fs.String("server", "", "server URL, e.g. https://relay.example.com:8787")
	tok := fs.String("token", "", "node token (prefer env RELAY_NODE_TOKEN)")
	name := fs.String("name", sanitizeName(host), "name agents use to address this node")
	var roots multiFlag
	fs.Var(&roots, "root", "directory the node may read/write (repeatable; first one is the default cwd)")
	allowExec := fs.Bool("allow-exec", false, "allow running shell commands")
	maxOutput := fs.Int("max-output", 256<<10, "max bytes returned per stream / per read")
	maxTimeout := fs.Int("max-timeout", 600, "max seconds a command may run")
	maxJobs := fs.Int("max-jobs", 16, "max background jobs running at once")
	maxJobTimeout := fs.Int("max-job-timeout", 6*3600, "max seconds a background job may run")
	stateDir := fs.String("state-dir", "", "where job logs are kept (default: user cache dir/relay-node/<name>)")
	probe := fs.String("probe", "git,python,python3,node,go,ffmpeg,docker", "commands to look up and report in node_info")
	logFile := fs.String("log-file", "", "write the log to this file instead of stderr (used by relay service)")
	settings := loadFlags(fs, args, defaultNodeConfig())
	setupLog(*logFile, settings)

	a := &nodeAgent{token: tokenFrom(*tok, "RELAY_NODE_TOKEN"), sem: make(chan struct{}, 8)}
	if *serverURL == "" || a.token == "" {
		log.Fatal("--server and RELAY_NODE_TOKEN (or --token) are required; or set this machine up with: relay join <code>")
	}
	if len(roots) == 0 {
		log.Fatal("at least one --root is required")
	}
	if !validName.MatchString(*name) {
		log.Fatalf("invalid --name %q", *name)
	}
	var err error
	if a.url, err = nodeURL(*serverURL); err != nil {
		log.Fatal(err)
	}
	for _, r := range roots {
		abs, err := filepath.Abs(r)
		if err == nil {
			abs, err = filepath.EvalSymlinks(abs)
		}
		if err != nil {
			log.Fatalf("root %q: %v", r, err)
		}
		if st, err := os.Stat(abs); err != nil || !st.IsDir() {
			log.Fatalf("root %q is not a directory", r)
		}
		a.roots = append(a.roots, abs)
	}
	a.shell = detectShell()
	caseInsensitive := make([]bool, len(a.roots))
	for i, r := range a.roots {
		caseInsensitive[i] = probeCaseInsensitive(r)
	}
	if *stateDir == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			log.Fatalf("no user cache dir; pass --state-dir: %v", err)
		}
		*stateDir = filepath.Join(cache, "relay-node", *name)
	}
	if a.uploads, err = newUploads(filepath.Join(*stateDir, "uploads")); err != nil {
		log.Fatalf("upload dir: %v", err)
	}
	if a.jobs, err = newJobManager(filepath.Join(*stateDir, "jobs"), *maxJobs, time.Duration(*maxJobTimeout)*time.Second); err != nil {
		log.Fatalf("job dir: %v", err)
	}

	tools := map[string]string{}
	for _, t := range strings.Split(*probe, ",") {
		if t = strings.TrimSpace(t); t == "" {
			continue
		}
		if p, err := exec.LookPath(t); err == nil {
			tools[t] = p
		}
	}
	a.info = NodeInfo{
		Name: *name, Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH, Hostname: host,
		Shell: a.shell, ShellKind: shellKind(a.shell), PathSep: string(filepath.Separator),
		Roots: a.roots, RootsCaseInsensitive: caseInsensitive, AllowExec: *allowExec,
		MaxOutput: *maxOutput, MaxTimeout: *maxTimeout, MaxJobs: *maxJobs, MaxJobTime: *maxJobTimeout, Tools: tools,
	}

	log.Printf("relay node %q -> %s  %s/%s shell=%s roots=%v case-insensitive=%v exec=%v",
		a.info.Name, a.url, a.info.OS, a.info.Arch, a.info.ShellKind, a.roots, caseInsensitive, a.info.AllowExec)
	a.local = newNodeLocal(settings, a.url)
	backoff := time.Second
	for {
		if a.local.gone() {
			log.Printf("settings %s were removed (relay leave); stopping", settings)
			return
		}
		if a.local.paused() {
			if a.local.state() != "paused" {
				log.Printf("paused: %s exists; staying disconnected until it's removed", sidecar(settings, ".paused"))
			}
			a.local.set("paused", "")
			backoff = time.Second
			time.Sleep(2 * time.Second)
			continue
		}
		a.local.set("connecting", "")
		connected, err := a.session()
		if connected {
			backoff = time.Second
		}
		if a.local.paused() || a.local.gone() {
			continue
		}
		if websocket.CloseStatus(err) == closeDisconnected {
			// The hub's owner turned this machine off in the console. Ask
			// again every minute, so it comes back once they allow it.
			if a.local.state() != "disconnected" {
				log.Printf("the hub's owner disconnected this machine; asking again every minute")
			}
			a.local.set("disconnected", "")
			backoff = time.Second
			for i := 0; i < 30 && !a.local.paused() && !a.local.gone(); i++ {
				time.Sleep(2 * time.Second)
			}
			continue
		}
		a.local.set("connecting", err.Error())
		log.Printf("link down: %v; reconnecting in %s", err, backoff)
		time.Sleep(backoff + time.Duration(rand.Int64N(int64(backoff/4)+1)))
		backoff = min(backoff*2, 30*time.Second)
	}
}

func sanitizeName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == '.' || r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, s)
	s = strings.Trim(strings.TrimSuffix(s, ".local"), "-.") // macOS: mbp.local -> mbp
	if s == "" {
		return "node"
	}
	return s
}

func nodeURL(s string) (string, error) {
	switch {
	case strings.HasPrefix(s, "https://"):
		s = "wss://" + strings.TrimPrefix(s, "https://")
	case strings.HasPrefix(s, "http://"):
		s = "ws://" + strings.TrimPrefix(s, "http://")
	case strings.HasPrefix(s, "ws://"), strings.HasPrefix(s, "wss://"):
	default:
		return "", fmt.Errorf("--server must start with http(s):// or ws(s)://")
	}
	s = strings.TrimRight(s, "/")
	if !strings.HasSuffix(s, "/node") {
		s += "/node"
	}
	return s, nil
}

// session runs one connection until it fails. connected reports whether the
// server accepted us, so the caller can reset its backoff.
func (a *nodeAgent) session() (connected bool, err error) {
	dctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	c, resp, err := websocket.Dial(dctx, a.url, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + a.token}},
	})
	cancel()
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return false, errors.New("server rejected the node token (401)")
		}
		return false, err
	}
	defer c.CloseNow()
	c.SetReadLimit(maxFrame)

	var wmu sync.Mutex
	send := func(m *Msg) error {
		wmu.Lock()
		defer wmu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return wsjson.Write(ctx, c, m)
	}

	if err := send(&Msg{Type: msgHello, Info: &a.info}); err != nil {
		return false, err
	}
	hctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var welcome Msg
	err = wsjson.Read(hctx, c, &welcome)
	cancel()
	if err != nil || welcome.Type != msgWelcome {
		return false, fmt.Errorf("no welcome from server: %w", err)
	}
	log.Printf("connected as %q", a.info.Name)
	a.local.set("connected", "")

	// Everything running on this link is cancelled when the link ends.
	linkCtx, cancelLink := context.WithCancel(context.Background())
	defer cancelLink()
	go func() { // pausing (from the local page) drops the link
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-linkCtx.Done():
				return
			case <-t.C:
				if a.local.paused() || a.local.gone() {
					c.Close(websocket.StatusNormalClosure, "paused on the node")
					return
				}
			}
		}
	}()
	go func() {
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-linkCtx.Done():
				return
			case <-t.C:
				ctx, cancel := context.WithTimeout(linkCtx, 10*time.Second)
				err := c.Ping(ctx)
				cancel()
				if err != nil {
					c.CloseNow()
					return
				}
			}
		}
	}()

	var rmu sync.Mutex
	running := map[string]context.CancelFunc{}
	for {
		var m Msg
		if err := wsjson.Read(context.Background(), c, &m); err != nil {
			return true, err
		}
		switch m.Type {
		case msgCancel:
			rmu.Lock()
			if cancel := running[m.ID]; cancel != nil {
				cancel()
			}
			rmu.Unlock()
		case msgReq:
			ctx, cancel := context.WithCancel(linkCtx)
			rmu.Lock()
			running[m.ID] = cancel
			rmu.Unlock()
			go func(m Msg) {
				defer func() {
					rmu.Lock()
					delete(running, m.ID)
					rmu.Unlock()
					cancel()
				}()
				a.sem <- struct{}{}
				res, err := a.dispatch(ctx, m.Op, m.Args)
				<-a.sem
				a.local.record(m.Op, m.Args, err)
				out := &Msg{Type: msgRes, ID: m.ID}
				if err != nil {
					out.Error = err.Error()
				} else if out.Result, err = json.Marshal(res); err != nil {
					out.Error = err.Error()
				}
				send(out)
			}(m)
		}
	}
}

func (a *nodeAgent) dispatch(ctx context.Context, op string, raw json.RawMessage) (any, error) {
	switch op {
	case "exec":
		var args ExecArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return a.doExec(ctx, args)
	case "fs_read":
		var args ReadArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return a.doRead(args)
	case "fs_write":
		var args WriteArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return a.doWrite(args)
	case "fs_edit":
		var args EditArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return a.doEdit(args)
	case "fs_list":
		var args ListArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return a.doList(args)
	case "job_logs":
		var args JobLogsArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return a.jobs.logs(ctx, args, a.info.MaxOutput)
	case "job_kill":
		var args JobArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return a.jobs.kill(args.ID)
	case "jobs_list":
		return a.jobs.list(), nil
	}
	return a.dispatchTransfer(op, raw)
}

func (a *nodeAgent) dispatchTransfer(op string, raw json.RawMessage) (any, error) {
	switch op {
	case "fs_stat", "fs_walk":
		var args StatArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		if op == "fs_stat" {
			return a.doStat(args)
		}
		return a.doWalk(args)
	case "fs_move":
		var args MoveArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return a.doMove(args)
	case "fs_remove":
		var args RemoveArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return a.doRemove(args)
	case "fs_glob":
		var args GlobArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return a.doGlob(args)
	case "fs_grep":
		var args GrepArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return a.doGrep(args)
	case "fs_mkdir":
		var args MkdirArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return a.doMkdir(args)
	case "get_chunk":
		var args GetChunkArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return a.doGetChunk(args)
	case "put_open":
		var args PutOpenArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return a.doPutOpen(args)
	case "put_chunk":
		var args PutChunkArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return a.doPutChunk(args)
	case "put_close", "put_abort":
		var args PutCloseArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		if op == "put_close" {
			return a.doPutClose(args)
		}
		return a.doPutAbort(args)
	}
	return nil, fmt.Errorf("unknown op %q", op)
}

// ---- fs jail -----------------------------------------------------------------

// resolve turns p into an absolute, symlink-free path and refuses anything
// outside the roots. Relative paths are taken from the first root.
func (a *nodeAgent) resolve(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return a.roots[0], nil
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(a.roots[0], p)
	}
	real, err := evalExisting(filepath.Clean(p))
	if err != nil {
		return "", err
	}
	for _, r := range a.roots {
		if within(r, real) {
			return real, nil
		}
	}
	return "", fmt.Errorf("path %q is outside this node's roots %v", p, a.roots)
}

// evalExisting resolves symlinks in the longest prefix of p that exists, so a
// file that is about to be created is still checked through its real parent.
func evalExisting(p string) (string, error) {
	rest, cur := "", p
	for {
		r, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(r, rest), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

func within(root, p string) bool {
	rel, err := filepath.Rel(root, p) // case-insensitive on Windows
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// ---- exec --------------------------------------------------------------------

func detectShell() string {
	if runtime.GOOS == "windows" {
		if p, err := exec.LookPath("pwsh.exe"); err == nil {
			return p
		}
		if p, err := exec.LookPath("powershell.exe"); err == nil {
			return p
		}
		return "powershell.exe"
	}
	if p, err := exec.LookPath("bash"); err == nil {
		return p
	}
	return "/bin/sh"
}

const psPrelude = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $OutputEncoding=[System.Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; "

func (a *nodeAgent) shellCmd(command string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.Command(a.shell, "-NoProfile", "-NonInteractive", "-Command", psPrelude+command)
	}
	return exec.Command(a.shell, "-c", command)
}

// buildCmd runs argv directly when given (identical on every OS: no shell,
// no quoting rules), otherwise the command line in the node's shell.
func (a *nodeAgent) buildCmd(args ExecArgs) *exec.Cmd {
	if len(args.Argv) > 0 {
		return exec.Command(args.Argv[0], args.Argv[1:]...)
	}
	return a.shellCmd(args.Command)
}

func (a *nodeAgent) doExec(ctx context.Context, args ExecArgs) (any, error) {
	if !a.info.AllowExec {
		return nil, errors.New("exec is disabled on this node (start it with --allow-exec)")
	}
	if (strings.TrimSpace(args.Command) == "") == (len(args.Argv) == 0) {
		return nil, errors.New("give exactly one of command (runs in the node's shell) or argv (runs a program directly)")
	}
	cwd, err := a.resolve(args.Cwd)
	if err != nil {
		return nil, err
	}
	if args.Background {
		cmd := a.buildCmd(args)
		cmd.Dir = cwd
		if args.Command == "" {
			args.Command = argvString(args.Argv)
		}
		return a.jobs.start(cmd, args, cwd)
	}
	timeout := args.TimeoutSec
	if timeout <= 0 {
		timeout = 120
	}
	timeout = min(timeout, a.info.MaxTimeout)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := a.buildCmd(args)
	cmd.Dir = cwd
	stdout := &capBuf{max: a.info.MaxOutput}
	stderr := &capBuf{max: a.info.MaxOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// Background children that keep our pipes open must not block the reply.
	cmd.WaitDelay = 2 * time.Second
	setProcGroup(cmd)

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	res := &ExecResult{}
	select {
	case err = <-done:
	case <-ctx.Done():
		killTree(cmd)
		select {
		case err = <-done:
		case <-time.After(5 * time.Second):
		}
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("cancelled by caller; process tree killed")
		}
		res.TimedOut = true
	}

	res.DurationMs = time.Since(start).Milliseconds()
	res.Stdout, res.StdoutTruncated = stdout.text()
	res.Stderr, res.StderrTruncated = stderr.text()
	var ee *exec.ExitError
	switch {
	case res.TimedOut:
		res.ExitCode = -1
	case err == nil:
	case errors.Is(err, exec.ErrWaitDelay):
		// The shell exited; a background child still held the pipes.
		res.ExitCode = cmd.ProcessState.ExitCode()
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	default:
		res.ExitCode = -1
		res.Stderr += "\n[relay] " + err.Error()
	}
	return res, nil
}

// capBuf keeps the first max bytes written to it and counts the rest.
type capBuf struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	max   int
	total int
}

func (c *capBuf) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total += len(p)
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

func (c *capBuf) text() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.ToValidUTF8(c.buf.String(), "�"), c.total > c.buf.Len()
}

// ---- fs ops ------------------------------------------------------------------

const maxReadFile = 50 << 20

func (a *nodeAgent) readText(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st.IsDir() {
		return "", fmt.Errorf("%s is a directory (use fs_list)", path)
	}
	if st.Size() > maxReadFile {
		return "", fmt.Errorf("%s is %d bytes; files over %d bytes are not supported", path, st.Size(), maxReadFile)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if bytes.IndexByte(data[:min(len(data), 8192)], 0) >= 0 {
		return "", fmt.Errorf("%s looks binary; only text files are supported", path)
	}
	return string(data), nil
}

func (a *nodeAgent) doRead(args ReadArgs) (*ReadResult, error) {
	path, err := a.resolve(args.Path)
	if err != nil {
		return nil, err
	}
	text, err := a.readText(path)
	if err != nil {
		return nil, err
	}
	res := &ReadResult{Path: path, CRLF: strings.Contains(text, "\r\n")}
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	res.TotalLines = len(lines)
	offset, limit := max(args.Offset, 1), args.Limit
	if limit <= 0 {
		limit = 2000
	}
	res.StartLine = offset

	var b strings.Builder
	for i := offset - 1; i < len(lines) && i < offset-1+limit; i++ {
		line := strings.TrimSuffix(lines[i], "\r")
		if b.Len()+len(line)+1 > a.info.MaxOutput {
			res.Truncated = true
			break
		}
		if i > offset-1 {
			b.WriteByte('\n')
		}
		b.WriteString(line)
	}
	res.Content = strings.ToValidUTF8(b.String(), "�")
	return res, nil
}

// writeAtomic writes via a temp file + rename so readers never see half a file.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	mode := fs.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(dir, ".relay-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	os.Chmod(tmp.Name(), mode)
	if err := os.Rename(tmp.Name(), path); err != nil {
		// Windows refuses to replace a file another process holds open.
		return os.WriteFile(path, data, mode)
	}
	return nil
}

func (a *nodeAgent) doWrite(args WriteArgs) (*WriteResult, error) {
	path, err := a.resolve(args.Path)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	if err := writeAtomic(path, []byte(args.Content)); err != nil {
		return nil, err
	}
	return &WriteResult{Path: path, Bytes: len(args.Content)}, nil
}

func (a *nodeAgent) doEdit(args EditArgs) (*EditResult, error) {
	path, err := a.resolve(args.Path)
	if err != nil {
		return nil, err
	}
	if args.OldString == "" {
		return nil, errors.New("old_string is empty")
	}
	if args.OldString == args.NewString {
		return nil, errors.New("old_string and new_string are identical")
	}
	text, err := a.readText(path)
	if err != nil {
		return nil, err
	}
	old, nw := args.OldString, args.NewString
	n := strings.Count(text, old)
	// fs_read strips \r, so on a CRLF file retry with CRLF line endings.
	if n == 0 && strings.Contains(text, "\r\n") && !strings.Contains(old, "\r\n") {
		crlf := strings.ReplaceAll(old, "\n", "\r\n")
		if c := strings.Count(text, crlf); c > 0 {
			old, nw, n = crlf, strings.ReplaceAll(nw, "\n", "\r\n"), c
		}
	}
	switch {
	case n == 0:
		return nil, fmt.Errorf("old_string not found in %s", path)
	case n > 1 && !args.ReplaceAll:
		return nil, fmt.Errorf("old_string occurs %d times in %s; add surrounding context or set replace_all", n, path)
	}
	if args.ReplaceAll {
		text = strings.ReplaceAll(text, old, nw)
	} else {
		text = strings.Replace(text, old, nw, 1)
	}
	if err := writeAtomic(path, []byte(text)); err != nil {
		return nil, err
	}
	return &EditResult{Path: path, Replacements: n}, nil
}

const maxListEntries = 2000

func (a *nodeAgent) doList(args ListArgs) (*ListResult, error) {
	path, err := a.resolve(args.Path)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(ents, func(i, j int) bool { return ents[i].IsDir() && !ents[j].IsDir() })
	res := &ListResult{Path: path, Entries: []ListEntry{}}
	for _, e := range ents {
		if len(res.Entries) == maxListEntries {
			res.Truncated = true
			break
		}
		le := ListEntry{Name: e.Name(), Dir: e.IsDir()}
		if info, err := e.Info(); err == nil {
			le.Size = info.Size()
			le.ModTime = info.ModTime().UTC().Format(time.RFC3339)
		}
		res.Entries = append(res.Entries, le)
	}
	return res, nil
}
