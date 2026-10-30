package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// relay with no arguments (or `relay ui`) opens a setup page in the browser,
// so nobody has to learn the commands: share this computer (relay join), set
// up the hub (relay init + serve), and afterwards see and steer them.
//
// The page is served only to this computer (127.0.0.1) and every API call
// must carry the random key from the link relay opens, so other web pages and
// other users can't drive it. Nodes and servers it starts without a service
// run as child processes and stop when relay does.

//go:embed ui/app.html
var appPage string

type app struct {
	key       string
	nodeCfg   string
	serverCfg string

	mu       sync.Mutex
	children map[string]*child // "node", "server"
	svcCache map[string]svcEntry
}

type child struct {
	cmd  *exec.Cmd
	done chan struct{} // closed when it exits
}

type svcEntry struct {
	status string
	at     time.Time
}

func runApp(args []string) {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:0", "address for the page; only loopback addresses are allowed")
	noBrowser := fs.Bool("no-browser", false, "print the link instead of opening a browser")
	fs.Parse(args)

	host, _, err := net.SplitHostPort(*listen)
	if ip := net.ParseIP(host); err != nil || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
		log.Fatalf("--listen %s: the page must stay on this computer (127.0.0.1)", *listen)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	a := &app{key: newToken()[:32], nodeCfg: defaultNodeConfig(), serverCfg: defaultServerConfig(),
		children: map[string]*child{}, svcCache: map[string]svcEntry{}}
	link := fmt.Sprintf("http://127.0.0.1:%d/#k=%s", port, a.key)

	fmt.Printf("relay %s setup page:\n\n  %s\n\nKeep this window open while you use it. Ctrl-C quits (and stops anything it started without a service).\n", version, link)
	if *noBrowser || !openBrowser(link) {
		fmt.Printf("\nOpen the link above in a browser on this computer. From another computer, tunnel it first:\n  ssh -L %d:127.0.0.1:%d <this host>\n", port, port)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		a.stopChildren()
		os.Exit(0)
	}()
	srv := &http.Server{Handler: a.routes(port), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.Serve(ln))
}

func openBrowser(url string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return false
		}
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start() == nil
}

func (a *app) routes(port int) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, appPage)
	})
	api := map[string]func(*http.Request) (any, error){
		"GET /api/state":           a.state,
		"GET /api/node/activity":   a.nodeActivity,
		"POST /api/join/check":     a.joinCheck,
		"POST /api/folders/pick":   a.pickFolder,
		"POST /api/folders/check":  a.checkFolder,
		"POST /api/join":           a.join,
		"POST /api/node/pause":     a.nodePause,
		"POST /api/node/start":     func(*http.Request) (any, error) { return ok(), a.startChild("node", a.nodeCfg) },
		"POST /api/node/autostart": a.nodeAutostart,
		"POST /api/node/leave":     a.nodeLeave,
		"POST /api/hub/check":      a.hubCheck,
		"POST /api/hub/public":     a.hubPublic,
		"POST /api/hub/setup":      a.hubSetup,
		"POST /api/hub/start":      func(*http.Request) (any, error) { return ok(), a.startHub() },
	}
	for route, h := range api {
		mux.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Relay-Key")), []byte(a.key)) != 1 {
				http.Error(w, "open the link relay printed (this page's key is missing or old)", http.StatusUnauthorized)
				return
			}
			res, err := h(r)
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				res = map[string]string{"error": err.Error()}
			}
			json.NewEncoder(w).Encode(res)
		})
	}
	// Only this computer's own names: a DNS-rebinding page gets another Host.
	hosts := map[string]bool{fmt.Sprintf("127.0.0.1:%d", port): true, fmt.Sprintf("localhost:%d", port): true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hosts[r.Host] {
			http.Error(w, "wrong host", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func ok() map[string]bool { return map[string]bool{"ok": true} }

func decodeBody(r *http.Request, v any) error {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(v); err != nil {
		return errors.New("bad request")
	}
	return nil
}

// ---- state --------------------------------------------------------------------

type nodeView struct {
	Configured bool        `json:"configured"`
	Name       string      `json:"name,omitempty"`
	Server     string      `json:"server,omitempty"`
	Roots      []string    `json:"roots,omitempty"`
	AllowExec  bool        `json:"allow_exec"`
	Service    string      `json:"service,omitempty"` // the service manager's word, or "not installed"
	Here       bool        `json:"here"`              // running as a child of this page
	Running    bool        `json:"running"`           // its status file is fresh
	Paused     bool        `json:"paused"`
	Status     *nodeStatus `json:"status,omitempty"`
}

type hubView struct {
	Configured bool   `json:"configured"`
	URL        string `json:"url,omitempty"`
	Listen     string `json:"listen,omitempty"`
	Running    bool   `json:"running"`
	Service    string `json:"service,omitempty"`
	Here       bool   `json:"here"`
	Console    string `json:"console,omitempty"` // the console on this computer, key included
	JoinCode   string `json:"join_code,omitempty"`
	Warning    string `json:"warning,omitempty"`
}

type folder struct {
	Label string `json:"label"`
	Path  string `json:"path"`
}

func (a *app) state(*http.Request) (any, error) {
	host, _ := os.Hostname()
	return map[string]any{
		"version": version, "os": runtime.GOOS, "arch": runtime.GOARCH, "hostname": host,
		"default_name": sanitizeName(host), "lan": lanIP(),
		"suggest": suggestFolders(), "node": a.nodeView(), "hub": a.hubView(),
	}, nil
}

func (a *app) nodeView() nodeView {
	v := nodeView{}
	m, err := readJSONMap(a.nodeCfg)
	if err != nil {
		return v
	}
	v.Configured = true
	v.Name, _ = m["name"].(string)
	v.Server, _ = m["server"].(string)
	v.AllowExec, _ = m["allow-exec"].(bool)
	switch r := m["root"].(type) {
	case []any:
		for _, x := range r {
			v.Roots = append(v.Roots, fmt.Sprint(x))
		}
	case string:
		v.Roots = []string{r}
	}
	v.Service = a.serviceStatus("node", a.nodeCfg)
	v.Here = a.childRunning("node")
	if _, err := os.Stat(sidecar(a.nodeCfg, ".paused")); err == nil {
		v.Paused = true
	}
	var st nodeStatus
	if b, err := os.ReadFile(sidecar(a.nodeCfg, ".status.json")); err == nil && json.Unmarshal(b, &st) == nil {
		v.Status = &st
		v.Running = time.Since(st.Updated) < statusStale
	}
	return v
}

func (a *app) hubView() hubView {
	v := hubView{}
	m, err := readJSONMap(a.serverCfg)
	if err != nil {
		return v
	}
	str := func(k string) string { s, _ := m[k].(string); return s }
	v.Configured, v.URL, v.Listen = true, str("url"), str("listen")
	v.Service = a.serviceStatus("server", a.serverCfg)
	v.Here = a.childRunning("server")
	v.JoinCode = encodeJoin(joinInfo{Server: v.URL, Token: str("node-token")})
	v.Warning = portMismatch(v.Listen, v.URL)
	if _, port, err := net.SplitHostPort(v.Listen); err == nil {
		local := "http://127.0.0.1:" + port
		v.Console = local + "/admin/#k=" + str("admin-token")
		c := &http.Client{Timeout: 2 * time.Second}
		if resp, err := c.Get(local + "/healthz"); err == nil {
			resp.Body.Close()
			v.Running = resp.StatusCode == http.StatusOK
		}
	}
	return v
}

// serviceStatus asks the service manager, at most every 10 s: on Windows that
// starts PowerShell, too slow for every poll.
func (a *app) serviceStatus(role, cfg string) string {
	a.mu.Lock()
	e, hit := a.svcCache[role]
	a.mu.Unlock()
	if hit && time.Since(e.at) < 10*time.Second {
		return e.status
	}
	st := "not installed"
	if s, err := newService(role, cfg); err == nil && s.installed() {
		st = s.status()
	}
	a.mu.Lock()
	a.svcCache[role] = svcEntry{st, time.Now()}
	a.mu.Unlock()
	return st
}

func (a *app) forgetService(role string) {
	a.mu.Lock()
	delete(a.svcCache, role)
	a.mu.Unlock()
}

func suggestFolders() []folder {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var out []folder
	var seen []os.FileInfo // Projects and projects are one folder on most Macs
	for _, n := range []string{"Projects", "projects", "code", "src", "work", "dev", "Documents", "Desktop"} {
		p := filepath.Join(home, n)
		st, err := os.Stat(p)
		if err != nil || !st.IsDir() || slices.ContainsFunc(seen, func(o os.FileInfo) bool { return os.SameFile(o, st) }) {
			continue
		}
		seen = append(seen, st)
		out = append(out, folder{n, p})
	}
	return out
}

// ---- children -----------------------------------------------------------------

func (a *app) childRunning(role string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.children[role]
	if c == nil {
		return false
	}
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

// startChild runs `relay node|serve --config cfg` for as long as this page runs.
func (a *app) startChild(role, cfg string) error {
	if a.childRunning(role) {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	sub := map[string]string{"node": "node", "server": "serve"}[role]
	cmd := exec.Command(exe, sub, "--config", cfg)
	cmd.Stdout, cmd.Stderr = prefixed(role), prefixed(role)
	if err := cmd.Start(); err != nil {
		return err
	}
	c := &child{cmd, make(chan struct{})}
	a.mu.Lock()
	a.children[role] = c
	a.mu.Unlock()
	go func() { cmd.Wait(); close(c.done) }()
	return nil
}

func (a *app) stopChild(role string) {
	a.mu.Lock()
	c := a.children[role]
	delete(a.children, role)
	a.mu.Unlock()
	if c != nil {
		c.cmd.Process.Kill()
		<-c.done
	}
}

func (a *app) stopChildren() {
	a.stopChild("node")
	a.stopChild("server")
}

// prefixed passes a child's log through to this window, each line tagged.
func prefixed(role string) io.Writer {
	pr, pw := io.Pipe()
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", role, sc.Text())
		}
	}()
	return pw
}

// ---- share this computer ----------------------------------------------------------

func (a *app) joinCheck(r *http.Request) (any, error) {
	var req struct{ Code string }
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	j, err := decodeJoin(req.Code)
	if err != nil {
		return nil, err
	}
	if err := checkNodeToken(j.Server, j.Token); err != nil {
		return map[string]string{"server": j.Server, "problem": err.Error()}, nil
	}
	return map[string]string{"server": j.Server}, nil
}

func (a *app) pickFolder(*http.Request) (any, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("osascript", "-e", `POSIX path of (choose folder with prompt "Choose a folder agents may use")`)
	case "windows":
		cmd = exec.Command("powershell.exe", "-NoProfile", "-STA", "-Command",
			`Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.FolderBrowserDialog; `+
				`$d.Description = 'Choose a folder agents may use'; $f = New-Object System.Windows.Forms.Form -Property @{TopMost = $true}; `+
				`if ($d.ShowDialog($f) -eq 'OK') { $d.SelectedPath }`)
	default:
		if p, err := exec.LookPath("zenity"); err == nil {
			cmd = exec.Command(p, "--file-selection", "--directory", "--title=Choose a folder agents may use")
		} else if p, err := exec.LookPath("kdialog"); err == nil {
			cmd = exec.Command(p, "--getexistingdirectory")
		}
	}
	if cmd == nil {
		return nil, errors.New("no folder dialog on this system; type the folder's path instead")
	}
	out, _ := cmd.Output() // cancelling exits non-zero with nothing printed
	p := strings.TrimSpace(string(out))
	if p == "" {
		return map[string]bool{"cancelled": true}, nil
	}
	return checkFolderPath(p)
}

func (a *app) checkFolder(r *http.Request) (any, error) {
	var req struct{ Path string }
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	return checkFolderPath(req.Path)
}

// checkFolderPath resolves a folder and warns when it is a whole drive or the
// whole home folder: an agent would see browser data, keys and documents.
func checkFolderPath(p string) (any, error) {
	p = strings.TrimSpace(p)
	home, _ := os.UserHomeDir()
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		p = filepath.Join(home, p[1:])
	}
	abs, err := filepath.Abs(p)
	if err != nil || p == "" {
		return nil, errors.New("type a folder's full path")
	}
	abs = filepath.Clean(abs)
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%s is not a folder on this computer", abs)
	}
	res := map[string]string{"path": abs}
	switch {
	case filepath.Dir(abs) == abs:
		res["warning"] = "That shares the whole drive. Agents could read everything on it, including other people's files and system settings. Share a project folder instead."
	case home != "" && strings.EqualFold(abs, filepath.Clean(home)):
		res["warning"] = "That shares your whole home folder: documents, browser data and keys. Share a project folder inside it instead."
	}
	return res, nil
}

func (a *app) join(r *http.Request) (any, error) {
	var req struct {
		Code      string   `json:"code"`
		Name      string   `json:"name"`
		Roots     []string `json:"roots"`
		AllowExec bool     `json:"allow_exec"`
		Autostart bool     `json:"autostart"`
	}
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	if _, err := os.Stat(a.nodeCfg); err == nil {
		return nil, errors.New("this computer is already shared; leave the hub first to join another")
	}
	cfg, err := saveJoin(req.Code, req.Name, req.Roots, req.AllowExec, a.nodeCfg, nil)
	if err != nil {
		return nil, err
	}
	log.Printf("saved %s", cfg)
	return ok(), a.runRole("node", cfg, req.Autostart)
}

// runRole starts a node or server: as a service when asked, else as a child.
func (a *app) runRole(role, cfg string, service bool) error {
	a.forgetService(role)
	if !service {
		return a.startChild(role, cfg)
	}
	a.stopChild(role)
	return serviceInstall(role, cfg)
}

func (a *app) nodePause(r *http.Request) (any, error) {
	var req struct{ Paused bool }
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	p := sidecar(a.nodeCfg, ".paused")
	if !req.Paused {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return ok(), nil
	}
	return ok(), writePrivate(p, []byte("Paused from the relay page. Delete this file to resume.\n"))
}

func (a *app) nodeAutostart(r *http.Request) (any, error) {
	var req struct{ On bool }
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	if req.On {
		return ok(), a.runRole("node", a.nodeCfg, true)
	}
	a.forgetService("node")
	if s, err := newService("node", a.nodeCfg); err == nil && s.installed() {
		if err := s.uninstall(); err != nil {
			return nil, err
		}
	}
	return ok(), a.startChild("node", a.nodeCfg) // keep sharing while the page runs
}

func (a *app) nodeLeave(*http.Request) (any, error) {
	a.stopChild("node")
	a.forgetService("node")
	if s, err := newService("node", a.nodeCfg); err == nil && s.installed() {
		if err := s.uninstall(); err != nil {
			return nil, err
		}
	}
	for _, suffix := range []string{".json", ".status.json", ".paused", ".activity.jsonl", ".activity.jsonl.1"} {
		if err := os.Remove(sidecar(a.nodeCfg, suffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return ok(), nil
}

func (a *app) nodeActivity(*http.Request) (any, error) {
	b, err := readTail(sidecar(a.nodeCfg, ".activity.jsonl"), 64<<10)
	if err != nil {
		return []activity{}, nil
	}
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	out := []activity{}
	for i := len(lines) - 1; i >= 0 && len(out) < 50; i-- {
		var e activity
		if json.Unmarshal(lines[i], &e) == nil {
			out = append(out, e)
		}
	}
	return out, nil
}

// readTail returns up to the last n bytes of a file, starting at a line.
func readTail(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := max(st.Size()-n, 0)
	b := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(b, off); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if off > 0 {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return b, nil
}

// ---- be the hub -----------------------------------------------------------------

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p < 1 || p > 65535 {
		return 0, errors.New("the port is a number from 1 to 65535")
	}
	return p, nil
}

func (a *app) hubCheck(r *http.Request) (any, error) {
	var req struct{ Port string }
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	port, err := parsePort(req.Port)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return map[string]string{"problem": fmt.Sprintf("Port %d is already in use on this computer. Pick another one.", port)}, nil
	}
	ln.Close()
	return map[string]bool{"free": true}, nil
}

// hubPublic asks api.ipify.org for this network's public address. The page
// only calls it when the person clicks "Find my public address".
func (a *app) hubPublic(r *http.Request) (any, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("couldn't ask api.ipify.org: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	ip := net.ParseIP(strings.TrimSpace(string(b)))
	if ip == nil {
		return nil, errors.New("api.ipify.org gave no address")
	}
	return map[string]string{"ip": ip.String()}, nil
}

func (a *app) hubSetup(r *http.Request) (any, error) {
	var req struct {
		Host      string `json:"host"`
		Port      string `json:"port"`
		Preset    string `json:"preset"`
		Autostart bool   `json:"autostart"`
	}
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	host := strings.TrimSpace(req.Host)
	if host == "" || strings.ContainsAny(host, " /:@?#") && net.ParseIP(host) == nil {
		return nil, errors.New("give the address as a plain IP address or domain name, like 203.0.113.5 or relay.example.com")
	}
	port, err := parsePort(req.Port)
	if err != nil {
		return nil, err
	}
	pub := "http://" + net.JoinHostPort(host, strconv.Itoa(port))
	cfg, cfgPath, err := initServer(filepath.Dir(a.serverCfg), fmt.Sprintf(":%d", port), pub, req.Preset, false)
	if err != nil {
		return nil, err
	}
	log.Printf("wrote %s (hub at %s)", cfgPath, cfg["url"])
	if err := a.runRole("server", cfgPath, req.Autostart); err != nil {
		return nil, err
	}
	for i := 0; i < 25 && !a.hubView().Running; i++ {
		time.Sleep(200 * time.Millisecond)
	}
	return a.hubView(), nil
}

func (a *app) startHub() error {
	if _, err := os.Stat(a.serverCfg); err != nil {
		return errors.New("the hub isn't set up on this computer")
	}
	return a.startChild("server", a.serverCfg)
}
