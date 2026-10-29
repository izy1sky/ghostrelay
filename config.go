package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Config files hold the same settings as the command-line flags, with the
// flag names as keys, so `relay serve` and `relay node` can start with no
// arguments. relay init writes the server's, relay join a node's.
//
//	~/.relay/server/server.json   tokens, listen address, policy, audit (0600)
//	~/.relay/server/policy.json
//	~/.relay/node.json            server URL, node token, name, roots (0600)
//
// RELAY_HOME moves ~/.relay. Flags given on the command line win over the
// file, and RELAY_*_TOKEN environment variables win over both.

func relayHome() string {
	if h := os.Getenv("RELAY_HOME"); h != "" {
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("no home directory; set RELAY_HOME: %v", err)
	}
	return filepath.Join(home, ".relay")
}

func defaultServerConfig() string { return filepath.Join(relayHome(), "server", "server.json") }
func defaultNodeConfig() string   { return filepath.Join(relayHome(), "node.json") }

// pathKeys are resolved against the config file's directory when relative.
var pathKeys = map[string]bool{"policy": true, "audit": true, "tls-cert": true, "tls-key": true,
	"state-dir": true, "log-file": true, "root": true}

// applyConfig sets every flag in fs that the command line left unset from the
// JSON file at path. A list value sets a repeatable flag once per element.
func applyConfig(fs *flag.FlagSet, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("%s: %v", path, err)
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	dir := filepath.Dir(path)
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.HasPrefix(k, "#") || k == "config" {
			continue // comments, and no recursion
		}
		if fs.Lookup(k) == nil {
			return fmt.Errorf("%s: unknown setting %q (keys are `relay %s` flag names)", path, k, fs.Name())
		}
		if set[k] {
			continue
		}
		vals, ok := cfg[k].([]any)
		if !ok {
			vals = []any{cfg[k]}
		}
		for _, v := range vals {
			s := fmt.Sprint(v)
			if f, ok := v.(float64); ok {
				s = fmt.Sprintf("%d", int64(f))
			}
			if pathKeys[k] && s != "" && !filepath.IsAbs(s) {
				s = filepath.Join(dir, s)
			}
			if err := fs.Set(k, s); err != nil {
				return fmt.Errorf("%s: %s: %v", path, k, err)
			}
		}
	}
	return nil
}

// loadFlags parses args, then fills unset flags from --config, or from the
// default config file when the command was given no arguments at all. It
// returns the file it used, if any.
func loadFlags(fs *flag.FlagSet, args []string, defaultPath string) string {
	cfgPath := fs.String("config", "", "settings file (JSON, keys are flag names); default "+defaultPath+" when run with no arguments")
	fs.Parse(args)
	path := *cfgPath
	if path == "" && len(args) == 0 {
		if _, err := os.Stat(defaultPath); err == nil {
			path = defaultPath
		}
	}
	if path != "" {
		if err := applyConfig(fs, path); err != nil {
			log.Fatalf("config: %v", err)
		}
	}
	return path
}

// setupLog sends the log to a file (rotated at 10 MiB) for services, and
// hides the console window a Windows logon task would otherwise show.
func setupLog(path, settings string) {
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			log.Fatalf("log file: %v", err)
		}
		if st, err := os.Stat(path); err == nil && st.Size() > 10<<20 {
			os.Rename(path, path+".1")
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Fatalf("log file: %v", err)
		}
		log.SetOutput(f)
		hideOwnConsole()
	}
	if settings != "" {
		log.Printf("settings from %s", settings)
	}
}

func writeJSON0600(path string, v any) error {
	b, _ := json.MarshalIndent(v, "", "  ")
	return writePrivate(path, append(b, '\n'))
}

// writePrivate writes a file only its owner can read: it holds tokens.
func writePrivate(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func readJSONMap(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(b, &m)
}

// ---- join codes ---------------------------------------------------------------

// A join code carries everything a node needs to connect: the server URL and
// the node token. It is a secret, like the token inside it.
const joinPrefix = "rj1_"

type joinInfo struct {
	Server string `json:"s"`
	Token  string `json:"t"`
}

func encodeJoin(j joinInfo) string {
	b, _ := json.Marshal(j)
	return joinPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func decodeJoin(code string) (joinInfo, error) {
	var j joinInfo
	rest, ok := strings.CutPrefix(strings.TrimSpace(code), joinPrefix)
	if !ok {
		return j, errors.New("not a join code (they start with " + joinPrefix + "; get one with: relay invite)")
	}
	b, err := base64.RawURLEncoding.DecodeString(rest)
	if err == nil {
		err = json.Unmarshal(b, &j)
	}
	if err != nil || j.Server == "" || j.Token == "" {
		return j, errors.New("join code is damaged; copy it again from: relay invite")
	}
	return j, nil
}

// checkNodeToken asks the server whether it accepts the node token, without
// connecting as a node: /node checks the token before the websocket upgrade.
func checkNodeToken(server, token string) error {
	u, err := url.Parse(strings.TrimRight(server, "/") + "/node")
	if err != nil {
		return err
	}
	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the server at %s: %v\n  is `relay serve` running there, and is the address reachable from this machine?", server, err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return errors.New("the server rejected the node token; get a fresh code with: relay invite")
	}
	return nil
}

// ---- relay init / invite ---------------------------------------------------------

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", filepath.Dir(defaultServerConfig()), "where to write the server's settings")
	listen := fs.String("listen", ":8787", "address the server listens on")
	pubURL := fs.String("url", "", "address nodes and agents use to reach the server (default: http://<this machine's LAN IP><listen port>)")
	preset := fs.String("policy", "ask", "starting policy: ask (reads allowed, everything else asks you), readonly, or open (everything allowed; for local tests)")
	force := fs.Bool("force", false, "overwrite existing settings (new tokens: existing nodes and agents must be re-added)")
	fs.Parse(args)

	pol, ok := policyPresets[*preset]
	if !ok {
		log.Fatalf("unknown --policy %q (ask, readonly or open)", *preset)
	}
	cfgPath := filepath.Join(*dir, "server.json")
	if _, err := os.Stat(cfgPath); err == nil && !*force {
		log.Fatalf("%s already exists. Print its join code with: relay invite   (or start over with --force)", cfgPath)
	}
	if *pubURL == "" {
		*pubURL = guessURL(*listen)
	}
	if _, err := nodeURL(*pubURL); err != nil {
		log.Fatalf("--url: %v", err)
	}
	cfg := map[string]any{
		"#":           "relay serve settings, written by relay init. Keys are relay serve flag names. Keep this file private.",
		"listen":      *listen,
		"url":         strings.TrimRight(*pubURL, "/"),
		"node-token":  newToken(),
		"agent-token": newToken(),
		"admin-token": newToken(),
		"policy":      "policy.json",
		"audit":       "audit.jsonl",
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		log.Fatal(err)
	}
	polPath := filepath.Join(*dir, "policy.json")
	if err := writePrivate(polPath, []byte(pol)); err != nil {
		log.Fatal(err)
	}
	if err := writeJSON0600(cfgPath, cfg); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Wrote %s and policy.json (preset %q).\n\n", cfgPath, *preset)
	printInvite(cfg, cfgPath)
}

func runInvite(args []string) {
	fs := flag.NewFlagSet("invite", flag.ExitOnError)
	path := fs.String("config", defaultServerConfig(), "server settings written by relay init")
	fs.Parse(args)
	cfg, err := readJSONMap(*path)
	if err != nil {
		log.Fatalf("%v\n  create one with: relay init", err)
	}
	printInvite(cfg, *path)
}

func printInvite(cfg map[string]any, cfgPath string) {
	str := func(k string) string { s, _ := cfg[k].(string); return s }
	u := str("url")
	if u == "" {
		u = guessURL(str("listen"))
	}
	serve := "relay serve"
	if cfgPath != defaultServerConfig() {
		serve += " --config " + quoteArg(cfgPath)
	}
	fmt.Printf(`1. Start the server here (or run it as a service: relay service install server):

     %s

2. On each machine to share, with the relay binary for its OS:

     relay join %s --root <folder> [--allow-exec] [--install]

   --root: the folder agents may use (repeatable). --allow-exec: let them run commands.
   --install: keep it running as a service, also after reboots.

3. On the agent's machine (Claude Code):

     claude mcp add --transport http relay %s/mcp --header "Authorization: Bearer %s"

4. Approve calls the policy asks about: %s/admin/  (admin token: %s)
   or here: relay approvals

The join code and tokens are secrets. Print this again with: relay invite
`, serve, encodeJoin(joinInfo{Server: u, Token: str("node-token")}), u, str("agent-token"), u, str("admin-token"))
	if strings.HasPrefix(u, "http://") {
		fmt.Println("\nNote: plain http sends tokens in clear. Fine on a LAN or localhost; on the internet use TLS (tls-cert, tls-key) or a TLS proxy.")
	}
}

// guessURL builds http://<LAN IP>:<port> from a listen address. Dialing UDP
// sends no packets; it only picks the interface with the default route.
func guessURL(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		port = "8787"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
		if c, err := net.Dial("udp", "192.0.2.1:9"); err == nil {
			host = c.LocalAddr().(*net.UDPAddr).IP.String()
			c.Close()
		}
	}
	return "http://" + net.JoinHostPort(host, port)
}

func quoteArg(s string) string {
	if strings.ContainsAny(s, " \t'\"") {
		return `"` + s + `"`
	}
	return s
}

// ---- relay join ------------------------------------------------------------------

func runJoin(args []string) {
	host, _ := os.Hostname()
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	name := fs.String("name", sanitizeName(host), "name agents use for this machine")
	var roots multiFlag
	fs.Var(&roots, "root", "folder agents may use (repeatable; the first is the default working directory)")
	allowExec := fs.Bool("allow-exec", false, "let agents run commands on this machine")
	cfgPath := fs.String("config", defaultNodeConfig(), "where to save this node's settings")
	install := fs.Bool("install", false, "install and start as a service that survives reboots, instead of running in this terminal")
	pos := parseInterleaved(fs, args)
	if len(pos) != 1 {
		log.Fatal("usage: relay join <code> --root <folder> [--name N] [--allow-exec] [--install]\n  get the code on the server with: relay invite")
	}
	j, err := decodeJoin(pos[0])
	if err != nil {
		log.Fatal(err)
	}
	if len(roots) == 0 {
		log.Fatal("give at least one --root: the folder agents may use on this machine")
	}
	if !validName.MatchString(*name) {
		log.Fatalf("invalid --name %q (letters, digits, - _ .)", *name)
	}
	var absRoots []string
	for _, r := range roots {
		abs, err := filepath.Abs(r)
		if err != nil {
			log.Fatal(err)
		}
		if st, err := os.Stat(abs); err != nil || !st.IsDir() {
			log.Fatalf("--root %s is not a folder", abs)
		}
		absRoots = append(absRoots, abs)
	}
	fmt.Printf("checking %s ... ", j.Server)
	if err := checkNodeToken(j.Server, j.Token); err != nil {
		fmt.Println("failed")
		log.Fatal(err)
	}
	fmt.Println("ok")

	cfg := map[string]any{
		"#":          "relay node settings, written by relay join. Keys are relay node flag names. Keep this file private.",
		"server":     j.Server,
		"token":      j.Token,
		"name":       *name,
		"root":       absRoots,
		"allow-exec": *allowExec,
	}
	abs, _ := filepath.Abs(*cfgPath)
	if err := writeJSON0600(abs, cfg); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("saved %s\n", abs)
	if *install {
		if err := serviceInstall("node", abs); err != nil {
			log.Fatal(err)
		}
		return
	}
	fmt.Println("running in this terminal; Ctrl-C stops it. To keep it running after logout and reboots: relay service install")
	runNode([]string{"--config", abs})
}

// ---- policy presets --------------------------------------------------------------

var readTools = `"nodes_list", "node_info", "fs_read", "fs_list", "fs_stat", "fs_glob", "fs_grep", "job_logs", "jobs_list"`

var policyPresets = map[string]string{
	"ask": `{
  "comment": "Written by relay init (preset: ask). First matching rule wins. Edit freely: the server reloads it within 2 seconds. See policy.example.json in the repo for more.",
  "default": "ask",
  "approval_timeout_sec": 300,
  "rules": [
    {"comment": "Looking around is always fine.", "tools": [` + readTools + `], "action": "allow"},
    {"comment": "Never touch secrets or git internals.", "tools": ["fs_write", "fs_edit", "fs_move", "fs_remove"], "paths": ["**/.git/**", "**/*.env", "**/.ssh/**"], "action": "deny", "reason": "secrets and git internals are off limits"}
  ]
}
`,
	"readonly": `{
  "comment": "Written by relay init (preset: readonly). Agents may look but not change or run anything.",
  "default": "deny",
  "rules": [
    {"tools": [` + readTools + `], "action": "allow"}
  ]
}
`,
	"open": `{
  "comment": "Written by relay init (preset: open). Everything is allowed: for local tests only.",
  "default": "allow",
  "rules": []
}
`,
}
