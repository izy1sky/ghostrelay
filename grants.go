package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Grants let one approval cover many calls: "python on win for an hour",
// "writes under D:/work/app/** for 30 minutes", "everything on win". They
// come from an approver widening a single approval, or from an agent asking
// for a whole task up front with request_grant.
//
// A grant covers calls the policy would ask about (or that fall through to
// the default). Explicit deny rules always win: no grant reaches .git, .env or
// whatever else a rule denies. Grants belong to one agent, expire by
// themselves, and are saved next to the policy so a restart keeps them.

type grant struct {
	ID       string    `json:"id"`
	Agent    string    `json:"agent"`
	Node     string    `json:"node"`
	Tools    []string  `json:"tools,omitempty"`    // empty: any tool
	Paths    []string  `json:"paths,omitempty"`    // globs on normalized paths; empty: anywhere
	Programs []string  `json:"programs,omitempty"` // exec: program names; empty: any command
	Reason   string    `json:"reason,omitempty"`
	By       string    `json:"by,omitempty"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
	Uses     int       `json:"uses"`

	cs, ci []*regexp.Regexp // compiled Paths, case-sensitive / -insensitive
}

const maxGrant = 24 * time.Hour

func (g *grant) compile() error {
	var err error
	if g.cs, err = compileGlobs(g.Paths, false); err != nil {
		return err
	}
	g.ci, err = compileGlobs(g.Paths, true)
	return err
}

func (g *grant) covers(q policyReq) bool {
	if g.Agent != q.Agent || g.Node != q.Node {
		return false
	}
	if len(g.Tools) > 0 && !slices.Contains(g.Tools, q.Tool) {
		return false
	}
	// For exec, listed programs are the scope: a program reaches any path
	// whatever its cwd, so the folders only limit cwd when no programs are listed.
	if len(g.Paths) > 0 && !(q.Tool == "exec" && len(g.Programs) > 0) {
		res := g.cs
		if q.FoldCase {
			res = g.ci
		}
		if !q.HasPath || !anyMatch(res, q.Path) {
			return false
		}
	}
	if q.Tool == "exec" && len(g.Programs) > 0 {
		prog, ok := programOf(q)
		if !ok || !slices.Contains(g.Programs, prog) {
			return false
		}
	}
	return true
}

// describe says what a grant allows, for approvers and agents.
func (g *grant) describe() string {
	others := slices.DeleteFunc(slices.Clone(g.Tools), func(t string) bool { return t == "exec" && len(g.Programs) > 0 })
	var what string
	switch {
	case len(g.Programs) > 0 && len(g.Tools) == 0:
		what = "exec of " + strings.Join(g.Programs, ", ") + "; any other tool"
	case len(g.Programs) > 0 && len(others) > 0:
		what = "exec of " + strings.Join(g.Programs, ", ") + "; " + strings.Join(others, ", ")
	case len(g.Programs) > 0:
		what = "exec of " + strings.Join(g.Programs, ", ")
	case len(g.Tools) == 0:
		what = "everything"
	default:
		what = strings.Join(g.Tools, ", ")
	}
	if len(g.Paths) > 0 {
		if len(g.Programs) > 0 && (len(g.Tools) == 0 || len(others) > 0) {
			what += " in " + strings.Join(g.Paths, ", ") // the programs run anywhere
		} else if len(g.Programs) == 0 {
			what += " in " + strings.Join(g.Paths, ", ")
		}
	}
	return what + " on " + g.Node
}

func describeAll(gs []grant) string {
	var parts []string
	for i := range gs {
		parts = append(parts, gs[i].describe())
	}
	return strings.Join(parts, "; ")
}

// ---- programs ----------------------------------------------------------------

// shellOps are what lets one shell command line run several programs. A
// program-scoped grant only matches a shell command that has none of them, so
// "python x.py; rm -rf ~" is not "python".
const shellOps = ";&|<>`\n\r"

// programOf names the program an exec request runs: argv[0], or the first
// word of a shell command, as a lowercase base name without .exe. ok is false
// when a shell command could run more than one program.
func programOf(q policyReq) (string, bool) {
	cmd := strings.TrimSpace(q.Command)
	first := cmd
	if !q.Argv {
		if strings.ContainsAny(cmd, shellOps) || strings.Contains(cmd, "$(") {
			return "", false
		}
		if strings.HasPrefix(cmd, `"`) || strings.HasPrefix(cmd, "'") {
			end := strings.IndexByte(cmd[1:], cmd[0])
			if end < 0 {
				return "", false
			}
			first = cmd[1 : end+1]
		} else if i := strings.IndexAny(cmd, " \t"); i >= 0 {
			first = cmd[:i]
		}
	} else if strings.HasPrefix(cmd, `"`) { // argvString quoted argv[0]
		if end := strings.Index(cmd[1:], `"`); end >= 0 {
			first = cmd[1 : end+1]
		}
	} else if i := strings.IndexByte(cmd, ' '); i >= 0 {
		first = cmd[:i]
	}
	p := normProgram(first)
	return p, p != ""
}

func normProgram(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	p = strings.ToLower(strings.TrimSpace(p))
	for _, ext := range []string{".exe", ".cmd", ".bat", ".com"} {
		p = strings.TrimSuffix(p, ext)
	}
	if strings.ContainsAny(p, " \t*?") {
		return ""
	}
	return p
}

// ---- suggestions for approvers -------------------------------------------------

// writeTools are granted together: an agent writing a file usually edits it
// and makes folders next to it too.
var writeTools = []string{"fs_write", "fs_edit", "fs_mkdir"}

// similarGrants widens the requests of one call that still need approval into
// grants an approver can give with one click: the same program on the same
// node, or the same kind of change under the folder the paths share. It
// returns nil when there is no safe generalization (a shell command chaining
// several programs).
func similarGrants(asking []policyReq) []grant {
	type group struct {
		node, tool string
		progs      []string
		dirs       []string
		fold       bool
	}
	var order []string
	groups := map[string]*group{}
	for _, q := range asking {
		tool := q.Tool
		if slices.Contains(writeTools, tool) {
			tool = "fs_write"
		}
		key := q.Node + "\x00" + tool
		g := groups[key]
		if g == nil {
			g = &group{node: q.Node, tool: tool}
			groups[key] = g
			order = append(order, key)
		}
		switch {
		case q.Tool == "exec":
			prog, ok := programOf(q)
			if !ok {
				return nil
			}
			if !slices.Contains(g.progs, prog) {
				g.progs = append(g.progs, prog)
			}
		case q.HasPath:
			g.dirs = append(g.dirs, path.Dir(q.Path))
			g.fold = g.fold || q.FoldCase
		}
	}
	var out []grant
	for _, key := range order {
		g := groups[key]
		gr := grant{Node: g.node, Tools: []string{g.tool}, Programs: g.progs}
		if g.tool == "fs_write" {
			gr.Tools = slices.Clone(writeTools)
		}
		if len(g.dirs) > 0 {
			gr.Paths = []string{strings.TrimSuffix(commonDir(g.dirs, g.fold), "/") + "/**"}
		}
		out = append(out, gr)
	}
	return out
}

// commonDir is the deepest folder containing every dir (slash paths).
func commonDir(dirs []string, fold bool) string {
	common := strings.Split(dirs[0], "/")
	for _, d := range dirs[1:] {
		parts := strings.Split(d, "/")
		n := 0
		for n < len(common) && n < len(parts) && (common[n] == parts[n] || fold && strings.EqualFold(common[n], parts[n])) {
			n++
		}
		common = common[:n]
	}
	if c := strings.Join(common, "/"); c != "" {
		return c
	}
	return "/"
}

// nodeGrants is the widest choice: everything on the nodes the call touches.
func nodeGrants(asking []policyReq) []grant {
	var out []grant
	for _, q := range asking {
		if !slices.ContainsFunc(out, func(g grant) bool { return g.Node == q.Node }) {
			out = append(out, grant{Node: q.Node})
		}
	}
	return out
}

// ---- store -----------------------------------------------------------------------

type grantStore struct {
	mu   sync.Mutex
	file string // "" keeps grants in memory only
	list []*grant
}

func newGrantStore(file string) (*grantStore, error) {
	st := &grantStore{file: file}
	if file == "" {
		return st, nil
	}
	b, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	var list []*grant
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("%s: %v", file, err)
	}
	now := time.Now()
	for _, g := range list {
		if g.Expires.After(now) && g.compile() == nil {
			st.list = append(st.list, g)
		}
	}
	return st, nil
}

// saveLocked writes the active grants; the caller holds mu.
func (st *grantStore) saveLocked() error {
	if st.file == "" {
		return nil
	}
	b, _ := json.MarshalIndent(st.list, "", "  ")
	return writePrivate(st.file, append(b, '\n'))
}

func (st *grantStore) pruneLocked() bool {
	now := time.Now()
	n := len(st.list)
	st.list = slices.DeleteFunc(st.list, func(g *grant) bool { return !g.Expires.After(now) })
	return len(st.list) != n
}

func (st *grantStore) add(g grant) (*grant, error) {
	if err := g.compile(); err != nil {
		return nil, err
	}
	idb := make([]byte, 4)
	rand.Read(idb)
	g.ID = "g" + hex.EncodeToString(idb)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.pruneLocked()
	st.list = append(st.list, &g)
	return &g, st.saveLocked()
}

func (st *grantStore) revoke(id string) (*grant, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for i, g := range st.list {
		if g.ID == id {
			st.list = slices.Delete(st.list, i, i+1)
			return g, st.saveLocked()
		}
	}
	return nil, fmt.Errorf("no active grant %q", id)
}

func (st *grantStore) active() []grant {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.pruneLocked() {
		st.saveLocked()
	}
	out := make([]grant, len(st.list))
	for i, g := range st.list {
		out[i] = *g
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Expires.Before(out[j].Expires) })
	return out
}

// cover finds a grant for every request in asking. It returns the IDs used,
// or nil if any request is left uncovered.
func (st *grantStore) cover(asking []policyReq) []string {
	if len(asking) == 0 {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	used := map[*grant]bool{}
	for _, q := range asking {
		var hit *grant
		for _, g := range st.list {
			if g.Expires.After(now) && g.covers(q) {
				hit = g
				break
			}
		}
		if hit == nil {
			return nil
		}
		used[hit] = true
	}
	var ids []string
	for g := range used {
		g.Uses++
		ids = append(ids, g.ID)
	}
	sort.Strings(ids)
	st.saveLocked() // keep use counts across restarts
	return ids
}

// grantFrom turns templates into stored grants for agent, lasting d.
func (s *server) grantFrom(templates []grant, agent, by, reason string, d time.Duration) ([]*grant, error) {
	d = min(max(d, time.Minute), maxGrant)
	var out []*grant
	for _, t := range templates {
		t.Agent, t.By, t.Reason = agent, by, reason
		t.Created, t.Expires = time.Now(), time.Now().Add(d)
		g, err := s.grants.add(t)
		if err != nil {
			return out, err
		}
		s.audit.write(map[string]any{"event": "grant_created", "id": g.ID, "agent": agent, "scope": g.describe(),
			"by": by, "reason": reason, "expires": g.Expires})
		out = append(out, g)
	}
	return out, nil
}

// ---- request_grant ---------------------------------------------------------------

type grantRequestArgs struct {
	Node     string   `json:"node"`
	Tools    []string `json:"tools"`
	Paths    []string `json:"paths"`
	Programs []string `json:"programs"`
	Minutes  int      `json:"minutes"`
	Reason   string   `json:"reason"`
}

const maxRequestMinutes = 8 * 60

// runRequestGrant asks the approver for a grant the agent describes, so one
// approval covers a whole task.
func (s *server) runRequestGrant(done <-chan struct{}, agent string, raw json.RawMessage) (string, string, error) {
	var a grantRequestArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return "", "", fmt.Errorf("invalid arguments: %v", err)
	}
	if strings.TrimSpace(a.Reason) == "" {
		return "", "", errors.New("reason is required: say what the task is, so the approver can judge it")
	}
	p := s.pol.Load()
	if p.none {
		return "no policy is loaded, so every call is already allowed; no grant needed", "no policy", nil
	}
	nc, err := s.node(a.Node)
	if err != nil {
		return "", "", err
	}
	if v := p.eval(policyReq{Agent: agent, Node: nc.info.Name, Tool: "request_grant"}); v.Action == actDeny && v.Rule != 0 {
		return "", v.String(), fmt.Errorf("denied by policy %s: request_grant — %s", v, firstNonEmpty(v.Reason, "this agent may not ask for grants"))
	}
	g := grant{Node: nc.info.Name}
	for _, t := range a.Tools {
		switch {
		case t == "transfer":
			g.Tools = append(g.Tools, "fs_read", "fs_write")
		case t == "request_grant" || !slices.Contains(toolNames, t):
			return "", "", fmt.Errorf("unknown tool %q", t)
		default:
			g.Tools = append(g.Tools, t)
		}
	}
	if len(a.Programs) > 0 && len(g.Tools) > 0 && !slices.Contains(g.Tools, "exec") {
		g.Tools = append(g.Tools, "exec")
	}
	for _, prog := range a.Programs {
		n := normProgram(prog)
		if n == "" {
			return "", "", fmt.Errorf("program %q: give a program name like python or git", prog)
		}
		g.Programs = append(g.Programs, n)
	}
	for _, pth := range a.Paths {
		pth = strings.ReplaceAll(pth, `\`, "/")
		if !strings.ContainsAny(pth, "*?") {
			pth = strings.TrimSuffix(normPath(pth, nc.info), "/") + "/**" // a folder and everything in it
		} else if !strings.HasPrefix(pth, "/") && !winAbs.MatchString(pth) {
			root := normPath("", nc.info)
			pth = strings.TrimSuffix(root, "/") + "/" + pth
		}
		g.Paths = append(g.Paths, pth)
	}
	if err := g.compile(); err != nil {
		return "", "", err
	}
	if a.Minutes <= 0 {
		a.Minutes = 60
	}
	a.Minutes = min(a.Minutes, maxRequestMinutes)
	g.Agent = agent

	display := policyReq{Agent: agent, Node: nc.info.Name, Tool: "request_grant", HasPath: true,
		Path: g.describe() + fmt.Sprintf(" · %d min", a.Minutes)}
	pc := &pendingCall{Kind: "grant", GrantScope: g.describe(), Minutes: a.Minutes, Reason: a.Reason, request: &g}
	note, err := s.requestApproval(done, display, nil, verdict{Action: actAsk}, p, pc)
	if err != nil {
		return "", note, err
	}
	if pc.granted == nil {
		return "", note, errors.New("approved, but no grant was recorded")
	}
	gr := pc.granted
	return fmt.Sprintf("granted %s: %s, until %s (%s).\nCalls inside this scope run without asking; anything outside it, or denied by a policy rule, still asks or is refused.",
		gr.ID, gr.describe(), gr.Expires.Local().Format("15:04"), time.Until(gr.Expires).Round(time.Minute)), note, nil
}

// ---- admin API and CLI -----------------------------------------------------------

func (s *server) handleGrants(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	type view struct {
		grant
		Scope string `json:"scope"`
	}
	var out []view
	for _, g := range s.grants.active() {
		out = append(out, view{g, g.describe()})
	}
	if out == nil {
		out = []view{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (s *server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.adminAuth(w, r) {
		return
	}
	var req struct {
		ID string `json:"id"`
		By string `json:"by"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	g, err := s.grants.revoke(req.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.audit.write(map[string]any{"event": "grant_revoked", "id": g.ID, "scope": g.describe(), "by": req.By + "@" + r.RemoteAddr})
	w.Write([]byte("ok\n"))
}

// relay grants [revoke <id>]
func runGrants(args []string) {
	if len(args) >= 1 && args[0] == "revoke" {
		if len(args) != 2 {
			fatalf("usage: relay grants revoke <id>")
		}
		if _, err := adminRequest("POST", serverFromEnv("")+"/admin/api/grants/revoke", map[string]string{"id": args[1], "by": "cli"}); err != nil {
			fatalf("%v", err)
		}
		fmt.Printf("revoked %s\n", args[1])
		return
	}
	out, err := adminRequest("GET", serverFromEnv("")+"/admin/api/grants", nil)
	if err != nil {
		fatalf("%v", err)
	}
	var list []struct {
		grant
		Scope string `json:"scope"`
	}
	json.Unmarshal(out, &list)
	if len(list) == 0 {
		fmt.Println("no active grants")
		return
	}
	for _, g := range list {
		fmt.Printf("%s  agent=%s  %s\n    until %s (%s left), used %d×, by %s", g.ID, g.Agent, g.Scope,
			g.Expires.Local().Format("15:04"), time.Until(g.Expires).Round(time.Minute), g.Uses, g.By)
		if g.Reason != "" {
			fmt.Printf(": %s", g.Reason)
		}
		fmt.Println()
	}
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
