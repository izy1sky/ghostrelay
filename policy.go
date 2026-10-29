package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Server-side policy: an ordered rule list, first match wins. See
// policy.example.json and README.md. The node still enforces its own roots and
// limits; the policy decides what the server is willing to forward at all.

const (
	actAllow = "allow"
	actAsk   = "ask"
	actDeny  = "deny"
)

type policyFile struct {
	Comment            string      `json:"comment,omitempty"`
	Default            string      `json:"default"`
	ApprovalTimeoutSec int         `json:"approval_timeout_sec,omitempty"`
	Notify             *notifyConf `json:"notify,omitempty"`
	Agents             []agentConf `json:"agents,omitempty"`
	Rules              []ruleConf  `json:"rules"`
}

type notifyConf struct {
	URL  string `json:"url"`
	Kind string `json:"kind,omitempty"` // json (default) | text | wecom
}

type agentConf struct {
	Name        string `json:"name"`
	TokenSHA256 string `json:"token_sha256"`
	Comment     string `json:"comment,omitempty"`
}

type ruleConf struct {
	Comment  string   `json:"comment,omitempty"`
	Agents   []string `json:"agents,omitempty"`
	Nodes    []string `json:"nodes,omitempty"`
	Tools    []string `json:"tools,omitempty"`
	Paths    []string `json:"paths,omitempty"`
	Commands []string `json:"commands,omitempty"`
	Action   string   `json:"action"`
	Reason   string   `json:"reason,omitempty"`
}

type rule struct {
	conf                 ruleConf
	agents, nodes, tools []*regexp.Regexp
	pathsCS, pathsCI     []*regexp.Regexp // case-sensitive / -insensitive (Windows nodes)
	commands             []*regexp.Regexp
}

type policy struct {
	none            bool // no --policy given: everything is allowed
	defaultAction   string
	approvalTimeout time.Duration
	notify          *notifyConf
	agents          []agentConf
	rules           []rule
}

// policyReq is one tool call reduced to what rules can match on.
type policyReq struct {
	Agent, Node, Tool string
	FoldCase          bool // path is on a case-insensitive filesystem
	HasPath           bool
	Path              string // normalized: absolute, forward slashes, cleaned
	HasCommand        bool
	Command           string
	Argv              bool // Command was rendered from argv (no shell)
}

type verdict struct {
	Action string
	Rule   int // 1-based; 0 means the default
	Reason string
}

func (v verdict) String() string {
	if v.Rule == 0 {
		return v.Action + " (default)"
	}
	return fmt.Sprintf("%s (rule %d)", v.Action, v.Rule)
}

var allowAll = &policy{none: true, defaultAction: actAllow}

var hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func loadPolicy(file string) (*policy, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return parsePolicy(data)
}

func parsePolicy(data []byte) (*policy, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	// A misspelled matcher ("tool" for "tools") would silently widen a rule.
	dec.DisallowUnknownFields()
	var f policyFile
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	p := &policy{defaultAction: f.Default, notify: f.Notify, agents: f.Agents,
		approvalTimeout: time.Duration(f.ApprovalTimeoutSec) * time.Second}
	if p.defaultAction == "" {
		p.defaultAction = actDeny
	}
	if !validAction(p.defaultAction) {
		return nil, fmt.Errorf("default: invalid action %q", p.defaultAction)
	}
	if p.approvalTimeout <= 0 {
		p.approvalTimeout = 5 * time.Minute
	}
	if n := p.notify; n != nil && n.URL != "" && !slices.Contains([]string{"", "json", "text", "wecom"}, n.Kind) {
		return nil, fmt.Errorf("notify.kind %q: want json, text or wecom", n.Kind)
	}
	seen := map[string]bool{"default": true}
	for i, a := range f.Agents {
		if !validName.MatchString(a.Name) || seen[a.Name] {
			return nil, fmt.Errorf("agents[%d]: invalid or duplicate name %q (\"default\" is reserved)", i, a.Name)
		}
		seen[a.Name] = true
		if !hexSHA256.MatchString(a.TokenSHA256) {
			return nil, fmt.Errorf("agents[%d] %s: token_sha256 must be 64 lowercase hex chars (relay hash)", i, a.Name)
		}
	}
	for i, rc := range f.Rules {
		r, err := compileRule(rc)
		if err != nil {
			return nil, fmt.Errorf("rules[%d] (rule %d): %v", i, i+1, err)
		}
		p.rules = append(p.rules, r)
	}
	return p, nil
}

func validAction(a string) bool { return a == actAllow || a == actAsk || a == actDeny }

var toolNames = func() []string {
	var out []string
	for _, t := range toolDefs {
		out = append(out, t["name"].(string))
	}
	return out
}()

func compileRule(rc ruleConf) (rule, error) {
	r := rule{conf: rc}
	if !validAction(rc.Action) {
		return r, fmt.Errorf("invalid action %q (allow, ask or deny)", rc.Action)
	}
	for _, t := range rc.Tools {
		if t == "transfer" {
			return r, fmt.Errorf(`"transfer" is checked as fs_read on every source file and fs_write on every destination file; write rules for those tools instead`)
		}
		if !strings.ContainsAny(t, "*?") && !slices.Contains(toolNames, t) {
			return r, fmt.Errorf("unknown tool %q (known: %s)", t, strings.Join(toolNames, ", "))
		}
	}
	var err error
	if r.agents, err = compileGlobs(rc.Agents, false); err != nil {
		return r, err
	}
	if r.nodes, err = compileGlobs(rc.Nodes, false); err != nil {
		return r, err
	}
	if r.tools, err = compileGlobs(rc.Tools, false); err != nil {
		return r, err
	}
	norm := make([]string, len(rc.Paths))
	for i, p := range rc.Paths {
		norm[i] = strings.ReplaceAll(p, `\`, "/")
	}
	if r.pathsCS, err = compileGlobs(norm, false); err != nil {
		return r, err
	}
	if r.pathsCI, err = compileGlobs(norm, true); err != nil {
		return r, err
	}
	for _, c := range rc.Commands {
		re, err := regexp.Compile(c)
		if err != nil {
			return r, fmt.Errorf("commands %q: %v", c, err)
		}
		r.commands = append(r.commands, re)
	}
	return r, nil
}

// globToRegexp: `*` stays within one path segment, `**` crosses segments,
// `**/` may match nothing, and a trailing `/**` also matches the directory itself.
func globToRegexp(g string) string {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(g); {
		switch {
		case g[i:] == "/**":
			b.WriteString("(?:/.*)?")
			i += 3
		case strings.HasPrefix(g[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 3
		case strings.HasPrefix(g[i:], "**"):
			b.WriteString(".*")
			i += 2
		case g[i] == '*':
			b.WriteString("[^/]*")
			i++
		case g[i] == '?':
			b.WriteString("[^/]")
			i++
		default:
			b.WriteString(regexp.QuoteMeta(g[i : i+1]))
			i++
		}
	}
	b.WriteString("$")
	return b.String()
}

func compileGlobs(globs []string, fold bool) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, g := range globs {
		expr := globToRegexp(g)
		if fold {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %v", g, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	return slices.ContainsFunc(res, func(re *regexp.Regexp) bool { return re.MatchString(s) })
}

func (r *rule) matches(q policyReq) bool {
	if len(r.agents) > 0 && !anyMatch(r.agents, q.Agent) {
		return false
	}
	if len(r.nodes) > 0 && !anyMatch(r.nodes, q.Node) {
		return false
	}
	if len(r.tools) > 0 && !anyMatch(r.tools, q.Tool) {
		return false
	}
	if len(r.pathsCS) > 0 {
		paths := r.pathsCS
		if q.FoldCase {
			paths = r.pathsCI
		}
		if !q.HasPath || !anyMatch(paths, q.Path) {
			return false
		}
	}
	if len(r.commands) > 0 && (!q.HasCommand || !anyMatch(r.commands, q.Command)) {
		return false
	}
	return true
}

func (p *policy) eval(q policyReq) verdict {
	for i := range p.rules {
		if p.rules[i].matches(q) {
			return verdict{Action: p.rules[i].conf.Action, Rule: i + 1, Reason: p.rules[i].conf.Reason}
		}
	}
	return verdict{Action: p.defaultAction}
}

// agentByToken finds the policy agent whose token hashes to token_sha256.
func (p *policy) agentByToken(token string) (string, bool) {
	sum := sha256.Sum256([]byte(token))
	h := []byte(hex.EncodeToString(sum[:]))
	for _, a := range p.agents {
		if subtle.ConstantTimeCompare(h, []byte(a.TokenSHA256)) == 1 {
			return a.Name, true
		}
	}
	return "", false
}

// ---- building requests -------------------------------------------------------

var winAbs = regexp.MustCompile(`^[A-Za-z]:/`)

// normPath mirrors the node's resolution lexically: relative paths hang off the
// first root. Symlinks are not followed here; the node's jail handles escapes.
func normPath(p string, info NodeInfo) string {
	win := info.OS == "windows"
	root := "/"
	if len(info.Roots) > 0 {
		root = info.Roots[0]
	}
	if win {
		p = strings.ReplaceAll(p, `\`, "/")
		root = strings.ReplaceAll(root, `\`, "/")
	}
	abs := strings.HasPrefix(p, "/") || win && winAbs.MatchString(p)
	switch {
	case strings.TrimSpace(p) == "":
		p = root
	case !abs:
		p = root + "/" + p
	}
	// path.Clean would treat "D:" as an ordinary segment and let ".." climb
	// past it, so clean the part after the drive as a rooted path.
	if win && winAbs.MatchString(p) {
		return p[:2] + path.Clean("/"+p[3:])
	}
	return path.Clean(p)
}

// foldsCase reports whether a normalized path sits on a case-insensitive
// filesystem, using what the node probed for each root. Nodes older than
// v0.5 did not probe, so fall back to the platform default there.
func foldsCase(info NodeInfo, p string) bool {
	if len(info.RootsCaseInsensitive) != len(info.Roots) || len(info.Roots) == 0 {
		return info.OS == "windows" || info.OS == "darwin"
	}
	for i, r := range info.Roots {
		root := normPath(r, info)
		if strings.EqualFold(p, root) || len(p) > len(root) && strings.EqualFold(p[:len(root)+1], root+"/") {
			return info.RootsCaseInsensitive[i]
		}
	}
	return info.RootsCaseInsensitive[0]
}

// pathTools take a single "path" argument that policy path rules match on.
var pathTools = []string{"fs_read", "fs_write", "fs_edit", "fs_list", "fs_stat", "fs_mkdir", "fs_remove", "fs_glob", "fs_grep"}

// buildReqs reduces one tool call to what rules match on. Most calls are one
// request; fs_move is two (its source and its destination), both of which
// must pass.
func buildReqs(agent, tool string, raw json.RawMessage, nc *nodeConn) []policyReq {
	q := policyReq{Agent: agent, Tool: tool}
	if nc == nil {
		return []policyReq{q}
	}
	q.Node = nc.info.Name
	var a struct {
		Path    string   `json:"path"`
		Cwd     string   `json:"cwd"`
		Command string   `json:"command"`
		Argv    []string `json:"argv"`
		Src     string   `json:"src"`
		Dst     string   `json:"dst"`
	}
	json.Unmarshal(raw, &a)
	withPath := func(q policyReq, p string) policyReq {
		q.HasPath, q.Path = true, normPath(p, nc.info)
		q.FoldCase = foldsCase(nc.info, q.Path)
		return q
	}
	switch {
	case tool == "exec":
		q.HasCommand, q.Command = true, a.Command
		if len(a.Argv) > 0 {
			q.Command, q.Argv = argvString(a.Argv), true
		}
		return []policyReq{withPath(q, a.Cwd)}
	case tool == "fs_move":
		return []policyReq{withPath(q, a.Src), withPath(q, a.Dst)}
	case slices.Contains(pathTools, tool):
		return []policyReq{withPath(q, a.Path)}
	}
	return []policyReq{q}
}

func buildReq(agent, tool string, raw json.RawMessage, nc *nodeConn) policyReq {
	return buildReqs(agent, tool, raw, nc)[0]
}

func (q policyReq) summary() string {
	var parts []string
	if q.Node != "" {
		parts = append(parts, "node="+q.Node)
	}
	if q.HasCommand {
		parts = append(parts, fmt.Sprintf("command=%q", q.Command))
	}
	if q.HasPath {
		parts = append(parts, "path="+q.Path)
	}
	return q.Tool + " " + strings.Join(parts, " ")
}

// ---- server side ---------------------------------------------------------------

// watchPolicy reloads the file when it changes. A broken edit keeps the old
// policy in force.
func (s *server) watchPolicy() {
	var lastMod time.Time
	var lastSize int64
	if st, err := os.Stat(s.policyPath); err == nil {
		lastMod, lastSize = st.ModTime(), st.Size()
	}
	for range time.Tick(2 * time.Second) {
		st, err := os.Stat(s.policyPath)
		if err != nil || st.ModTime().Equal(lastMod) && st.Size() == lastSize {
			continue
		}
		lastMod, lastSize = st.ModTime(), st.Size()
		p, err := loadPolicy(s.policyPath)
		if err != nil {
			s.audit.write(map[string]any{"event": "policy_reload_failed", "error": err.Error()})
			continue
		}
		s.pol.Store(p)
		s.audit.write(map[string]any{"event": "policy_reloaded", "rules": len(p.rules), "default": p.defaultAction})
	}
}

// authorize applies the policy to one tool call, waiting for a human when the
// verdict is ask. It returns a short note for the audit log.
func (s *server) authorize(ctxDone <-chan struct{}, q policyReq) (string, error) {
	return s.authorizeMany(ctxDone, []policyReq{q}, q)
}

// authorizeMany checks several requests that make up one call (a transfer
// reads many files and writes many). A deny rule denies; otherwise the
// requests the policy doesn't allow outright must all be covered by grants,
// or the call asks, once, showing display to the approver.
func (s *server) authorizeMany(ctxDone <-chan struct{}, qs []policyReq, display policyReq) (string, error) {
	p := s.pol.Load()
	if p.none {
		return "no policy", nil
	}
	v, q := p.evalAll(qs)
	denied := func() error {
		msg := fmt.Sprintf("denied by policy %s: %s", v, q.summary())
		if v.Reason != "" {
			msg += " — " + v.Reason
		}
		return errors.New(msg)
	}
	switch {
	case v.Action == actAllow:
		return v.String(), nil
	case v.Action == actDeny && v.Rule != 0:
		return v.String(), denied() // explicit deny rules beat grants and approvals
	}
	var asking []policyReq
	for _, q := range qs {
		if p.eval(q).Action != actAllow {
			asking = append(asking, q)
		}
	}
	if ids := s.grants.cover(asking); ids != nil {
		return v.String() + ", grant " + strings.Join(ids, ","), nil
	}
	if v.Action == actDeny {
		return v.String(), denied()
	}
	if s.alwaysAllowed(display) {
		return v.String() + ", previously approved always", nil
	}
	return s.requestApproval(ctxDone, display, asking, v, p, nil)
}

// evalAll returns the strictest verdict over qs and the request that drew it:
// a deny rule over the default's deny, over ask, over allow.
func (p *policy) evalAll(qs []policyReq) (verdict, policyReq) {
	rank := func(v verdict) int {
		switch v.Action {
		case actAsk:
			return 1
		case actDeny:
			if v.Rule != 0 {
				return 3
			}
			return 2
		}
		return 0
	}
	worst, worstQ := verdict{Action: actAllow}, policyReq{}
	for i, q := range qs {
		v := p.eval(q)
		if i == 0 || rank(v) > rank(worst) {
			worst, worstQ = v, q
		}
		if rank(v) == 3 {
			break
		}
	}
	return worst, worstQ
}

func logPolicyMode(p *policy, file string) {
	if p.none {
		log.Printf("WARNING: no --policy: every tool call from an authenticated agent is allowed")
		return
	}
	log.Printf("policy %s: %d rules, default %s, %d named agents", file, len(p.rules), p.defaultAction, len(p.agents))
}
