package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
)

// Calls whose verdict is "ask" wait here until an admin decides, through
// the /admin page, the relay approve/deny CLI, or the approval times out.

type pendingCall struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"` // "call", or "grant" for request_grant
	Agent   string    `json:"agent"`
	Node    string    `json:"node,omitempty"`
	Tool    string    `json:"tool"`
	Command string    `json:"command,omitempty"`
	Path    string    `json:"path,omitempty"`
	Verdict string    `json:"verdict"`
	Reason  string    `json:"reason,omitempty"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`

	// The wider approvals on offer: grants for calls like this one, or for
	// everything on its node(s). Similar is empty when there is no safe
	// generalization. For a request_grant, GrantScope and Minutes are what
	// the agent asked for.
	Similar    string `json:"similar,omitempty"`
	NodeScope  string `json:"node_scope,omitempty"`
	GrantScope string `json:"grant_scope,omitempty"`
	Minutes    int    `json:"minutes,omitempty"`

	decision           chan decision
	req                policyReq
	similar, nodeScope []grant
	request            *grant // request_grant: the grant asked for
	granted            *grant // request_grant: the grant given
}

type decision struct {
	Allow  bool
	Always bool
	By     string
	Reason string
	Note   string // grants created, for the audit log
}

func alwaysKey(q policyReq) string {
	return strings.Join([]string{q.Agent, q.Node, q.Tool, q.Path, q.Command}, "\x00")
}

func (s *server) alwaysAllowed(q policyReq) bool {
	s.amu.Lock()
	defer s.amu.Unlock()
	return s.always[alwaysKey(q)]
}

// requestApproval waits for a human to decide on q. asking are the requests
// of the call that still need approval, from which the wider grant choices
// are drawn. pc, when given, is a prepared request_grant card.
func (s *server) requestApproval(ctxDone <-chan struct{}, q policyReq, asking []policyReq, v verdict, p *policy, pc *pendingCall) (string, error) {
	if s.adminToken == "" {
		return v.String(), fmt.Errorf("policy %s requires approval for %s, but the server has no RELAY_ADMIN_TOKEN, so nobody can approve", v, q.summary())
	}
	if pc == nil {
		pc = &pendingCall{Kind: "call", Reason: v.Reason}
		if pc.similar = similarGrants(asking); pc.similar != nil {
			pc.Similar = describeAll(pc.similar)
		}
		if pc.nodeScope = nodeGrants(asking); pc.nodeScope != nil {
			pc.NodeScope = describeAll(pc.nodeScope)
		}
	}
	idb := make([]byte, 4)
	rand.Read(idb)
	pc.ID, pc.Agent, pc.Node, pc.Tool = hex.EncodeToString(idb), q.Agent, q.Node, q.Tool
	pc.Verdict, pc.Created, pc.Expires = v.String(), time.Now(), time.Now().Add(p.approvalTimeout)
	pc.decision, pc.req = make(chan decision, 1), q
	if pc.Kind == "grant" {
		pc.Verdict = "grant request"
	}
	if q.HasCommand {
		pc.Command = q.Command
	}
	if q.HasPath {
		pc.Path = q.Path
	}
	s.amu.Lock()
	s.pending[pc.ID] = pc
	s.amu.Unlock()
	defer func() {
		s.amu.Lock()
		delete(s.pending, pc.ID)
		s.amu.Unlock()
	}()

	s.audit.write(map[string]any{"event": "approval_requested", "id": pc.ID, "agent": q.Agent, "call": q.summary(), "verdict": pc.Verdict, "reason": pc.Reason})
	log.Printf(">>> APPROVAL NEEDED %s  agent=%s  %s   (relay approve %s | relay deny %s; or the /admin page)", pc.ID, q.Agent, q.summary(), pc.ID, pc.ID)
	if p.notify != nil && p.notify.URL != "" {
		go s.sendNotify(p.notify, pc)
	}

	timer := time.NewTimer(p.approvalTimeout)
	defer timer.Stop()
	select {
	case d := <-pc.decision:
		s.audit.write(map[string]any{"event": "approval_decided", "id": pc.ID, "allow": d.Allow, "always": d.Always, "by": d.By, "reason": d.Reason, "grants": d.Note})
		if !d.Allow {
			msg := fmt.Sprintf("denied by a human approver: %s", q.summary())
			if d.Reason != "" {
				msg += " — " + d.Reason
			}
			return v.String() + ", denied by " + d.By, errors.New(msg)
		}
		if d.Always {
			s.amu.Lock()
			s.always[alwaysKey(q)] = true
			s.amu.Unlock()
		}
		if d.Note != "" {
			return v.String() + ", approved by " + d.By + ", " + d.Note, nil
		}
		return v.String() + ", approved by " + d.By, nil
	case <-timer.C:
		s.audit.write(map[string]any{"event": "approval_timeout", "id": pc.ID})
		return v.String() + ", timed out", fmt.Errorf("approval for %s timed out after %s; nobody approved it", q.summary(), p.approvalTimeout)
	case <-ctxDone:
		s.audit.write(map[string]any{"event": "approval_abandoned", "id": pc.ID})
		return v.String() + ", caller gave up", errors.New("caller cancelled while waiting for approval")
	}
}

func (s *server) sendNotify(n *notifyConf, pc *pendingCall) {
	what := pc.req.summary()
	if pc.Kind == "grant" {
		what = fmt.Sprintf("grant request: %s for %d min\nreason: %s", pc.GrantScope, pc.Minutes, pc.Reason)
	}
	text := fmt.Sprintf("relay approval %s\nagent: %s\n%s\nexpires: %s\n\nrelay approve %s\nrelay deny %s",
		pc.ID, pc.Agent, what, pc.Expires.Format(time.Kitchen), pc.ID, pc.ID)
	var body []byte
	ctype := "application/json"
	switch n.Kind {
	case "text":
		body, ctype = []byte(text), "text/plain; charset=utf-8"
	case "wecom":
		body, _ = json.Marshal(map[string]any{"msgtype": "text", "text": map[string]string{"content": text}})
	default:
		body, _ = json.Marshal(map[string]any{"pending": pc, "text": text})
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(n.URL, ctype, bytes.NewReader(body))
	if err != nil {
		log.Printf("notify failed: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("notify failed: HTTP %d", resp.StatusCode)
	}
}

// ---- admin HTTP --------------------------------------------------------------

func (s *server) adminAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.adminToken == "" {
		http.Error(w, "admin API disabled (no RELAY_ADMIN_TOKEN)", http.StatusNotFound)
		return false
	}
	if !checkBearer(r, s.adminToken) {
		s.audit.write(map[string]any{"event": "admin_auth_failed", "remote": r.RemoteAddr})
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *server) handlePending(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	s.amu.Lock()
	list := make([]*pendingCall, 0, len(s.pending))
	for _, pc := range s.pending {
		list = append(list, pc)
	}
	s.amu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].Created.Before(list[j].Created) })
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func (s *server) handleDecide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.adminAuth(w, r) {
		return
	}
	var req struct {
		ID       string `json:"id"`
		Decision string `json:"decision"` // allow | always | similar | node | deny
		Minutes  int    `json:"minutes"`  // similar, node, and grant requests
		Reason   string `json:"reason"`
		By       string `json:"by"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !slices.Contains([]string{"allow", "always", "similar", "node", "deny"}, req.Decision) {
		http.Error(w, "decision must be allow, always, similar, node or deny", http.StatusBadRequest)
		return
	}
	d := decision{Allow: req.Decision != "deny", Always: req.Decision == "always", Reason: req.Reason, By: "admin@" + r.RemoteAddr}
	if req.By != "" {
		d.By = req.By + "@" + r.RemoteAddr
	}
	s.amu.Lock()
	pc := s.pending[req.ID]
	if pc != nil {
		delete(s.pending, req.ID)
	}
	s.amu.Unlock()
	if pc == nil {
		http.Error(w, "no pending call with that id (already decided or expired?)", http.StatusNotFound)
		return
	}
	var templates []grant
	minutes := req.Minutes
	switch {
	case pc.Kind == "grant" && d.Allow:
		templates = []grant{*pc.request}
		if minutes <= 0 {
			minutes = pc.Minutes
		}
	case req.Decision == "similar":
		if pc.similar == nil {
			s.putBack(pc)
			http.Error(w, "no similar grant for this call (a shell command running several programs); use allow or node", http.StatusBadRequest)
			return
		}
		templates = pc.similar
	case req.Decision == "node":
		templates = pc.nodeScope
	}
	if len(templates) > 0 {
		if minutes <= 0 {
			minutes = 60
		}
		gs, err := s.grantFrom(templates, pc.Agent, d.By, firstNonEmpty(pc.Reason, req.Reason), time.Duration(minutes)*time.Minute)
		if err != nil {
			s.putBack(pc)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var ids []string
		for _, g := range gs {
			ids = append(ids, g.ID)
		}
		d.Note = "grant " + strings.Join(ids, ",")
		if pc.Kind == "grant" {
			pc.granted = gs[0]
		}
	}
	pc.decision <- d
	w.Write([]byte("ok\n"))
}

// putBack returns a pending call whose decision failed, so it can be decided again.
func (s *server) putBack(pc *pendingCall) {
	s.amu.Lock()
	s.pending[pc.ID] = pc
	s.amu.Unlock()
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

const adminPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>relay approvals</title>
<style>
:root{--bg:#fafaf9;--fg:#1c1917;--muted:#78716c;--card:#fff;--line:#e7e5e4;--ok:#15803d;--no:#b91c1c;--accent:#1d4ed8}
@media (prefers-color-scheme:dark){:root{--bg:#1c1917;--fg:#f5f5f4;--muted:#a8a29e;--card:#292524;--line:#44403c;--ok:#4ade80;--no:#f87171;--accent:#93c5fd}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,sans-serif}
main{max-width:760px;margin:0 auto;padding:16px}
h1{font-size:18px;margin:8px 0 4px} h2{font-size:15px;margin:22px 0 8px;color:var(--muted);font-weight:600}
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;color:var(--muted);font-size:13px;margin-bottom:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin-bottom:12px}
.grant{border-left:4px solid var(--accent)}
.meta{color:var(--muted);font-size:13px}
.why{margin:6px 0;font-weight:500}
pre{white-space:pre-wrap;word-break:break-all;margin:8px 0;font:13px ui-monospace,monospace}
.btns{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
button{font:inherit;font-size:14px;padding:6px 11px;border-radius:8px;border:1px solid var(--line);background:transparent;color:var(--fg);cursor:pointer;text-align:left}
button small{display:block;color:var(--muted);font-size:12px;max-width:34ch;overflow-wrap:anywhere}
.allow{border-color:var(--ok);color:var(--ok)} .deny{border-color:var(--no);color:var(--no)} .wide{border-color:var(--accent);color:var(--accent)}
select,input{font:inherit;padding:5px 8px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg)}
input{width:100%;box-sizing:border-box}
.empty{color:var(--muted)}
</style></head><body><main>
<h1>relay approvals</h1>
<div class="bar">Wider approvals last <select id="dur"><option value="15">15 minutes</option><option value="60" selected>1 hour</option><option value="240">4 hours</option><option value="480">8 hours</option></select>
<span>· deny rules in the policy always apply</span></div>
<div id="login" class="card" hidden><label>Admin token<br><input id="tok" type="password" autocomplete="off"></label>
<p><button id="save">Save for this tab</button></p></div>
<div id="bulk"></div>
<div id="list"></div><p id="empty" class="empty" hidden>Nothing waiting for approval.</p>
<h2>Active grants</h2><div id="grants"></div>
<script>
const $=s=>document.querySelector(s);
let tok=''; try{tok=sessionStorage.getItem('relayAdmin')||''}catch(e){}
try{const d=localStorage.getItem('relayDur'); if(d) $('#dur').value=d}catch(e){}
$('#dur').onchange=()=>{try{localStorage.setItem('relayDur',$('#dur').value)}catch(e){}};
$('#save').onclick=()=>{tok=$('#tok').value.trim(); try{sessionStorage.setItem('relayAdmin',tok)}catch(e){} load()};
function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
const H=()=>({'Authorization':'Bearer '+tok,'Content-Type':'application/json'});
function mins(){return +$('#dur').value}
function human(m){return m>=60?(m/60)+' h':m+' min'}
async function decide(id,decision,minutes){
  const reason=decision==='deny'?(prompt('Reason (optional, shown to the agent)')||''):'';
  const r=await fetch('api/decide',{method:'POST',headers:H(),body:JSON.stringify({id,decision,minutes:minutes||0,reason,by:'web'})});
  if(!r.ok) alert(await r.text());
  load();
}
async function revoke(id){await fetch('api/grants/revoke',{method:'POST',headers:H(),body:JSON.stringify({id,by:'web'})}); load()}
function btn(cls,label,sub,on){return '<button class="'+cls+'" data-on="'+esc(on)+'">'+label+(sub?'<small>'+esc(sub)+'</small>':'')+'</button>'}
function card(p){
  const head='<div class="meta">'+esc(p.id)+' · agent <b>'+esc(p.agent)+'</b> · node <b>'+esc(p.node||'-')+'</b> · '+esc(p.verdict)+' · expires '+new Date(p.expires).toLocaleTimeString()+'</div>';
  if(p.kind==='grant') return '<div class="card grant">'+head+'<div class="why">'+esc(p.reason)+'</div><pre>'+esc(p.grant_scope)+'</pre>'+
    '<div class="btns">'+btn('allow','Grant for '+human(p.minutes),'as asked','grant:'+p.id+':'+p.minutes)+btn('wide','Grant for '+human(mins()),'the chosen duration','grant:'+p.id+':'+mins())+btn('deny','Deny','','deny:'+p.id)+'</div></div>';
  return '<div class="card">'+head+'<pre>'+esc(p.tool)+(p.command?'\n$ '+esc(p.command):'')+(p.path?'\n'+esc(p.path):'')+'</pre>'+
    (p.reason?'<div class="meta">'+esc(p.reason)+'</div>':'')+
    '<div class="btns">'+btn('allow','Allow once','','allow:'+p.id)+
    (p.similar?btn('wide','Allow similar · '+human(mins()),p.similar,'similar:'+p.id):'')+
    btn('wide','Everything on node · '+human(mins()),p.node_scope,'node:'+p.id)+
    btn('deny','Deny','','deny:'+p.id)+'</div></div>';
}
async function load(){
  if(!tok){$('#login').hidden=false;return}
  const r=await fetch('api/pending',{headers:H()});
  if(r.status===401){$('#login').hidden=false;return}
  $('#login').hidden=true;
  const items=await r.json();
  $('#empty').hidden=items.length>0;
  $('#list').innerHTML=items.map(card).join('');
  const byAgent={}; items.filter(p=>p.kind!=='grant').forEach(p=>(byAgent[p.agent]=byAgent[p.agent]||[]).push(p.id));
  $('#bulk').innerHTML=Object.entries(byAgent).filter(([a,ids])=>ids.length>1).map(([a,ids])=>'<p><button class="allow" data-on="all:'+esc(ids.join(','))+'">Allow all '+ids.length+' waiting from '+esc(a)+' (once each)</button></p>').join('');
  const gr=await (await fetch('api/grants',{headers:H()})).json();
  $('#grants').innerHTML=gr.length?gr.map(g=>'<div class="card"><div class="meta">'+esc(g.id)+' · agent <b>'+esc(g.agent)+'</b> · until '+new Date(g.expires).toLocaleTimeString()+' · used '+g.uses+'× · by '+esc(g.by)+'</div><pre>'+esc(g.scope)+'</pre>'+(g.reason?'<div class="meta">'+esc(g.reason)+'</div>':'')+'<div class="btns">'+btn('deny','Revoke','','revoke:'+g.id)+'</div></div>').join(''):'<p class="empty">None.</p>';
  document.querySelectorAll('button[data-on]').forEach(b=>b.onclick=()=>{
    const [what,id,m]=b.dataset.on.split(':');
    if(what==='revoke') return revoke(id);
    if(what==='all') return Promise.all(id.split(',').map(i=>fetch('api/decide',{method:'POST',headers:H(),body:JSON.stringify({id:i,decision:'allow',by:'web'})}))).then(load);
    if(what==='grant') return decide(id,'allow',+m);
    decide(id,what,(what==='similar'||what==='node')?mins():0);
  });
}
load(); setInterval(load,2000);
</script></main></body></html>`

func (s *server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/" {
		http.Redirect(w, r, "/admin/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
	w.Write([]byte(adminPage))
}

// ---- CLI: approvals / approve / deny / hash / policy check -----------------------

func serverFromEnv(v string) string {
	if v != "" {
		return strings.TrimRight(v, "/")
	}
	if e := os.Getenv("RELAY_SERVER"); e != "" {
		return strings.TrimRight(e, "/")
	}
	// On the server's own machine, relay init's settings know the port.
	if cfg, err := readJSONMap(defaultServerConfig()); err == nil {
		if listen, _ := cfg["listen"].(string); listen != "" {
			if _, port, err := net.SplitHostPort(listen); err == nil {
				return "http://127.0.0.1:" + port
			}
		}
	}
	return "http://127.0.0.1:8787"
}

func adminRequest(method, url string, body any) ([]byte, error) {
	tok := strings.TrimSpace(os.Getenv("RELAY_ADMIN_TOKEN"))
	if tok == "" {
		if cfg, err := readJSONMap(defaultServerConfig()); err == nil {
			tok, _ = cfg["admin-token"].(string)
		}
	}
	if tok == "" {
		return nil, errors.New("set RELAY_ADMIN_TOKEN (or run this on the server, after relay init)")
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// parseInterleaved lets flags come before or after the positional id.
func parseInterleaved(fs *flag.FlagSet, args []string) []string {
	fs.Parse(args)
	var pos []string
	for fs.NArg() > 0 {
		pos = append(pos, fs.Arg(0))
		fs.Parse(fs.Args()[1:])
	}
	return pos
}

func runApprovals(args []string) {
	fs := flag.NewFlagSet("approvals", flag.ExitOnError)
	srv := fs.String("server", "", "server URL (default $RELAY_SERVER or http://127.0.0.1:8787)")
	fs.Parse(args)
	out, err := adminRequest("GET", serverFromEnv(*srv)+"/admin/api/pending", nil)
	if err != nil {
		log.Fatal(err)
	}
	var list []pendingCall
	json.Unmarshal(out, &list)
	if len(list) == 0 {
		fmt.Println("nothing pending")
		return
	}
	for _, p := range list {
		fmt.Printf("%s  agent=%s node=%s tool=%s  %s  (expires %s)\n", p.ID, p.Agent, p.Node, p.Tool, p.Verdict, p.Expires.Local().Format(time.TimeOnly))
		if p.Kind == "grant" {
			fmt.Printf("    wants: %s for %d min\n    why:   %s\n    relay approve %s  [--for 2h]\n", p.GrantScope, p.Minutes, p.Reason, p.ID)
			continue
		}
		if p.Command != "" {
			fmt.Printf("    $ %s\n", p.Command)
		}
		if p.Path != "" {
			fmt.Printf("    %s\n", p.Path)
		}
		if p.Similar != "" {
			fmt.Printf("    relay approve %s --similar --for 1h   → %s\n", p.ID, p.Similar)
		}
		fmt.Printf("    relay approve %s --node --for 30m     → %s\n", p.ID, p.NodeScope)
	}
}

func runDecide(args []string, deny bool) {
	name := "approve"
	if deny {
		name = "deny"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	srv := fs.String("server", "", "server URL (default $RELAY_SERVER or http://127.0.0.1:8787)")
	always := fs.Bool("always", false, "also allow identical calls (same agent, node, tool, path, command) until the server restarts")
	similar := fs.Bool("similar", false, "also grant calls like this one (same program, or same kind of change in the same folder) for --for")
	node := fs.Bool("node", false, "also grant everything on this node to this agent for --for (deny rules still apply)")
	dur := fs.Duration("for", time.Hour, "how long --similar / --node grants last (e.g. 30m, 2h); for a grant request, overrides what the agent asked")
	reason := fs.String("reason", "", "reason shown to the agent (deny)")
	pos := parseInterleaved(fs, args)
	if len(pos) != 1 {
		log.Fatalf("usage: relay %s <id> [flags]", name)
	}
	d := "allow"
	switch {
	case deny:
		d = "deny"
	case *node:
		d = "node"
	case *similar:
		d = "similar"
	case *always:
		d = "always"
	}
	minutes := 0
	if *similar || *node || isFlagSet(fs, "for") {
		minutes = int(dur.Minutes())
	}
	if _, err := adminRequest("POST", serverFromEnv(*srv)+"/admin/api/decide",
		map[string]any{"id": pos[0], "decision": d, "minutes": minutes, "reason": *reason, "by": "cli"}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s: %s\n", pos[0], d)
}

func isFlagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

// runHash prints the sha256 of a token read from stdin, for policy "agents".
func runHash() {
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	tok := strings.TrimSpace(line)
	if tok == "" {
		log.Fatal("usage: echo $TOKEN | relay hash")
	}
	sum := sha256.Sum256([]byte(tok))
	fmt.Println(hex.EncodeToString(sum[:]))
}

func runPolicyCheck(args []string) {
	fs := flag.NewFlagSet("policy check", flag.ExitOnError)
	file := fs.String("policy", "policy.json", "policy file")
	agent := fs.String("agent", "default", "agent name")
	node := fs.String("node", "", "node name")
	osName := fs.String("os", "linux", "node OS (windows makes paths case-insensitive)")
	root := fs.String("root", "/", "node's first root (base for relative paths)")
	tool := fs.String("tool", "", "tool name")
	pth := fs.String("path", "", "path (fs tools) or cwd (exec)")
	cmd := fs.String("command", "", "command (exec)")
	fs.Parse(args)
	p, err := loadPolicy(*file)
	if err != nil {
		log.Fatalf("policy invalid: %v", err)
	}
	fmt.Printf("policy ok: %d rules, default %s, %d agents\n", len(p.rules), p.defaultAction, len(p.agents))
	if *tool == "" {
		return
	}
	nc := &nodeConn{info: NodeInfo{Name: *node, OS: *osName, Roots: []string{*root}}}
	raw, _ := json.Marshal(map[string]string{"path": *pth, "cwd": *pth, "command": *cmd})
	if *node == "" {
		nc = nil
	}
	q := buildReq(*agent, *tool, raw, nc)
	v := p.eval(q)
	fmt.Printf("%s\n  -> %s", q.summary(), v)
	if v.Reason != "" {
		fmt.Printf(": %s", v.Reason)
	}
	fmt.Println()
}
