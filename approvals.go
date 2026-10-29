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
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Calls whose verdict is "ask" wait here until an admin decides, through
// the /admin page, the relay approve/deny CLI, or the approval times out.

type pendingCall struct {
	ID       string    `json:"id"`
	Agent    string    `json:"agent"`
	Node     string    `json:"node,omitempty"`
	Tool     string    `json:"tool"`
	Command  string    `json:"command,omitempty"`
	Path     string    `json:"path,omitempty"`
	Verdict  string    `json:"verdict"`
	Reason   string    `json:"reason,omitempty"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
	decision chan decision
	req      policyReq
}

type decision struct {
	Allow  bool
	Always bool
	By     string
	Reason string
}

func alwaysKey(q policyReq) string {
	return strings.Join([]string{q.Agent, q.Node, q.Tool, q.Path, q.Command}, "\x00")
}

func (s *server) alwaysAllowed(q policyReq) bool {
	s.amu.Lock()
	defer s.amu.Unlock()
	return s.always[alwaysKey(q)]
}

func (s *server) requestApproval(ctxDone <-chan struct{}, q policyReq, v verdict, p *policy) (string, error) {
	if s.adminToken == "" {
		return v.String(), fmt.Errorf("policy %s requires approval for %s, but the server has no RELAY_ADMIN_TOKEN, so nobody can approve", v, q.summary())
	}
	idb := make([]byte, 4)
	rand.Read(idb)
	pc := &pendingCall{
		ID: hex.EncodeToString(idb), Agent: q.Agent, Node: q.Node, Tool: q.Tool,
		Verdict: v.String(), Reason: v.Reason, Created: time.Now(), Expires: time.Now().Add(p.approvalTimeout),
		decision: make(chan decision, 1), req: q,
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

	s.audit.write(map[string]any{"event": "approval_requested", "id": pc.ID, "agent": q.Agent, "call": q.summary(), "verdict": v.String()})
	log.Printf(">>> APPROVAL NEEDED %s  agent=%s  %s   (relay approve %s | relay deny %s)", pc.ID, q.Agent, q.summary(), pc.ID, pc.ID)
	if p.notify != nil && p.notify.URL != "" {
		go s.sendNotify(p.notify, pc)
	}

	timer := time.NewTimer(p.approvalTimeout)
	defer timer.Stop()
	select {
	case d := <-pc.decision:
		s.audit.write(map[string]any{"event": "approval_decided", "id": pc.ID, "allow": d.Allow, "always": d.Always, "by": d.By, "reason": d.Reason})
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
	text := fmt.Sprintf("relay approval %s\nagent: %s\n%s\nexpires: %s\n\nrelay approve %s\nrelay deny %s",
		pc.ID, pc.Agent, pc.req.summary(), pc.Expires.Format(time.Kitchen), pc.ID, pc.ID)
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
		Decision string `json:"decision"` // allow | always | deny
		Reason   string `json:"reason"`
		By       string `json:"by"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	d := decision{Allow: req.Decision != "deny", Always: req.Decision == "always", Reason: req.Reason, By: "admin@" + r.RemoteAddr}
	if req.By != "" {
		d.By = req.By + "@" + r.RemoteAddr
	}
	if req.Decision != "allow" && req.Decision != "always" && req.Decision != "deny" {
		http.Error(w, "decision must be allow, always or deny", http.StatusBadRequest)
		return
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
	pc.decision <- d
	w.Write([]byte("ok\n"))
}

const adminPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>relay approvals</title>
<style>
:root{--bg:#fafaf9;--fg:#1c1917;--muted:#78716c;--card:#fff;--line:#e7e5e4;--ok:#15803d;--no:#b91c1c}
@media (prefers-color-scheme:dark){:root{--bg:#1c1917;--fg:#f5f5f4;--muted:#a8a29e;--card:#292524;--line:#44403c;--ok:#4ade80;--no:#f87171}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,sans-serif}
main{max-width:720px;margin:0 auto;padding:16px}
h1{font-size:18px;margin:8px 0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin-bottom:12px}
.meta{color:var(--muted);font-size:13px}
pre{white-space:pre-wrap;word-break:break-all;margin:8px 0;font:13px ui-monospace,monospace}
button{font:inherit;padding:6px 12px;border-radius:8px;border:1px solid var(--line);background:transparent;color:var(--fg);cursor:pointer;margin-right:6px}
.allow{border-color:var(--ok);color:var(--ok)} .deny{border-color:var(--no);color:var(--no)}
input{font:inherit;padding:6px 8px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg);width:100%;box-sizing:border-box}
#empty{color:var(--muted)}
</style></head><body><main>
<h1>relay approvals</h1>
<div id="login" class="card" hidden><label>Admin token<br><input id="tok" type="password" autocomplete="off"></label>
<p><button id="save">Save for this tab</button></p></div>
<div id="list"></div><p id="empty" hidden>Nothing waiting for approval.</p>
<script>
const $=s=>document.querySelector(s);
let tok=''; try{tok=sessionStorage.getItem('relayAdmin')||''}catch(e){}
$('#save').onclick=()=>{tok=$('#tok').value.trim(); try{sessionStorage.setItem('relayAdmin',tok)}catch(e){} load()};
function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
async function decide(id,decision){
  const reason=decision==='deny'?(prompt('Reason (optional, shown to the agent)')||''):'';
  await fetch('api/decide',{method:'POST',headers:{'Authorization':'Bearer '+tok,'Content-Type':'application/json'},body:JSON.stringify({id,decision,reason,by:'web'})});
  load();
}
async function load(){
  if(!tok){$('#login').hidden=false;return}
  const r=await fetch('api/pending',{headers:{'Authorization':'Bearer '+tok}});
  if(r.status===401){$('#login').hidden=false;return}
  $('#login').hidden=true;
  const items=await r.json();
  $('#empty').hidden=items.length>0;
  $('#list').innerHTML=items.map(p=>'<div class="card"><div class="meta">'+esc(p.id)+' · agent <b>'+esc(p.agent)+'</b> · node <b>'+esc(p.node||'-')+'</b> · '+esc(p.verdict)+
    ' · expires '+new Date(p.expires).toLocaleTimeString()+'</div><pre>'+esc(p.tool)+(p.command?'\n$ '+esc(p.command):'')+(p.path?'\n'+esc(p.path):'')+'</pre>'+
    (p.reason?'<div class="meta">'+esc(p.reason)+'</div>':'')+
    '<p><button class="allow" data-d="allow" data-id="'+esc(p.id)+'">Allow</button><button data-d="always" data-id="'+esc(p.id)+'">Allow always</button><button class="deny" data-d="deny" data-id="'+esc(p.id)+'">Deny</button></p></div>').join('');
  document.querySelectorAll('#list button').forEach(b=>b.onclick=()=>decide(b.dataset.id,b.dataset.d));
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
	return "http://127.0.0.1:8787"
}

func adminRequest(method, url string, body any) ([]byte, error) {
	tok := strings.TrimSpace(os.Getenv("RELAY_ADMIN_TOKEN"))
	if tok == "" {
		return nil, errors.New("set RELAY_ADMIN_TOKEN")
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
		if p.Command != "" {
			fmt.Printf("    $ %s\n", p.Command)
		}
		if p.Path != "" {
			fmt.Printf("    %s\n", p.Path)
		}
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
	reason := fs.String("reason", "", "reason shown to the agent (deny)")
	pos := parseInterleaved(fs, args)
	if len(pos) != 1 {
		log.Fatalf("usage: relay %s <id> [flags]", name)
	}
	d := "allow"
	switch {
	case deny:
		d = "deny"
	case *always:
		d = "always"
	}
	if _, err := adminRequest("POST", serverFromEnv(*srv)+"/admin/api/decide",
		map[string]string{"id": pos[0], "decision": d, "reason": *reason, "by": "cli"}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s: %s\n", pos[0], d)
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
