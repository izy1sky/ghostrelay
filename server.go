package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type server struct {
	nodeToken  string
	agentToken string // optional when the policy names its own agents
	adminToken string // optional; without it "ask" verdicts cannot be approved
	audit      *auditLog

	policyPath string
	pol        atomic.Pointer[policy]

	mu    sync.RWMutex
	nodes map[string]*nodeConn

	amu     sync.Mutex
	pending map[string]*pendingCall
	always  map[string]bool

	grants *grantStore

	// for the console: what to put in join codes and agent setup, and the log it shows
	pubURL, listen, auditPath string
	tls                       bool
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", ":8787", "address to listen on")
	nodeTok := fs.String("node-token", "", "token nodes must present (prefer env RELAY_NODE_TOKEN)")
	agentTok := fs.String("agent-token", "", "token MCP clients must present (prefer env RELAY_AGENT_TOKEN)")
	certFile := fs.String("tls-cert", "", "TLS certificate file (enables HTTPS/WSS)")
	keyFile := fs.String("tls-key", "", "TLS key file")
	auditPath := fs.String("audit", "relay-audit.jsonl", "audit log file (JSON lines)")
	adminTok := fs.String("admin-token", "", "token for approving calls (prefer env RELAY_ADMIN_TOKEN)")
	policyPath := fs.String("policy", "", "policy file (JSON); reloaded when it changes. Without it every call is allowed")
	pubURL := fs.String("url", "", "address nodes and agents use to reach this server (shown by relay invite)")
	logFile := fs.String("log-file", "", "write the log to this file instead of stderr (used by relay service)")
	settings := loadFlags(fs, args, defaultServerConfig())
	setupLog(*logFile, settings)

	s := &server{
		nodeToken:  tokenFrom(*nodeTok, "RELAY_NODE_TOKEN"),
		agentToken: tokenFrom(*agentTok, "RELAY_AGENT_TOKEN"),
		adminToken: tokenFrom(*adminTok, "RELAY_ADMIN_TOKEN"),
		policyPath: *policyPath,
		nodes:      map[string]*nodeConn{},
		pending:    map[string]*pendingCall{},
		always:     map[string]bool{},
		pubURL:     strings.TrimRight(*pubURL, "/"),
		listen:     *listen,
		auditPath:  *auditPath,
		tls:        *certFile != "" || *keyFile != "",
	}
	pol := allowAll
	if s.policyPath != "" {
		p, err := loadPolicy(s.policyPath)
		if err != nil {
			log.Fatalf("policy %s: %v", s.policyPath, err)
		}
		pol = p
	}
	s.pol.Store(pol)
	if s.nodeToken == "" {
		log.Fatal("RELAY_NODE_TOKEN is required (generate with: relay token)")
	}
	if s.agentToken == "" && len(pol.agents) == 0 {
		log.Fatal("RELAY_AGENT_TOKEN is required unless the policy defines agents")
	}
	toks := []string{s.nodeToken, s.agentToken, s.adminToken}
	for i := range toks {
		for j := i + 1; j < len(toks); j++ {
			if toks[i] != "" && toks[i] == toks[j] {
				log.Fatal("node, agent and admin tokens must all differ")
			}
		}
	}
	grantsFile := ""
	if s.policyPath != "" {
		grantsFile = filepath.Join(filepath.Dir(s.policyPath), "grants.json")
	}
	var err error
	if s.grants, err = newGrantStore(grantsFile); err != nil {
		log.Fatalf("grants: %v", err)
	}
	if n := len(s.grants.active()); n > 0 {
		log.Printf("%d active grants from %s (relay grants)", n, grantsFile)
	}
	a, err := openAudit(*auditPath)
	if err != nil {
		log.Fatalf("audit log: %v", err)
	}
	s.audit = a
	logPolicyMode(pol, s.policyPath)
	if s.policyPath != "" {
		go s.watchPolicy()
	}
	if s.adminToken == "" {
		log.Printf("no RELAY_ADMIN_TOKEN: calls the policy marks \"ask\" will be refused")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/", s.handleAdminPage)
	mux.HandleFunc("/admin", s.handleAdminPage)
	mux.HandleFunc("/admin/api/pending", s.handlePending)
	mux.HandleFunc("/admin/api/decide", s.handleDecide)
	mux.HandleFunc("/admin/api/grants", s.handleGrants)
	mux.HandleFunc("/admin/api/grants/revoke", s.handleRevoke)
	mux.HandleFunc("/admin/api/nodes", s.handleNodes)
	mux.HandleFunc("/admin/api/setup", s.handleSetup)
	mux.HandleFunc("/admin/api/activity", s.handleActivity)
	mux.HandleFunc("/node", s.handleNode)
	mux.HandleFunc("/mcp", s.handleMCP)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	if *pubURL != "" {
		log.Printf("reachable as %s; print join codes with: relay invite", *pubURL)
		if w := portMismatch(*listen, *pubURL); w != "" {
			log.Print(w)
		}
	}
	if *certFile != "" || *keyFile != "" {
		log.Printf("relay %s serving https on %s (nodes: /node, agents: /mcp)", version, *listen)
		log.Fatal(srv.ListenAndServeTLS(*certFile, *keyFile))
	}
	log.Printf("relay %s serving PLAIN http on %s (nodes: /node, agents: /mcp)", version, *listen)
	log.Printf("WARNING: no TLS; tokens travel in clear. Use --tls-cert/--tls-key, a TLS proxy, or a private network")
	log.Fatal(srv.ListenAndServe())
}

func checkBearer(r *http.Request, want string) bool {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// ---- node link -------------------------------------------------------------

type nodeConn struct {
	info        NodeInfo
	conn        *websocket.Conn
	remote      string
	connectedAt time.Time

	wmu     sync.Mutex
	seq     atomic.Uint64
	pmu     sync.Mutex
	pending map[string]chan *Msg

	done      chan struct{}
	closeOnce sync.Once
}

func (s *server) handleNode(w http.ResponseWriter, r *http.Request) {
	if !checkBearer(r, s.nodeToken) {
		s.audit.write(map[string]any{"event": "node_auth_failed", "remote": r.RemoteAddr})
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(maxFrame)

	hctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var hello Msg
	err = wsjson.Read(hctx, c, &hello)
	cancel()
	if err != nil || hello.Type != msgHello || hello.Info == nil || !validName.MatchString(hello.Info.Name) {
		c.Close(websocket.StatusPolicyViolation, "bad hello")
		return
	}

	nc := &nodeConn{
		info:        *hello.Info,
		conn:        c,
		remote:      r.RemoteAddr,
		connectedAt: time.Now(),
		pending:     map[string]chan *Msg{},
		done:        make(chan struct{}),
	}
	if old := s.register(nc); old != nil {
		old.close("replaced by new connection")
	}
	if err := nc.write(&Msg{Type: msgWelcome}); err != nil {
		nc.close("welcome failed")
	}
	s.audit.write(map[string]any{"event": "node_connected", "node": nc.info.Name, "remote": nc.remote,
		"os": nc.info.OS, "roots": nc.info.Roots, "allow_exec": nc.info.AllowExec})

	go nc.pingLoop()
	nc.readLoop()

	s.unregister(nc)
	s.audit.write(map[string]any{"event": "node_disconnected", "node": nc.info.Name, "remote": nc.remote})
}

func (s *server) register(nc *nodeConn) (old *nodeConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old = s.nodes[nc.info.Name]
	s.nodes[nc.info.Name] = nc
	return old
}

func (s *server) unregister(nc *nodeConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nodes[nc.info.Name] == nc {
		delete(s.nodes, nc.info.Name)
	}
}

func (s *server) node(name string) (*nodeConn, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if nc := s.nodes[name]; nc != nil {
		return nc, nil
	}
	names := make([]string, 0, len(s.nodes))
	for n := range s.nodes {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("node %q is not connected (no nodes are connected)", name)
	}
	return nil, fmt.Errorf("node %q is not connected; connected nodes: %s", name, strings.Join(names, ", "))
}

func (s *server) nodeList() []*nodeConn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*nodeConn, 0, len(s.nodes))
	for _, nc := range s.nodes {
		out = append(out, nc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].info.Name < out[j].info.Name })
	return out
}

func (nc *nodeConn) close(reason string) {
	nc.closeOnce.Do(func() {
		close(nc.done)
		nc.conn.Close(websocket.StatusGoingAway, reason)
	})
}

// write uses its own timeout: cancelling a coder/websocket write closes the
// connection, so a caller's request context must never reach it.
func (nc *nodeConn) write(m *Msg) error {
	nc.wmu.Lock()
	defer nc.wmu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return wsjson.Write(ctx, nc.conn, m)
}

func (nc *nodeConn) readLoop() {
	for {
		var m Msg
		if err := wsjson.Read(context.Background(), nc.conn, &m); err != nil {
			nc.close("read error")
			return
		}
		if m.Type != msgRes {
			continue
		}
		nc.pmu.Lock()
		ch := nc.pending[m.ID]
		nc.pmu.Unlock()
		if ch != nil {
			ch <- &m
		}
	}
}

func (nc *nodeConn) pingLoop() {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-nc.done:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := nc.conn.Ping(ctx)
			cancel()
			if err != nil {
				nc.close("ping timeout")
				return
			}
		}
	}
}

// call sends one operation to the node and waits for its reply. If ctx ends
// first, the node is told to cancel the operation.
func (nc *nodeConn) call(ctx context.Context, op string, args any, out any) error {
	raw, err := json.Marshal(args)
	if err != nil {
		return err
	}
	id := strconv.FormatUint(nc.seq.Add(1), 10)
	ch := make(chan *Msg, 1)
	nc.pmu.Lock()
	nc.pending[id] = ch
	nc.pmu.Unlock()
	defer func() {
		nc.pmu.Lock()
		delete(nc.pending, id)
		nc.pmu.Unlock()
	}()

	if err := nc.write(&Msg{Type: msgReq, ID: id, Op: op, Args: raw}); err != nil {
		return fmt.Errorf("send to node %q: %w", nc.info.Name, err)
	}
	select {
	case m := <-ch:
		if m.Error != "" {
			return errors.New(m.Error)
		}
		return json.Unmarshal(m.Result, out)
	case <-nc.done:
		return fmt.Errorf("node %q disconnected during %s", nc.info.Name, op)
	case <-ctx.Done():
		nc.write(&Msg{Type: msgCancel, ID: id})
		return fmt.Errorf("%s on node %q: %w", op, nc.info.Name, ctx.Err())
	}
}

// ---- audit -------------------------------------------------------------------

type auditLog struct {
	mu sync.Mutex
	f  *os.File
}

func openAudit(path string) (*auditLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &auditLog{f: f}, nil
}

func (a *auditLog) write(rec map[string]any) {
	rec["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.f.Write(append(b, '\n'))
	log.Printf("audit %s", b)
}
