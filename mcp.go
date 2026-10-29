package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Minimal MCP streamable-HTTP server: one JSON-RPC message per POST, answered
// with application/json. No sessions, no server-initiated stream.

var supportedProtocols = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type textContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content []textContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

func (s *server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agent, ok := s.identifyAgent(r)
	if !ok {
		s.audit.write(map[string]any{"event": "agent_auth_failed", "remote": r.RemoteAddr})
		w.Header().Set("WWW-Authenticate", `Bearer realm="relay"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxFrame))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	var req rpcReq
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPC(w, &rpcResp{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcErr{-32700, "parse error (batches are not supported)"}})
		return
	}
	if len(req.ID) == 0 || string(req.ID) == "null" || req.Method == "" {
		// Notification, or a response to a request we never send.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	result, rerr := s.dispatchRPC(r.Context(), agent, r.RemoteAddr, &req)
	writeRPC(w, &rpcResp{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rerr})
}

func writeRPC(w http.ResponseWriter, resp *rpcResp) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// identifyAgent maps the bearer token to an agent name: "default" for
// RELAY_AGENT_TOKEN, or a named agent from the policy.
func (s *server) identifyAgent(r *http.Request) (string, bool) {
	if s.agentToken != "" && checkBearer(r, s.agentToken) {
		return "default", true
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return "", false
	}
	return s.pol.Load().agentByToken(tok)
}

func (s *server) dispatchRPC(ctx context.Context, agent, remote string, req *rpcReq) (any, *rpcErr) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &p)
		pv := supportedProtocols[0]
		if slices.Contains(supportedProtocols, p.ProtocolVersion) {
			pv = p.ProtocolVersion
		}
		return map[string]any{
			"protocolVersion": pv,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "relay", "version": version},
			"instructions": "Tools run on remote nodes, which may be macOS, Linux or Windows. Call nodes_list, then node_info " +
				"for a node's OS, shell_kind, path separator, roots and whether each root is case-insensitive. " +
				"The fs_* tools and transfer behave the same on every OS and accept forward slashes everywhere; " +
				"prefer them over shell commands for file work. exec with argv runs a program directly (same on every OS); " +
				"exec with command uses the node's shell (PowerShell on Windows, bash or sh elsewhere). " +
				"For long commands use background=true, then poll job_logs with offset and wait_sec. " +
				"Some calls may wait for a human to approve them.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": toolDefs}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcErr{-32602, "invalid params"}
		}
		if !slices.ContainsFunc(toolDefs, func(t map[string]any) bool { return t["name"] == p.Name }) {
			return nil, &rpcErr{-32602, "unknown tool: " + p.Name}
		}
		if len(p.Arguments) == 0 {
			p.Arguments = json.RawMessage("{}")
		}
		return s.callTool(ctx, agent, remote, p.Name, p.Arguments), nil
	}
	return nil, &rpcErr{-32601, "method not found: " + req.Method}
}

func (s *server) callTool(ctx context.Context, agent, remote, name string, args json.RawMessage) toolResult {
	start := time.Now()
	text, policyNote, err := s.runTool(ctx, agent, name, args)
	rec := map[string]any{"event": "tool_call", "agent": agent, "remote": remote, "tool": name, "policy": policyNote,
		"args": auditArgs(args), "ok": err == nil, "ms": time.Since(start).Milliseconds()}
	if err != nil {
		rec["error"] = err.Error()
	}
	s.audit.write(rec)
	if err != nil {
		return toolResult{Content: []textContent{{"text", err.Error()}}, IsError: true}
	}
	return toolResult{Content: []textContent{{"text", text}}}
}

// auditArgs keeps the log readable: long strings (file contents) are shortened.
func auditArgs(raw json.RawMessage) map[string]any {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	for k, v := range m {
		if s, ok := v.(string); ok && len(s) > 300 {
			m[k] = fmt.Sprintf("%s…(%d bytes)", s[:300], len(s))
		}
	}
	return m
}

// runTool authorizes a call against the policy, then runs it. The middle
// return value is the policy decision, for the audit log.
func (s *server) runTool(ctx context.Context, agent, name string, raw json.RawMessage) (string, string, error) {
	if name == "nodes_list" {
		note, err := s.authorize(ctx.Done(), buildReq(agent, name, raw, nil))
		if err != nil {
			return "", note, err
		}
		nodes := s.nodeList()
		if len(nodes) == 0 {
			return "no nodes connected", note, nil
		}
		var b strings.Builder
		for _, nc := range nodes {
			fmt.Fprintf(&b, "%s\t%s/%s\thost=%s\texec=%v\troots=%s\tconnected=%s\n",
				nc.info.Name, nc.info.OS, nc.info.Arch, nc.info.Hostname, nc.info.AllowExec,
				strings.Join(nc.info.Roots, ";"), nc.connectedAt.UTC().Format(time.RFC3339))
		}
		return b.String(), note, nil
	}

	if name == "transfer" {
		return s.runTransfer(ctx, agent, raw)
	}

	var base struct {
		Node string `json:"node"`
	}
	if err := json.Unmarshal(raw, &base); err != nil {
		return "", "", fmt.Errorf("invalid arguments: %v", err)
	}
	if base.Node == "" {
		return "", "", fmt.Errorf("argument \"node\" is required (see nodes_list)")
	}
	nc, err := s.node(base.Node)
	if err != nil {
		return "", "", err
	}
	reqs := buildReqs(agent, name, raw, nc)
	display := reqs[0]
	if len(reqs) == 2 {
		display.Path = reqs[0].Path + " → " + reqs[1].Path
	}
	note, err := s.authorizeMany(ctx.Done(), reqs, display)
	if err != nil {
		return "", note, err
	}
	text, err := s.forward(ctx, agent, nc, name, raw)
	return text, note, err
}

// forward sends an authorized call to its node and formats the reply.
func (s *server) forward(ctx context.Context, agent string, nc *nodeConn, name string, raw json.RawMessage) (string, error) {
	switch name {
	case "node_info":
		b, _ := json.MarshalIndent(nc.info, "", "  ")
		return string(b), nil

	case "exec":
		var args ExecArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
		args.Owner = agent
		if args.Background {
			var ji JobInfo
			if err := s.quickCall(ctx, nc, "exec", args, &ji); err != nil {
				return "", err
			}
			return fmt.Sprintf("started job %s on node %s (pid %d)\nRead output with job_logs(node=%q, job_id=%q); pass next_offset back as offset, and wait_sec to wait for new output.\n",
				ji.ID, nc.info.Name, ji.PID, nc.info.Name, ji.ID), nil
		}
		limit := args.TimeoutSec
		if limit <= 0 {
			limit = 120
		}
		ctx, cancel := context.WithTimeout(ctx, time.Duration(min(limit, nc.info.MaxTimeout)+15)*time.Second)
		defer cancel()
		var res ExecResult
		if err := nc.call(ctx, "exec", args, &res); err != nil {
			return "", err
		}
		return formatExec(&res), nil

	case "fs_read":
		var args ReadArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
		var res ReadResult
		if err := s.quickCall(ctx, nc, "fs_read", args, &res); err != nil {
			return "", err
		}
		return formatRead(&res), nil

	case "fs_write":
		var args WriteArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
		var res WriteResult
		if err := s.quickCall(ctx, nc, "fs_write", args, &res); err != nil {
			return "", err
		}
		return fmt.Sprintf("wrote %d bytes to %s", res.Bytes, res.Path), nil

	case "fs_edit":
		var args EditArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
		var res EditResult
		if err := s.quickCall(ctx, nc, "fs_edit", args, &res); err != nil {
			return "", err
		}
		return fmt.Sprintf("replaced %d occurrence(s) in %s", res.Replacements, res.Path), nil

	case "fs_list":
		var args ListArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
		var res ListResult
		if err := s.quickCall(ctx, nc, "fs_list", args, &res); err != nil {
			return "", err
		}
		return formatList(&res), nil

	case "fs_stat":
		var args StatArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
		var res StatResult
		if err := s.quickCall(ctx, nc, "fs_stat", args, &res); err != nil {
			return "", err
		}
		return formatStat(&res), nil

	case "fs_mkdir":
		var args MkdirArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
		var res StatResult
		if err := s.quickCall(ctx, nc, "fs_mkdir", args, &res); err != nil {
			return "", err
		}
		return "directory ready: " + res.Path, nil

	case "fs_move":
		var args MoveArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
		var res StatResult
		if err := s.quickCall(ctx, nc, "fs_move", args, &res); err != nil {
			return "", err
		}
		return "moved to " + res.Path, nil

	case "fs_remove":
		var args RemoveArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
		var res map[string]any
		if err := s.quickCall(ctx, nc, "fs_remove", args, &res); err != nil {
			return "", err
		}
		kind := "file"
		switch {
		case res["symlink"] == true:
			kind = "symlink (its target was not touched)"
		case res["dir"] == true:
			kind = "directory"
		}
		return fmt.Sprintf("removed %s %v", kind, res["removed"]), nil

	case "fs_glob":
		var args GlobArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
		var res GlobResult
		if err := s.quickCall(ctx, nc, "fs_glob", args, &res); err != nil {
			return "", err
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s  (%d matches for %s)\n", res.Root, len(res.Matches), args.Pattern)
		for _, m := range res.Matches {
			b.WriteString(m + "\n")
		}
		if res.Truncated {
			b.WriteString("[truncated; narrow the pattern or raise max]\n")
		}
		return b.String(), nil

	case "fs_grep":
		var args GrepArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
		var res GrepResult
		if err := s.quickCall(ctx, nc, "fs_grep", args, &res); err != nil {
			return "", err
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s  (%d matches", res.Root, len(res.Matches))
		if res.Skipped > 0 {
			fmt.Fprintf(&b, ", %d binary or large files skipped", res.Skipped)
		}
		b.WriteString(")\n")
		for _, m := range res.Matches {
			fmt.Fprintf(&b, "%s:%d: %s\n", m.File, m.Line, m.Text)
		}
		if res.Truncated {
			b.WriteString("[truncated; narrow the search or raise max]\n")
		}
		return b.String(), nil

	case "job_logs":
		var args JobLogsArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
		ctx, cancel := context.WithTimeout(ctx, time.Duration(min(max(args.WaitSec, 0), maxJobWait)+30)*time.Second)
		defer cancel()
		var res JobLogsResult
		if err := nc.call(ctx, "job_logs", args, &res); err != nil {
			return "", err
		}
		return formatJobLogs(&res), nil

	case "job_kill":
		var args JobArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
		var ji JobInfo
		if err := s.quickCall(ctx, nc, "job_kill", args, &ji); err != nil {
			return "", err
		}
		return jobLine(&ji), nil

	case "jobs_list":
		var res JobsListResult
		if err := s.quickCall(ctx, nc, "jobs_list", struct{}{}, &res); err != nil {
			return "", err
		}
		if len(res.Jobs) == 0 {
			return "no jobs on node " + nc.info.Name, nil
		}
		var b strings.Builder
		for i := range res.Jobs {
			b.WriteString(jobLine(&res.Jobs[i]))
		}
		return b.String(), nil
	}
	return "", fmt.Errorf("unknown tool %q", name)
}

func (s *server) quickCall(ctx context.Context, nc *nodeConn, op string, args, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return nc.call(ctx, op, args, out)
}

func formatExec(r *ExecResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "exit_code: %d  (%d ms)\n", r.ExitCode, r.DurationMs)
	if r.TimedOut {
		b.WriteString("[timed out; process tree killed]\n")
	}
	if r.Stdout != "" {
		b.WriteString("--- stdout ---\n" + r.Stdout)
		if !strings.HasSuffix(r.Stdout, "\n") {
			b.WriteByte('\n')
		}
		if r.StdoutTruncated {
			b.WriteString("[stdout truncated]\n")
		}
	}
	if r.Stderr != "" {
		b.WriteString("--- stderr ---\n" + r.Stderr)
		if !strings.HasSuffix(r.Stderr, "\n") {
			b.WriteByte('\n')
		}
		if r.StderrTruncated {
			b.WriteString("[stderr truncated]\n")
		}
	}
	return b.String()
}

func formatRead(r *ReadResult) string {
	var b strings.Builder
	lines := strings.Split(r.Content, "\n")
	if r.Content == "" {
		lines = nil
	}
	end := r.StartLine + len(lines) - 1
	fmt.Fprintf(&b, "%s  (lines %d-%d of %d", r.Path, r.StartLine, max(end, r.StartLine-1), r.TotalLines)
	if r.CRLF {
		b.WriteString(", CRLF line endings")
	}
	b.WriteString(")\n")
	for i, l := range lines {
		fmt.Fprintf(&b, "%6d\t%s\n", r.StartLine+i, l)
	}
	if r.Truncated {
		b.WriteString("[output truncated; read again with a larger offset]\n")
	}
	return b.String()
}

func formatStat(r *StatResult) string {
	if !r.Exists {
		return r.Path + ": does not exist"
	}
	var b strings.Builder
	kind := "file"
	if r.Dir {
		kind = "directory"
	}
	fmt.Fprintf(&b, "%s: %s", r.Path, kind)
	if r.Symlink {
		b.WriteString(" (reached through a symlink)")
	}
	if !r.Dir {
		fmt.Fprintf(&b, ", %d bytes", r.Size)
	}
	fmt.Fprintf(&b, ", mode %04o, modified %s", r.Mode, r.ModTime)
	if r.SHA256 != "" {
		fmt.Fprintf(&b, "\nsha256 %s", r.SHA256)
	}
	return b.String() + "\n"
}

func jobLine(j *JobInfo) string {
	status := j.State
	if j.ExitCode != nil && j.State == jobExited {
		status = fmt.Sprintf("exited %d", *j.ExitCode)
	}
	owner := ""
	if j.Owner != "" {
		owner = "  owner=" + j.Owner
	}
	return fmt.Sprintf("%s  %-10s %6ds  %d bytes out  pid=%d%s  $ %s\n",
		j.ID, status, j.DurationMs/1000, j.OutputBytes, j.PID, owner, j.Command)
}

func formatJobLogs(r *JobLogsResult) string {
	var b strings.Builder
	b.WriteString(jobLine(&r.Job))
	fmt.Fprintf(&b, "--- output bytes %d-%d of %d ---\n", r.Offset, r.NextOffset, r.Job.OutputBytes)
	b.WriteString(r.Data)
	if r.Data != "" && !strings.HasSuffix(r.Data, "\n") {
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "--- next_offset: %d", r.NextOffset)
	switch {
	case r.More:
		b.WriteString(" (more output available now)")
	case r.Job.State == jobRunning:
		b.WriteString(" (job still running)")
	default:
		b.WriteString(" (job finished; this is the end)")
	}
	b.WriteString(" ---\n")
	return b.String()
}

func formatList(r *ListResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  (%d entries)\n", r.Path, len(r.Entries))
	for _, e := range r.Entries {
		if e.Dir {
			fmt.Fprintf(&b, "d %12s  %s  %s/\n", "-", e.ModTime, e.Name)
		} else {
			fmt.Fprintf(&b, "f %12d  %s  %s\n", e.Size, e.ModTime, e.Name)
		}
	}
	if r.Truncated {
		b.WriteString("[listing truncated]\n")
	}
	return b.String()
}

// ---- tool definitions ----------------------------------------------------------

func prop(typ, desc string) map[string]any { return map[string]any{"type": typ, "description": desc} }

var nodeProp = prop("string", "Name of the node to run on (see nodes_list).")

func schema(required []string, props map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}

var toolDefs = []map[string]any{
	{
		"name":        "nodes_list",
		"description": "List connected nodes with their OS, hostname, whether exec is enabled, and allowed roots.",
		"inputSchema": schema([]string{}, map[string]any{}),
		"annotations": map[string]any{"readOnlyHint": true},
	},
	{
		"name":        "node_info",
		"description": "Details of one node: OS, shell, allowed roots, limits, and which probed tools (git, python, ffmpeg...) are installed.",
		"inputSchema": schema([]string{"node"}, map[string]any{"node": nodeProp}),
		"annotations": map[string]any{"readOnlyHint": true},
	},
	{
		"name": "exec",
		"description": "Run a program on a node and return exit code, stdout and stderr. Give exactly one of argv or command. " +
			"argv runs the program directly with exactly these arguments: no shell, no quoting rules, the same on macOS, Linux and Windows, " +
			"and the exit code is the program's own. command is a command line for the node's shell: check node_info.shell_kind " +
			"(powershell on Windows, bash or sh elsewhere) and use that shell's syntax. No TTY and empty stdin, so interactive prompts fail. " +
			"Output per stream is capped.",
		"inputSchema": schema([]string{"node"}, map[string]any{
			"node":        nodeProp,
			"argv":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": `Program and arguments, e.g. ["git", "status", "--short"]. Found on the node's PATH.`},
			"command":     prop("string", "Command line in the node's shell syntax."),
			"cwd":         prop("string", "Working directory; must be inside the node's roots. Defaults to the first root."),
			"timeout_sec": prop("integer", "Kill the command after this many seconds (default 120 in the foreground; for background jobs the node's job limit)."),
			"background":  prop("boolean", "Start as a background job and return its job_id at once. Use for anything that may run longer than a minute or two; read output with job_logs."),
		}),
		"annotations": map[string]any{"destructiveHint": true, "openWorldHint": true},
	},
	{
		"name": "job_logs",
		"description": "Read a background job's status and output (stdout and stderr interleaved). Pass the returned next_offset as offset " +
			"on the next call to get only new output. wait_sec (max 60) waits for new output or for the job to end instead of returning at once.",
		"inputSchema": schema([]string{"node", "job_id"}, map[string]any{
			"node":      nodeProp,
			"job_id":    prop("string", "Job id returned by exec with background=true."),
			"offset":    prop("integer", "Byte offset to read from (default 0)."),
			"max_bytes": prop("integer", "Max bytes to return (default 64 KiB, capped by the node)."),
			"tail":      prop("boolean", "Return the last max_bytes of output instead of reading from offset."),
			"wait_sec":  prop("integer", "Wait up to this many seconds for new output or job exit."),
		}),
		"annotations": map[string]any{"readOnlyHint": true},
	},
	{
		"name":        "job_kill",
		"description": "Kill a background job and everything it started.",
		"inputSchema": schema([]string{"node", "job_id"}, map[string]any{"node": nodeProp, "job_id": prop("string", "Job id.")}),
		"annotations": map[string]any{"destructiveHint": true},
	},
	{
		"name":        "jobs_list",
		"description": "List background jobs on a node: running ones and recently finished ones.",
		"inputSchema": schema([]string{"node"}, map[string]any{"node": nodeProp}),
		"annotations": map[string]any{"readOnlyHint": true},
	},
	{
		"name":        "fs_read",
		"description": "Read a text file on a node. Returns lines prefixed with line numbers (number + tab; the prefix is not part of the file).",
		"inputSchema": schema([]string{"node", "path"}, map[string]any{
			"node":   nodeProp,
			"path":   prop("string", "File path, absolute or relative to the node's first root."),
			"offset": prop("integer", "First line to return (1-based)."),
			"limit":  prop("integer", "Max lines to return (default 2000)."),
		}),
		"annotations": map[string]any{"readOnlyHint": true},
	},
	{
		"name":        "fs_write",
		"description": "Create or overwrite a text file on a node. Parent directories are created.",
		"inputSchema": schema([]string{"node", "path", "content"}, map[string]any{
			"node":    nodeProp,
			"path":    prop("string", "File path, absolute or relative to the node's first root."),
			"content": prop("string", "Full file content."),
		}),
		"annotations": map[string]any{"destructiveHint": true},
	},
	{
		"name": "fs_edit",
		"description": "Replace an exact string in a file on a node. old_string must match exactly once unless replace_all is set. " +
			"CRLF files are handled when old_string uses \\n.",
		"inputSchema": schema([]string{"node", "path", "old_string", "new_string"}, map[string]any{
			"node":        nodeProp,
			"path":        prop("string", "File path."),
			"old_string":  prop("string", "Exact text to replace."),
			"new_string":  prop("string", "Replacement text."),
			"replace_all": prop("boolean", "Replace every occurrence."),
		}),
		"annotations": map[string]any{"destructiveHint": true},
	},
	{
		"name": "transfer",
		"description": "Copy a file or a whole directory from one node to another (or within one node), streamed through the server. " +
			"Binary files are fine. Each file is checked by sha256 on the destination and only appears there once complete. " +
			"Like cp -r: a file copied onto an existing directory goes inside it; a directory is copied to dst_path. Symlinks are skipped. " +
			"Policy treats it as fs_read of every source file plus fs_write of every destination file.",
		"inputSchema": schema([]string{"src_node", "src_path", "dst_node", "dst_path"}, map[string]any{
			"src_node":  prop("string", "Node to copy from."),
			"src_path":  prop("string", "File or directory on the source node."),
			"dst_node":  prop("string", "Node to copy to (may be the same node)."),
			"dst_path":  prop("string", "Destination path on dst_node."),
			"overwrite": prop("boolean", "Replace existing files (for a directory: merge into an existing one). Default false."),
		}),
		"annotations": map[string]any{"destructiveHint": true},
	},
	{
		"name":        "fs_stat",
		"description": "Does a path exist; is it a file or directory; size, mode, modification time. sha256=true also hashes a file (to compare copies across nodes).",
		"inputSchema": schema([]string{"node", "path"}, map[string]any{
			"node":   nodeProp,
			"path":   prop("string", "Path on the node."),
			"sha256": prop("boolean", "Also return the file's sha256."),
		}),
		"annotations": map[string]any{"readOnlyHint": true},
	},
	{
		"name":        "fs_mkdir",
		"description": "Create a directory and any missing parents (no error if it exists).",
		"inputSchema": schema([]string{"node", "path"}, map[string]any{"node": nodeProp, "path": prop("string", "Directory to create.")}),
	},
	{
		"name": "fs_move",
		"description": "Rename or move a file or directory within one node (use transfer between nodes). A symlink is moved as a link. " +
			"Fails across volumes; then use transfer and fs_remove.",
		"inputSchema": schema([]string{"node", "src", "dst"}, map[string]any{
			"node":      nodeProp,
			"src":       prop("string", "Existing path."),
			"dst":       prop("string", "Full new path (not just a target directory)."),
			"overwrite": prop("boolean", "Replace an existing file at dst."),
		}),
		"annotations": map[string]any{"destructiveHint": true},
	},
	{
		"name":        "fs_remove",
		"description": "Delete a file, a symlink (never its target) or a directory. Non-empty directories need recursive=true. Node roots cannot be removed.",
		"inputSchema": schema([]string{"node", "path"}, map[string]any{
			"node":      nodeProp,
			"path":      prop("string", "Path to delete."),
			"recursive": prop("boolean", "Delete a directory and everything in it."),
		}),
		"annotations": map[string]any{"destructiveHint": true},
	},
	{
		"name": "fs_glob",
		"description": "Find files by pattern under a directory, e.g. **/*.go or src/*/test_*.py. * stays within one directory, ** crosses directories. " +
			"Matching follows the filesystem's case sensitivity. Symlinks are not followed.",
		"inputSchema": schema([]string{"node", "pattern"}, map[string]any{
			"node":    nodeProp,
			"path":    prop("string", "Directory to search (default: the node's first root)."),
			"pattern": prop("string", "Glob, relative to path, with forward slashes."),
			"max":     prop("integer", "Max results (default 1000)."),
		}),
		"annotations": map[string]any{"readOnlyHint": true},
	},
	{
		"name":        "fs_grep",
		"description": "Search file contents with a regular expression (RE2 syntax) under a directory or in one file. Skips binary files and files over 10 MiB.",
		"inputSchema": schema([]string{"node", "pattern"}, map[string]any{
			"node":        nodeProp,
			"path":        prop("string", "Directory or file (default: the node's first root)."),
			"pattern":     prop("string", "Regular expression."),
			"glob":        prop("string", "Only search files matching this glob, e.g. **/*.py."),
			"ignore_case": prop("boolean", "Case-insensitive match."),
			"max":         prop("integer", "Max matching lines (default 200)."),
		}),
		"annotations": map[string]any{"readOnlyHint": true},
	},
	{
		"name":        "fs_list",
		"description": "List a directory on a node (directories first).",
		"inputSchema": schema([]string{"node"}, map[string]any{
			"node": nodeProp,
			"path": prop("string", "Directory; defaults to the node's first root."),
		}),
		"annotations": map[string]any{"readOnlyHint": true},
	},
}
