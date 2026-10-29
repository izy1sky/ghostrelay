# relay

A single binary that lets an agent on one host use the files and shell of
other hosts that have no public address. A policy on the server decides what
each agent may do, and asks a human when it should.

```
Host A (agent) ──MCP /mcp──► relay serve (public IP) ◄──WSS /node── relay node (Host B, Windows)
                              │ policy → allow / ask / deny
                              └ /admin page + relay approve CLI
```

- `relay serve` runs on the one machine with a reachable address.
- `relay node` runs on each resource host and **dials out**. It needs no open port.
- The agent adds the server as an MCP server and gets these tools:
  `nodes_list`, `node_info`, `exec`, `fs_read`, `fs_write`, `fs_edit`, `fs_list`,
  `transfer` (node-to-node copy), and for background jobs `job_logs`,
  `job_kill`, `jobs_list`.

Wire details are in [PROTOCOL.md](PROTOCOL.md).

## Build

```bash
go build -o relay .
GOOS=windows GOARCH=amd64 go build -o relay.exe .
go test ./...
```

Prebuilt: `dist/relay-{darwin-arm64,linux-amd64,windows-amd64.exe,windows-arm64.exe}`.

## Run

**1. Server** (public host). Generate three *different* tokens:

```bash
export RELAY_NODE_TOKEN=$(./relay token)    # nodes use it to connect
export RELAY_AGENT_TOKEN=$(./relay token)   # the "default" agent (optional if the policy names agents)
export RELAY_ADMIN_TOKEN=$(./relay token)   # you, approving calls
cp policy.example.json policy.json          # then edit it
./relay serve --listen :8787 --policy policy.json --tls-cert cert.pem --tls-key key.pem
```

Without `--tls-cert/--tls-key` it serves plain HTTP. That is fine on
localhost or behind a TLS reverse proxy (Caddy, nginx). It is **not** fine on
the open internet, because the tokens would travel in clear.
Without `--policy`, every call from an authenticated agent is allowed, and the
server prints a warning.

**2. Node** (Windows host, PowerShell):

```powershell
$env:RELAY_NODE_TOKEN = "<node token>"
.\relay.exe node --server https://your-server:8787 --name win --root D:\work --allow-exec
```

- `--root` (repeatable): the only directories the fs tools may touch. The first
  one is the default `cwd`.
- `--allow-exec`: exec is **off** unless you pass it.
- `--max-output` (256 KiB) and `--max-timeout` (600 s): caps the node enforces
  no matter what the server asks for.
- `--max-jobs` (16), `--max-job-timeout` (6 h), `--state-dir` (default: the
  user cache dir + `relay-node/<name>`): background job limits, and where job
  logs live.

The node reconnects by itself (1 s → 30 s backoff).

**3. Agent** (Host A, Claude Code):

```bash
claude mcp add --transport http relay https://your-server:8787/mcp --header "Authorization: Bearer <agent token>"
```

Then ask, for example: "on node win, run `ffmpeg -version`".

## Background jobs

For anything that runs longer than a minute or two (builds, renders,
training), the agent calls `exec` with `background: true`. That returns a
`job_id` at once:

```
exec(node="win", command="dotnet build", background=true)  → started job j1ee526e5
job_logs(node="win", job_id="j1ee526e5", wait_sec=30)        → output 0-812, next_offset 812, still running
job_logs(..., offset=812, wait_sec=60)                        → only the new output
job_kill(node="win", job_id="j1ee526e5")                      → kills it and everything it started
jobs_list(node="win")                                         → running and recently finished jobs
```

- **Jobs survive the link.** The job runs on the node, and stdout and stderr go
  straight into a log file there. A dropped connection, a server restart or a
  client that gives up doesn't touch it. After reconnecting, keep reading from
  the last `next_offset`.
- `wait_sec` (max 60) makes `job_logs` return as soon as there is new output or
  the job ends, so the agent doesn't have to poll in a tight loop.
- `tail: true` returns just the last `max_bytes`.
- **Limits:** `--max-jobs` running at once, and `--max-job-timeout` per job
  (`timeout_sec` can only shorten it). A job that hits the timeout is killed
  with its whole process tree and marked `timed_out`.
- **Retention:** finished jobs and their logs are kept for 24 h, at most 50.
  **A node restart forgets all jobs and deletes their logs.** On Unix the
  processes themselves may keep running.
- `jobs_list` shows which agent started each job (`owner`), as the server
  recorded it.
- **Foreground `exec` is unchanged:** it blocks, and a link drop still kills it.
  Use background jobs for anything you can't afford to lose.

Background `exec` goes through the same policy rules as foreground `exec`.
Allow `job_logs` and `jobs_list` freely. `job_kill` can stop any job on the
node, not only the caller's.

## Transfer

`transfer` copies a file or a whole directory from one node to another (or
within one node), streamed through the server. Binary files are fine.

```
transfer(src_node="mac", src_path="build/app.zip", dst_node="win", dst_path="D:/work/in")
transfer(src_node="win", src_path="renders", dst_node="mac", dst_path="renders-copy")
```

- **`cp -r` semantics:** a file copied onto an existing directory goes inside it.
  A directory is copied to `dst_path`. Existing files are never replaced
  unless you set `overwrite`; for a directory, `overwrite` merges into it.
- **Integrity:** each file is streamed in 1 MiB chunks into a temp file next to
  the target. The destination node checks the sha256 the server computed while
  streaming, and only renames the file into place if it matches. A failed or
  interrupted transfer never leaves a partial file under the target name. If
  the destination node crashes mid-copy, its temp file is deleted the next
  time it starts.
- **Throughput:** reading the next chunk overlaps with writing the current one.
  Locally, with both nodes on one Mac, 50 MiB took 1.3 s. Over a real network
  it is roughly bounded by chunk size ÷ round-trip time per hop.
- **Limits:** directories up to 20,000 entries (archive anything bigger first).
  Symlinks and special files are skipped and listed in the result.
- **Errors:** on failure the result says how many files were already copied.
  Files already copied stay; nothing is rolled back.
- **To or from the agent's own machine:** run `relay node` there too. It's just
  another node.

**Policy:** a transfer is checked as `fs_read` of **every** source file plus
`fs_write` of **every** destination file (and each directory it creates),
before any byte moves. Any deny refuses the whole transfer and names the file.
Otherwise any ask asks once, for the whole transfer. So a `**/.git/**` write
deny can't be bypassed by copying a directory that contains `.git`. Rules can't
name `transfer` directly; write them for `fs_read` / `fs_write`.

The call blocks until the copy finishes. MCP clients with a short tool timeout
may give up on very large copies: the server then stops and aborts the upload
on the destination.

## Policy

`policy.json` is an ordered list of rules. **The first matching rule wins**;
if none match, `default` applies (`deny` if unset). Start from
[policy.example.json](policy.example.json).

```json
{
  "default": "deny",
  "approval_timeout_sec": 300,
  "notify": {"kind": "wecom", "url": "https://..."},
  "agents": [{"name": "mac", "token_sha256": "<echo $TOKEN | relay hash>"}],
  "rules": [
    {"tools": ["fs_read", "fs_list", "nodes_list", "node_info"], "action": "allow"},
    {"tools": ["fs_write", "fs_edit"], "paths": ["**/.git/**", "**/*.env"], "action": "deny", "reason": "secrets"},
    {"tools": ["exec"], "commands": ["(?i)\\b(rm|del|Remove-Item)\\b"], "action": "ask"},
    {"agents": ["mac"], "nodes": ["win"], "tools": ["exec", "fs_write"], "paths": ["D:/work/**"], "action": "allow"},
    {"tools": ["exec", "fs_write", "fs_edit"], "action": "ask"}
  ]
}
```

A rule matches when **every matcher it lists** matches. A matcher you leave
out matches anything.

| Matcher | Matches | Syntax |
|---|---|---|
| `agents` | agent name: `default` (RELAY_AGENT_TOKEN) or a name from `agents` | glob |
| `nodes` | node name | glob |
| `tools` | tool name (unknown names are rejected, to catch typos) | glob |
| `paths` | `path` for fs tools, `cwd` for exec, made absolute against the node's first root | glob: `*` one segment, `**` any depth, `/**` at the end includes the dir itself |
| `commands` | exec command line | Go regexp, any match |

- **Actions:** `allow`; `deny` (the agent sees the rule number and `reason`);
  `ask` (the call waits for a human, up to `approval_timeout_sec`, then is refused).
- **Windows nodes:** paths use `/` or `\` and are compared case-insensitively.
  `..` can't climb past the drive.
- **Named agents:** give each agent machine its own token, and list only its
  sha256 in the policy. Then rules can treat your Mac differently from a CI box.
- **Hot reload:** the file is re-read within 2 s of a change. An invalid edit is
  rejected (logged as `policy_reload_failed`) and the old policy stays in force.
- **Test a policy before relying on it:**
  ```bash
  ./relay policy check --policy policy.json --node win --os windows --root 'D:\work' --tool exec --command "Remove-Item x"
  ```

### Approving `ask` calls

The tool call blocks while it waits. You can decide in three ways:

- **Web:** open `https://your-server:8787/admin/` (on your phone too). Paste the
  admin token once per tab, then tap **Allow**, **Allow always** or **Deny**.
- **CLI:**
  ```bash
  export RELAY_SERVER=https://your-server:8787 RELAY_ADMIN_TOKEN=...
  ./relay approvals
  ./relay approve 5f3892ba            # or --always
  ./relay deny 5f3892ba --reason "not that folder"
  ```
- **Notification:** set `notify.url` and the server POSTs each request there.
  `kind`: `json` (default), `text` (plain body, works with ntfy), or `wecom`
  (WeCom group robot).

**Allow always** approves identical calls (same agent, node, tool, path and
command) until the server restarts. It's kept in memory only.

Without `RELAY_ADMIN_TOKEN`, `ask` calls are refused right away, because nobody
could approve them.

## Security model

| Layer | What it does |
|---|---|
| Separate tokens | Node, agent and admin tokens must all differ. Each one only opens its own endpoint. All are compared in constant time. |
| Server policy | allow / ask / deny per agent × node × tool × path × command. Default deny once a policy is loaded. |
| Human approval | `ask` calls wait for the web page or CLI. Timeouts deny. |
| Node-side jail | Every path and `cwd` is resolved through symlinks and must be under a `--root`. `../`, absolute paths and symlinks that escape are refused, **whatever the policy says**. |
| exec opt-in | Off by default on the node. **Once on, a command can do anything the node's OS user can.** |
| Process control | Timeout or cancel kills the whole process tree. No TTY, empty stdin. |
| Audit | `relay-audit.jsonl`: connects, auth failures, every tool call with agent, policy decision and result, every approval with who decided, policy reloads. |

Things to keep in mind:
- **`commands` regexes are a seatbelt, not a wall.** `pwsh -enc ...`, scripts,
  aliases and `cmd /c` get around them. For exec, prefer narrow `allow` rules
  with everything else on `ask`, over trying to deny the bad cases.
- **The policy matches paths as text.** The server doesn't follow symlinks on
  the node; the node's jail does. Keep path rules inside the node's roots.
- **Run the node as a dedicated low-privilege Windows user**, ideally inside a
  VM you can snapshot.

## Tested (macOS; server, node and agent on one machine)

- **v0.1:** MCP handshake, all tools, CRLF-aware edit, jail escapes (`../`,
  absolute, symlink read and write, `cwd`), timeout and cancel killing the
  process tree, output caps, auto-reconnect, wrong tokens, and a real headless
  Claude Code agent.
- **v0.2:** unit tests for glob matching, Windows/Unix path normalization
  (including `..` past the drive), rule evaluation and policy validation.
  Live tests:
  - allow, default deny, deny with reason
  - named agents that may write while `default` may not
  - `ask` → CLI approve, CLI deny with reason, approve always (the repeat
    skipped the queue), timeout, and approve from the web page
  - hot reload, and rejection of an invalid edit
  - admin API refusing a missing token and the agent token
- **v0.3:** unit tests for job lifecycle, long-poll reads by offset, UTF-8-safe
  chunking, kill, timeout and the running-jobs limit. Live tests:
  - a job kept running through a server restart (the node reconnected), and
    its full output was read back afterwards from the saved offset
  - `job_kill` removed the job and its children
  - tail reads, unknown job ids
  - policy deny applied to background `exec`
  - a real headless Claude Code agent started a 15 s job, followed it with
    `offset` + `wait_sec`, and reported the final line and exit code

- **v0.4:** unit tests for chunked put/get round trip (binary, across a chunk
  boundary, mode bits), refusals (existing file, jail escape, out-of-order
  chunk, sha256 mismatch: nothing written, no temp left), walk skipping
  symlinks, stranded-upload cleanup, and strictest-verdict policy evaluation.
  Live tests between two nodes:
  - 50 MiB random binary (same sha256 on both sides)
  - a directory tree with an empty dir and a skipped symlink
  - overwrite refusal and merge; a file onto a directory going inside it
  - a directory containing `.git` refused before anything was copied
  - destination jail escape
  - `ask` → approve, with the exec bit preserved
  - source node killed mid-copy, and destination node killed mid-copy
    (`kill -9`): no partial target either way, and the temp file was cleaned
    up on restart
  - a real headless Claude Code agent copying a directory and then running a
    script from the copy

**Not yet tested on a real Windows host.** The Windows binary builds and passes
`go vet`. The job and transfer unit tests are Unix-only.

## Testing a Windows node

`tests/win_smoke.py` runs on the Mac and checks what only a real Windows host
can show:
- PowerShell exec, UTF-8 output, exit codes, stderr
- tree kill via `taskkill`
- `cwd` with spaces and Chinese
- the jail on `C:\` paths, backslash and mixed-case paths, CRLF edits
- background jobs and `job_kill`
- transfers in both directions, with Chinese file names

It needs no policy on the server.

1. **Mac, terminal 1:** the server, listening on the LAN:
   ```bash
   export RELAY_NODE_TOKEN=$(./relay token) RELAY_AGENT_TOKEN=$(./relay token)
   echo $RELAY_NODE_TOKEN; ipconfig getifaddr en0   # note both for Windows
   ./relay serve --listen 0.0.0.0:8787
   ```
2. **Mac, terminal 2:** the Mac node (same `RELAY_NODE_TOKEN`):
   ```bash
   mkdir -p ~/relay-test && ./relay node --server http://127.0.0.1:8787 --name mac --root ~/relay-test --allow-exec
   ```
3. **Windows, PowerShell:** copy `dist/relay-windows-amd64.exe` over. Use the
   arm64 build if `$env:PROCESSOR_ARCHITECTURE` says ARM64. Then:
   ```powershell
   mkdir C:\relay-test -Force
   Unblock-File .\relay-windows-amd64.exe
   $env:RELAY_NODE_TOKEN = "<token from step 1>"
   .\relay-windows-amd64.exe node --server http://<mac ip>:8787 --name win --root C:\relay-test --allow-exec
   ```
4. **Mac, terminal 3:**
   ```bash
   RELAY_AGENT_TOKEN=<agent token> python3 tests/win_smoke.py --mac-root ~/relay-test
   ```

This uses plain HTTP, so keep it to a trusted LAN. macOS may ask whether
`relay` may accept incoming connections: allow it. INFO lines report behavior
worth knowing (like how native programs print Chinese) without failing the run.

## Next steps

1. **mTLS enrollment:** a one-time token is swapped for a per-node client cert.
2. **Background transfers:** run big copies as jobs, with progress you can poll,
   and resume from the last good chunk after a link drop.
3. **Custom tools:** nodes advertise their own tools (for example
   `win.ffmpeg_transcode`), re-exported over MCP. Policy already matches them
   by glob.
4. **Windows service:** run the node at boot (`sc.exe create` or NSSM for now).
5. **Job ownership:** let the policy limit `job_kill` / `job_logs` to the
   agent that started the job.

Other notes:
- On Windows, `exec`'s exit code follows PowerShell rules. Native programs
  report their real exit code. A failed cmdlet with no `exit` statement reports
  1 or 0.
- A command that leaves a background child holding its output gets its reply
  about 2 s late.
