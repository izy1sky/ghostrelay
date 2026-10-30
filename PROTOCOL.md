# relay wire protocol (v0.5)

Three parties:

- **server** (`relay serve`): the only host with a reachable address.
- **node** (`relay node`): a resource host. Dials out to the server; never listens.
- **agent**: any MCP client (Claude Code etc.). Talks MCP to the server.

```
agent ──HTTP POST /mcp (Bearer AGENT_TOKEN)──► server ◄──WSS /node (Bearer NODE_TOKEN)── node
```

The two tokens are separate on purpose: an agent token cannot register a node,
and a node token cannot call tools.

## 1. Node link: `GET /node` (WebSocket)

Auth: `Authorization: Bearer <NODE_TOKEN>` on the upgrade request. A wrong
token is rejected with 401 before the upgrade.

Every frame is one JSON text message:

```json
{"type": "...", "id": "...", "op": "...", "args": {}, "result": {}, "error": "", "info": {}}
```

| type      | direction      | fields                | meaning                                       |
|-----------|----------------|-----------------------|-----------------------------------------------|
| `hello`   | node → server  | `info`                | first frame; registers the node               |
| `welcome` | server → node  |                       | registration accepted                         |
| `req`     | server → node  | `id`, `op`, `args`    | run an operation                              |
| `res`     | node → server  | `id`, `result`/`error`| reply to `req` with the same `id`             |
| `cancel`  | server → node  | `id`                  | the caller gave up; stop the running `req`    |

- `id` is chosen by the server and unique per connection. Many `req`s can be in
  flight at once; replies may arrive in any order.
- If a second node registers with a name that is already connected, the old
  connection is closed and replaced (this is the reconnect path).
- Both sides send WebSocket pings every 20 s; a missed pong closes the link.
  The node reconnects with exponential backoff (1 s → 30 s).
- When the link drops, the node cancels every in-flight `req` (including a
  foreground `exec`). Background jobs are not requests and keep running.

### `info` (hello)

```json
{"name": "win", "version": "0.5.0", "os": "windows", "arch": "amd64",
 "hostname": "DESKTOP-1", "shell": "C:\\...\\pwsh.exe", "shell_kind": "powershell",
 "path_sep": "\\", "roots": ["D:\\work"], "roots_case_insensitive": [true],
 "allow_exec": true,
 "max_output": 262144, "max_timeout_sec": 600,
 "max_jobs": 16, "max_job_timeout_sec": 21600,
 "tools": {"git": "C:\\Program Files\\Git\\cmd\\git.exe"}}
```

### Operations

| op         | args                                                  | result                                                                 |
|------------|-------------------------------------------------------|------------------------------------------------------------------------|
| `exec`     | `command` **or** `argv[]`, `cwd?`, `timeout_sec?`, `owner` | `exit_code`, `stdout`, `stderr`, `*_truncated`, `timed_out`, `duration_ms` |
| `exec` + `background: true` | same                                 | job (below), returned at once                                          |
| `job_logs` | `job_id`, `offset?` (bytes), `max_bytes?`, `tail?`, `wait_sec?` (≤ 60) | `job`, `data`, `offset`, `next_offset`, `more`             |
| `job_kill` | `job_id`                                              | job                                                                    |
| `jobs_list`| none                                                  | `jobs[]`                                                               |
| `fs_stat`  | `path`, `sha256?`                                     | `path` (resolved), `exists`, `dir`, `symlink`, `size`, `mode`, `mod_time`, `sha256?` |
| `fs_move`  | `src`, `dst`, `overwrite?`                            | stat of `dst`                                                          |
| `fs_remove`| `path`, `recursive?`                                  | `removed`, `dir`, `symlink`                                            |
| `fs_glob`  | `path?`, `pattern`, `max?`                            | `root`, `matches[]` (relative, `/`), `truncated`                       |
| `fs_grep`  | `path?`, `pattern` (RE2), `glob?`, `ignore_case?`, `max?` | `root`, `matches[]` (`file`, `line`, `text`), `truncated`, `skipped_files` |
| `fs_walk`  | `path`                                                | `root`, `entries[]` (`rel`, `dir`, `size`, `mode`), `skipped[]`        |
| `fs_mkdir` | `path`                                                | stat of the directory                                                  |
| `get_chunk`| `path`, `offset`, `length` (≤ 4 MiB)                  | `data` (base64), `eof`                                                 |
| `put_open` | `path`, `mode?`, `overwrite?`                         | `upload_id`, `path`                                                    |
| `put_chunk`| `upload_id`, `offset` (must equal bytes written), `data` | `written`                                                           |
| `put_close`| `upload_id`, `sha256`                                 | `path`, `bytes`, `sha256`; a mismatch discards the upload              |
| `put_abort`| `upload_id`                                           | `aborted`                                                              |
| `fs_read`  | `path`, `offset?` (1-based line), `limit?` (lines)    | `path`, `content`, `start_line`, `total_lines`, `truncated`, `crlf`    |
| `fs_write` | `path`, `content`                                     | `path`, `bytes`                                                        |
| `fs_edit`  | `path`, `old_string`, `new_string`, `replace_all?`    | `path`, `replacements`                                                 |
| `fs_list`  | `path?`                                               | `path`, `entries[]` (`name`, `dir`, `size`, `mod_time`), `truncated`   |

A job is `{id, command, cwd, owner, pid, state, exit_code?, started, ended?,
duration_ms, output_bytes}`. `state` is `running`, `exited`, `killed` or
`timed_out`. `owner` is always set by the server to the calling agent's
name; whatever the agent sends is overwritten.

Jobs belong to the node process, not to a link. stdout and stderr go,
interleaved, straight into `<state-dir>/jobs/<id>.log`. `job_logs` reads that
file by byte offset, and never splits a UTF-8 character across chunks. With
`wait_sec` it returns as soon as there is new data or the job ends. Finished
jobs are kept for 24 h, at most 50. A node restart clears the job directory.

Transfer ops are internal: the server drives them for the `transfer` tool;
they are not MCP tools. `put_open` creates `.relay-up-*` next to the target and
records it under `<state-dir>/uploads/`. `put_close` verifies size and sha256,
fsyncs, applies the mode bits (not on Windows), and renames the file into
place. Uploads idle for 10 minutes are discarded, and records left by a
crashed node process are cleaned up when it starts again. `fs_walk` never
follows symlinks.

### System probe and OS neutrality (v0.5)

At startup the node fills `shell_kind` (`powershell` | `bash` | `sh`),
`path_sep`, and `roots_case_insensitive`. The last is measured on each root:
the node creates `.relay-case-probe-*` and stats its uppercase name. If the
root is read-only, it falls back to the platform default.

- `exec` with `argv` runs `argv[0]` (looked up on `PATH`) with exactly those
  arguments and no shell. With `command`, it uses the node's shell. Exactly one
  of the two is required.
- `fs_remove` and `fs_move` resolve the parent directory through the jail but
  act on the final element itself (`Lstat`), so a symlink is removed or moved
  as a link and its target is never touched. Roots can't be removed or moved.
- `fs_glob` and `fs_grep` walk without following symlinks. Glob matching folds
  case when the root is case-insensitive.

## 2. Node-side enforcement (the node has the final say)

The server can ask for anything; the node decides.

- **fs jail:** every path (and `exec`'s `cwd`) is made absolute, symlinks are
  resolved, and it must fall inside one of the `--root` directories. Relative
  paths are relative to the first root.
- **exec is off by default.** It needs `--allow-exec`. Once on, a command can do
  whatever the node's OS user can do. The jail only constrains `cwd`. The real
  boundary for `exec` is the OS account (and the VM) the node runs as.
- Output is capped at `max_output` bytes per stream. The timeout is capped at
  `max_timeout_sec`. On timeout or cancel the whole process tree is killed.
- Commands run without a TTY; stdin is empty.
- Windows: commands run in PowerShell (pwsh if installed, otherwise Windows
  PowerShell) with UTF-8 output forced.

## 3. Agent face: `POST /mcp` (MCP streamable HTTP)

Auth: `Authorization: Bearer <AGENT_TOKEN>`.

Minimal streamable-HTTP server: one JSON-RPC message per POST, answered with
`application/json`. Notifications get `202`. `GET`/`DELETE` return `405` (no
server-initiated stream, no sessions). Methods: `initialize`, `ping`,
`tools/list`, `tools/call`.

Tools: `nodes_list`, `node_info`, `exec`, `fs_read`, `fs_write`, `fs_edit`,
`fs_list`, `fs_stat`, `fs_mkdir`, `fs_move`, `fs_remove`, `fs_glob`, `fs_grep`,
`job_logs`, `job_kill`, `jobs_list`, `transfer`, `request_grant`. Every tool except
`nodes_list` and `transfer` (which takes `src_node` / `dst_node`) takes a
required `node` argument;
there is no implicit default node.

### Agent identity

The bearer token picks the agent name that policy rules match on:
`RELAY_AGENT_TOKEN` is `default`, and any token whose sha256 appears in the
policy's `agents` list takes that agent's name. Anything else gets a 401.

## 4. Policy and approvals (v0.2)

Every `tools/call` is checked against the policy before anything is sent to a
node (rule format: README.md). The result is one of:

- `allow`: forwarded.
- `deny`: returned at once as a tool error (`isError: true`) naming the rule.
- `ask`: the HTTP request stays open while a pending entry waits for a
  decision.

Path rules fold case when the node reported the path's root as
case-insensitive (platform default for nodes older than v0.5). `fs_move` is
two requests (`src` and `dst`), and both must pass. For `argv` exec, `commands`
regexes see the arguments joined with spaces, quoted where needed.

`transfer` is evaluated as `fs_read` on every source file and `fs_write` on
every destination file and directory. The strictest verdict wins (deny > ask >
allow), with one approval for the whole transfer. A timeout or a deny returns a tool error. The approval wait is not
counted against `exec`'s own timeout.

### Grants (v0.7)

Between the verdict and the approval sits a grant check. A deny **rule** is
final. Otherwise every request of the call that the policy doesn't allow
(ask, or the default) must be covered by an active grant, or the call asks.
A grant `{agent, node, tools?, paths?, programs?, expires}` covers a request
when the agent and node are equal, the tool is listed (or none are), the path
matches a glob (folded like rule paths; for exec only when no programs are
listed), and for exec the program is listed: `argv[0]`, or the first word of a
shell command with no `; & | < > `` ` `` $(` in it, as a lowercase base name
without `.exe`. Grants are stored in `grants.json` beside the policy (0600) and
pruned when they expire (at most 24 h).

`request_grant {node, programs?, paths?, tools?, minutes?, reason}` creates a
pending entry of kind `grant`; approving it stores that grant (for `minutes`,
default 60, max 480, unless the approver gives another duration) and returns
its id, scope and expiry to the agent. Relative `paths` hang off the node's
first root; a path without glob characters means that folder and everything
in it. A deny rule on `request_grant` stops an agent from asking.

Admin endpoints, all with `Authorization: Bearer <ADMIN_TOKEN>`:

| Method + path              | Body / result                                                       |
|----------------------------|---------------------------------------------------------------------|
| `GET /admin/api/pending`   | `[{id, kind, agent, node, tool, command?, path?, verdict, reason?, created, expires, similar?, node_scope?, grant_scope?, minutes?}]` |
| `POST /admin/api/decide`   | `{"id", "decision": "allow" \| "always" \| "similar" \| "node" \| "deny", "minutes"?, "reason"?, "by"?}` → `ok`, or 404 if already gone. `similar` / `node` also store the offered grants for `minutes` (default 60); `allow` on a `grant` entry stores the requested grant |
| `GET /admin/api/grants`    | active grants: `[{id, agent, node, tools?, paths?, programs?, reason?, by, created, expires, uses, scope}]` |
| `POST /admin/api/grants/revoke` | `{"id", "by"?}` → `ok`, or 404 |
| `GET /admin/api/nodes`     | `{connected: [node_info + remote, connected_at], disconnected: [{name, by, at}]}` |
| `POST /admin/api/nodes/disconnect` | `{"name", "by"?}` → `ok`. Closes that node's link with WebSocket code **4003** and refuses it (4003 again, at the hello) until allowed. The list lives in `blocked.json` beside the policy |
| `POST /admin/api/nodes/allow` | `{"name", "by"?}` → `ok`. The node gets back in at its next try (nodes refused with 4003 retry every minute) |
| `GET /admin/api/setup`     | `{version, url, listen, tls, join_code?, agent_token, named_agents, policy: {file, default, rules}, warning?}`: what the console needs to add machines and agents. `warning` is set when the port in `url` differs from `listen` |
| `GET /admin/api/activity?limit=N` | the newest audit records first (default 300, max 1000) |

The console at `/admin/` is one page using only these calls; a `#k=<admin token>`
fragment in its link signs it in for that tab.

### The local page (bare `relay`)

`relay` with no arguments, or `relay ui [--listen 127.0.0.1:PORT] [--no-browser]`,
serves a setup page on a loopback address and opens it. Its JSON API lives
under `/api/` and answers only requests whose `Host` is `127.0.0.1:PORT` or
`localhost:PORT` and that carry the random `X-Relay-Key` from the printed link
(`#k=...`). It drives the same code as `relay init`, `relay join` and
`relay service`. Nodes and servers it starts without a service run as its
child processes and stop with it.

A node with a settings file keeps three files beside it, which the page reads:
`node.status.json` (state, since, last error; rewritten every 5 s, so older
than 15 s means not running), `node.activity.jsonl` (each call it ran, minus
polling and transfer plumbing; rotated at 1 MiB) and `node.paused` (while it
exists, the node stays disconnected). If the settings file disappears
(`relay leave`), the node stops. Its state is `connecting`, `connected`,
`paused` or `disconnected` (refused by the hub with 4003).

`relay update` reads the newest release from
`https://api.github.com/repos/izy1sky/ghostrelay/releases/latest`, downloads
`relay_<version>_<os>_<arch>.tar.gz|.zip` and `SHA256SUMS`, refuses a
mismatch, and replaces `~/.relay/bin/relay` (with installed services stopped,
then started) and the copy that ran it. The setup page asks the same API once
when it starts, to offer **Update**.

With `RELAY_HOME` set, service names get a suffix from a hash of that folder
(`ghostrelay-node-box-1a2b3c`), so a second settings folder never drives the
services of `~/.relay`.
| `GET /admin/`              | the approval page; it needs no token to load, but asks for one before showing data |

## 5. Audit

The server appends one JSON line per event to `--audit` (default
`relay-audit.jsonl`):
- node connect and disconnect
- auth failures (node, agent, admin)
- every tool call: agent, remote address, node, arguments (long strings
  shortened), policy decision, result status, duration
- approval requested / decided (by whom, and why) / timed out / abandoned
- policy reloaded / reload failed

## Planned

mTLS node enrollment · background / resumable transfers · node-advertised
custom tools · job ownership in policy.
