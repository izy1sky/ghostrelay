<p align="center">
  <img src="assets/logo.svg" width="160" alt="ghostrelay logo: a pixel ghost with a >_ prompt for a face, wired to three terminals">
</p>

<h1 align="center">ghostrelay</h1>

<p align="center">
  <b>Your agent, inside every machine you own.</b><br>
  <code>one MCP hub · nodes dial out · mac · linux · windows</code>
</p>

<p align="center">
  <img alt="Go 1.24+" src="https://img.shields.io/badge/go-1.24%2B-39d353?style=flat-square&labelColor=0b0f14&logo=go&logoColor=7dff9b">
  <img alt="MCP" src="https://img.shields.io/badge/MCP-streamable%20HTTP-39d353?style=flat-square&labelColor=0b0f14">
  <img alt="Platforms" src="https://img.shields.io/badge/nodes-macOS%20%7C%20Linux%20%7C%20Windows-39d353?style=flat-square&labelColor=0b0f14">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-39d353?style=flat-square&labelColor=0b0f14">
</p>

A single binary, `relay`, that lets an agent on one host use the files and
shell of other hosts that have no public address. A policy on the server
decides what each agent may do, and asks a human when it should.

```
Host A (agent) ──MCP /mcp──► relay serve (public IP) ◄──WSS /node── relay node (Host B: macOS / Linux / Windows)
                              │ policy → allow / ask / deny
                              └ /admin page + relay approve CLI
```

- `relay serve` runs on the one machine with a reachable address.
- `relay node` runs on each resource host and **dials out**. It needs no open port.
- The agent adds the server as an MCP server and gets one set of tools that
  works the same whatever OS a node runs (see
  [One API for every OS](#one-api-for-every-os)):

| Group | Tools |
|---|---|
| Discover | `nodes_list`, `node_info` |
| Run | `exec` (`argv` = no shell, or `command` = the node's shell), `job_logs`, `job_kill`, `jobs_list` |
| Files | `fs_read`, `fs_write`, `fs_edit`, `fs_list`, `fs_stat`, `fs_mkdir`, `fs_move`, `fs_remove`, `fs_glob`, `fs_grep` |
| Between nodes | `transfer` |

Wire details are in [PROTOCOL.md](PROTOCOL.md).

## Quick start

Three commands, one per machine. Get `relay` for each OS from
[Releases](../../releases) (or `go build -o relay .`).

> **The release binaries aren't code-signed yet.** Downloaded through a
> browser, the OS may refuse or warn the first time. To clear that once:
> - **macOS:** `xattr -d com.apple.quarantine relay`, or System Settings →
>   Privacy & Security → **Open Anyway**.
> - **Windows:** `Unblock-File .\relay.exe` in PowerShell, or **More info →
>   Run anyway** on the SmartScreen prompt.
>
> Downloads with `curl`, `wget` or `gh release download` don't need this, and
> neither does the copy `relay service install` makes. Check a download
> against `SHA256SUMS` on the release page.

**1. Server** (a machine the others can reach):

```bash
relay init --url http://<this machine's address>:8787   # tokens, a policy, a join code
relay serve                                            # or: relay service install server
```

`relay init` prints everything else you need: the join code, the Claude Code
command, and where to approve calls. `relay invite` prints it again.

**2. Each machine to share**, any OS:

```bash
relay join rj1_... --root ~/work --allow-exec --install
```

It checks the server and the code, saves its settings, and with `--install`
keeps running as a service, also after reboots (launchd on macOS, a systemd
user unit on Linux, a logon Scheduled Task on Windows; no admin rights).
Without `--install` it runs in the terminal. `--root` is the folder agents may
use; `--allow-exec` lets them run commands.

**3. The agent's machine:** paste the `claude mcp add ...` line `relay init`
printed. Then ask Claude, for example: "on node win, run `ffmpeg -version`".

Day to day:

| Command | Does |
|---|---|
| `relay service status` / `logs [-f]` / `uninstall` | check, follow or remove the node service (add `server` for the server's) |
| `relay approvals`, `relay approve <id> [--similar\|--node] [--for 1h]`, `relay deny <id>` | decide calls the policy asks about (on the server, no setup needed) |
| `relay grants`, `relay grants revoke <id>` | see and end the grants that let calls through without asking |
| `relay invite` | the join code and agent command again |

Settings live in `~/.relay` (`RELAY_HOME` moves it): `server/server.json`,
`server/policy.json` and `node.json`. They hold tokens, so they are only
readable by you. The keys are the flag names below, so anything a flag can
set, the file can too; flags win over the file.

The default policy (`relay init --policy workspace`) lets agents work without
asking you at every step:

| Allowed | Asks you | Denied |
|---|---|---|
| reading and searching; writing, editing, moving files and making folders (inside each node's roots, which the node enforces); commands that only look, like `git status`, `ls`, `python --version` | other commands, deletes | writes to `.git`, `.env`, `.ssh` |

When it does ask, one approval can cover many calls: see
[Grants](#grants-approve-once-for-many-calls). Other starting points:
`--policy ask` (everything but reads asks), `readonly`, and `open` (local tests).

## Build

```bash
go build -o relay .
go test ./...
python3 tests/e2e.py ./relay     # init, serve, join, then the smoke test
```

Releases: push a tag like `v0.6.0` and [the release workflow](.github/workflows/release.yml)
builds archives for macOS, Linux and Windows (amd64 and arm64) with checksums.
CI runs the unit and end-to-end tests on Linux and Windows for every push.

## Manual setup (flags)

Everything `relay init` and `relay join` do can be done with flags, for
scripts or containers.

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

**2. Node**, on each resource host, whatever its OS. The flags are the same everywhere.

```bash
# macOS / Linux
RELAY_NODE_TOKEN=<node token> ./relay node --server https://your-server:8787 --name box --root ~/work --allow-exec
```

```powershell
# Windows (PowerShell)
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

## One API for every OS

The agent shouldn't have to guess what a node is, and shouldn't need a
different tool per OS. So:

**1. The node probes its system at startup, and reports it in `node_info`.**

| Field | Example | How it's found |
|---|---|---|
| `os`, `arch` | `windows`, `amd64` | the binary's platform |
| `shell`, `shell_kind` | `C:\...\pwsh.exe`, `powershell` | `pwsh` → `powershell` on Windows; `bash` → `sh` elsewhere |
| `path_sep` | `\` | the platform |
| `roots_case_insensitive` | `[true]` | **asked of each root's filesystem**: create a lowercase file, look it up in uppercase |
| `tools` | `{"git": "...", "ffmpeg": "..."}` | looked up on `PATH` (`--probe`) |

Case sensitivity is probed rather than guessed, because the OS doesn't decide
it. macOS volumes are usually case-insensitive but can be case-sensitive. Linux
is usually case-sensitive but can use ext4 casefold. Windows can turn on case
sensitivity per directory.

**2. File tools behave the same everywhere.** `fs_*` and `transfer`:
- accept forward slashes on every OS (Windows also takes `\`)
- return paths in the node's own form
- handle CRLF files on edit
- follow the filesystem's case rules in `fs_glob`
- never follow a symlink when removing or moving one

`fs_stat(sha256=true)` hashes a file, to compare copies across nodes without
`shasum` vs `Get-FileHash`. Use these instead of `rm`/`del`, `mkdir`, `mv`,
`find` or `grep`, and the same call works on any node.

**3. `exec` has two modes.**
- `argv: ["git", "status", "--short"]` runs the program directly. There's no
  shell and no quoting rules, the exit code is the program's own, and it
  behaves the same on all three OSes. Prefer it.
- `command: "..."` is a command line for the node's shell. Check
  `node_info.shell_kind` and write PowerShell or POSIX syntax to match.

**4. Policy follows the filesystem, not the OS name.** Path rules compare
case-insensitively exactly where the node reported that root as
case-insensitive. A `**/.git/**` deny catches `.GIT` on a normal Mac volume or
on Windows, and leaves a genuinely separate `.GIT` directory alone on a
case-sensitive Linux disk. Nodes older than v0.5 don't report it, so the
server falls back to the platform default for them (Windows and macOS:
insensitive).

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
| `paths` | `path` for fs tools (both `src` and `dst` for `fs_move`), `cwd` for exec, made absolute against the node's first root | glob: `*` one segment, `**` any depth, `/**` at the end includes the dir itself |
| `commands` | exec command line; for `argv`, the arguments joined with spaces (quoted where needed), so `^git\b` matches both forms | Go regexp, any match |

- **Actions:** `allow`; `deny` (the agent sees the rule number and `reason`);
  `ask` (the call waits for a human, up to `approval_timeout_sec`, then is refused).
- **Case:** path rules compare case-insensitively where the node probed that
  root as case-insensitive (see [One API for every OS](#one-api-for-every-os)).
- **Windows paths:** `/` or `\`, and `..` can't climb past the drive.
- **Named agents:** give each agent machine its own token, and list only its
  sha256 in the policy. Then rules can treat your Mac differently from a CI box.
- **Hot reload:** the file is re-read within 2 s of a change. An invalid edit is
  rejected (logged as `policy_reload_failed`) and the old policy stays in force.
- **Test a policy before relying on it:**
  ```bash
  ./relay policy check --policy policy.json --node win --os windows --root 'D:\work' --tool exec --command "Remove-Item x"
  ```

### Approving `ask` calls

The tool call waits **on the server**; the node sees nothing until you decide.
You can decide in three ways:

- **Web:** open `https://your-server:8787/admin/` (on your phone too). Paste the
  admin token once per tab. Each waiting call offers **Allow once**, **Allow
  similar** (for example *exec of python on win*), **Everything on node**, and
  **Deny**; the wider two last as long as the duration picker says. The page
  also lists active grants, with **Revoke**.
- **CLI:**
  ```bash
  export RELAY_SERVER=https://your-server:8787 RELAY_ADMIN_TOKEN=...   # not needed on the server itself
  ./relay approvals
  ./relay approve 5f3892ba                       # this call only
  ./relay approve 5f3892ba --similar --for 1h    # and calls like it
  ./relay approve 5f3892ba --node --for 30m      # and everything on that node
  ./relay deny 5f3892ba --reason "not that folder"
  ```
- **Notification:** set `notify.url` and the server POSTs each request there.
  `kind`: `json` (default), `text` (plain body, works with ntfy), or `wecom`
  (WeCom group robot).

`relay approve --always` still approves identical calls (same agent, node,
tool, path and command) until the server restarts.

Without `RELAY_ADMIN_TOKEN`, `ask` calls are refused right away, because nobody
could approve them.

### Grants: approve once for many calls

A grant lets calls through without asking, for one agent, for a while. There
are two ways to get one:

1. **You widen an approval.** *Allow similar* grants the same program on that
   node (`python build.py` → *exec of python on win*), or the same kind of
   change under the folder the paths share (*fs_write, fs_edit, fs_mkdir in
   D:/work/app/\*\**). *Everything on node* grants all tools there.
2. **The agent asks for a whole task first,** with the `request_grant` tool:
   > node `win`, programs `dotnet`, `git`; folder `D:/work/app`; 45 minutes;
   > *"Build and test the app"*

   You approve one card (**Grant for 45 min**, or for the duration you pick),
   and the task's calls run without asking. The agent is told to do this
   before multi-step work.

How grants behave:
- **Deny rules always win.** No grant writes to `.git`, `.env` or whatever a
  rule denies. A grant covers calls the policy would ask about or that fall
  through to its default.
- **Program grants need a single program.** A shell command that could run
  several (`;`, `&&`, `|`, `>`, `` ` ``, `$(...)`) is not "python", so
  `python a.py; rm -rf ~` still asks. Commands given as `argv` always name
  one program.
- **A program grant trusts the program**, wherever it runs: listed programs
  are the scope for exec, and folders limit only file changes (or exec's cwd,
  when no programs are listed).
- **They expire** (up to 24 h; `request_grant` asks for at most 8 h), are saved
  in `grants.json` next to the policy so restarts keep them, and can be revoked
  any time: `relay grants revoke <id>` or the admin page.
- **Every use is audited**: the audit log's `policy` field names the grant, as
  in `ask (default), grant g6e481918`.

To stop an agent from asking for grants at all, deny the tool:
`{"agents": ["ci"], "tools": ["request_grant"], "action": "deny"}`.

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
- **Run the node as a dedicated low-privilege user** (on any OS), ideally
  inside a VM you can snapshot.

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

- **v0.5:** unit tests for:
  - the case probe against the real filesystem, and shell-kind detection
  - `argv` exec: verbatim arguments, exit codes, missing programs
  - `fs_remove` on a symlink keeping its target, and refusing roots,
    non-empty dirs and escapes
  - `fs_move`, including case-only renames
  - `fs_glob` / `fs_grep`, skipping binaries and handling CRLF
  - `fs_stat` hashing
  - policy case folding per probed root, including an old node falling back
  - `fs_move` checking both paths

  Live: `tests/node_smoke.py` passed 24 of 24 on a normal macOS volume, and
  again with the node's root on a **case-sensitive APFS volume** (Linux-like).
  That run included transfers between the two kinds of volume. The live
  policy check denied `repo/.GIT/config` on the case-insensitive node and
  allowed it on the case-sensitive one.

**Not yet tested on a real Windows or Linux host.** Both binaries build and
pass `go vet` (Linux shares the Unix code paths tested on macOS). The job,
transfer and symlink unit tests are Unix-only. `tests/node_smoke.py` is how to
check a real host.

## Testing a node (any OS)

For a full walk-through of every feature, with what each step should show,
see [TESTING.md](TESTING.md). To make one tool call by hand, as an agent would:
`python3 tests/mcp.py exec '{"node": "a", "argv": ["git", "--version"]}'`.

`tests/node_smoke.py` runs on the agent machine. It asks the node what it is
(`node_info`) and picks matching shell snippets: PowerShell on Windows, POSIX
elsewhere. Everything else goes through the OS-neutral tools. It checks:
- the system probe against reality: a mixed-case read must succeed exactly
  when the root was reported case-insensitive
- `argv` and shell exec: UTF-8, exit codes, stderr, tree kill on timeout,
  `cwd` with spaces and Chinese
- the jail
- every `fs_*` tool, including CRLF edits checked by sha256
- background jobs and `job_kill`
- with `--peer`, transfers in both directions with sha256 comparison

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
3. **The host under test**, with the binary for its platform from `dist/`:
   ```powershell
   # Windows (use the arm64 build if $env:PROCESSOR_ARCHITECTURE says ARM64)
   mkdir C:\relay-test -Force; Unblock-File .\relay-windows-amd64.exe
   $env:RELAY_NODE_TOKEN = "<token from step 1>"
   .\relay-windows-amd64.exe node --server http://<mac ip>:8787 --name win --root C:\relay-test --allow-exec
   ```
   ```bash
   # Linux
   mkdir -p ~/relay-test && chmod +x relay-linux-amd64
   RELAY_NODE_TOKEN=<token from step 1> ./relay-linux-amd64 node --server http://<mac ip>:8787 --name linux --root ~/relay-test --allow-exec
   ```
4. **Mac, terminal 3:** test it, using the Mac node as the transfer peer:
   ```bash
   RELAY_AGENT_TOKEN=<agent token> python3 tests/node_smoke.py --node win --peer mac
   ```

This uses plain HTTP, so keep it to a trusted LAN. macOS may ask whether
`relay` may accept incoming connections: allow it. The Mac node can be tested
the same way (`--node mac`). INFO lines report behavior
worth knowing (like how native programs print Chinese) without failing the run.

## Next steps

1. **mTLS enrollment:** a one-time token is swapped for a per-node client cert.
2. **Background transfers:** run big copies as jobs, with progress you can poll,
   and resume from the last good chunk after a link drop.
3. **Custom tools:** nodes advertise their own tools (for example
   `win.ffmpeg_transcode`), re-exported over MCP. Policy already matches them
   by glob.
4. **Job ownership:** let the policy limit `job_kill` / `job_logs` to the
   agent that started the job.

Other notes:
- On Windows, a `command`'s exit code follows PowerShell rules. A failed
  cmdlet with no `exit` statement reports 1 or 0. Use `argv` when the exact
  exit code matters.
- A command that leaves a background child holding its output gets its reply
  about 2 s late.
