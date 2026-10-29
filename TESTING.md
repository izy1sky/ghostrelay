# Testing relay by hand

A walk-through you can follow on one machine in about 30 minutes. Every step
says what to run and what you should see. Part 1 sets up the server and two
nodes. Parts 2–9 test one feature each. Part 10 connects a real agent
(Claude Code), Part 11 adds a Windows or Linux machine, and Part 12 tests
the one-command setup (`relay init`, `relay join`, `relay service`).

You need Go 1.24+, Python 3, and `curl`. Commands are for macOS or Linux
(zsh or bash). Everything stays inside `~/relay-test`.

**How the tests talk to the server.** `tests/mcp.py` sends one tool call the
way an agent does, and prints the result:

```
python3 tests/mcp.py <tool> '<json arguments>'
```

It exits 0 when the call works, 1 for a tool error (refused, denied, failed),
and 2 for an HTTP error. The setup below aliases it as `rt`.

---

## Part 1. Setup

### 1.1 Build and unit tests

```bash
cd ~/projects/relay
go build -o relay . && go test ./...
```

✅ You should see `ok  relay`.

### 1.2 Tokens and folders

Write the three tokens to a file, so every terminal uses the same ones
(see the README for what each token is for):

```bash
mkdir -p ~/relay-test/a ~/relay-test/b
cat > ~/relay-test/env.sh <<EOF
export RELAY_NODE_TOKEN=$(./relay token)
export RELAY_AGENT_TOKEN=$(./relay token)
export RELAY_ADMIN_TOKEN=$(./relay token)
export RELAY_SERVER=http://127.0.0.1:8787
alias rt='python3 $PWD/tests/mcp.py'
EOF
```

**In every new terminal**, first run:

```bash
cd ~/projects/relay && source ~/relay-test/env.sh
```

### 1.3 Start the server and two nodes

Use three terminals and leave them running.

**Terminal 1: the server** (no policy for now):

```bash
./relay serve --listen 127.0.0.1:8787
```

✅ It warns `no --policy: every tool call ... is allowed` and `no TLS`. Both
are expected here.

**Terminal 2: node `a`**, with exec on:

```bash
./relay node --server $RELAY_SERVER --name a --root ~/relay-test/a --allow-exec
```

**Terminal 3: node `b`**, with exec **off**:

```bash
./relay node --server $RELAY_SERVER --name b --root ~/relay-test/b
```

✅ Each node prints its probe, e.g. `darwin/arm64 shell=bash ...
case-insensitive=[true] exec=true`, then `connected as "a"`. The server logs
a `node_connected` audit line for each.

Use **terminal 4** for everything below.

---

## Part 2. Automated smoke test

Before testing by hand, run the 24 automated checks:

```bash
python3 tests/node_smoke.py --node a --peer b
```

It runs commands on `a`. The peer `b` is only a transfer target, so it doesn't
need exec.

✅ It ends with `24 passed, 0 failed`. The `INFO` lines are notes, not
failures. It leaves a `smoke` folder in each root, which the steps below
don't care about.

---

## Part 3. Authentication

| # | Run | Expect |
|---|---|---|
| 3.1 | `curl -s -o /dev/null -w '%{http_code}\n' -X POST $RELAY_SERVER/mcp -d '{}'` | `401` (no token) |
| 3.2 | `RELAY_AGENT_TOKEN=$RELAY_NODE_TOKEN rt nodes_list` | `HTTP 401` (a node token can't call tools) |
| 3.3 | `RELAY_AGENT_TOKEN=$RELAY_ADMIN_TOKEN rt nodes_list` | `HTTP 401` (neither can the admin token) |
| 3.4 | `RELAY_NODE_TOKEN=wrong ./relay node --server $RELAY_SERVER --name fake --root ~/relay-test/b`, then Ctrl-C | `server rejected the node token (401); reconnecting...`; the server logs `node_auth_failed` |
| 3.5 | `RELAY_NODE_TOKEN=x RELAY_AGENT_TOKEN=x ./relay serve --listen 127.0.0.1:8788` | refuses to start: `node, agent and admin tokens must all differ` |
| 3.6 | `rt nodes_list` | one line each for `a` (`exec=true`) and `b` (`exec=false`) |

---

## Part 4. What a node reports, and exec

| # | Run | Expect |
|---|---|---|
| 4.1 | `rt node_info '{"node":"a"}'` | JSON with `os`, `shell_kind`, `path_sep`, `roots_case_insensitive`, limits, and `tools` (git, python3… whatever is on PATH) |
| 4.2 | `rt exec '{"node":"a","argv":["echo","hello 世界"]}'` | `exit_code: 0`, stdout `hello 世界` |
| 4.3 | `rt exec '{"node":"a","command":"echo out; echo err >&2; exit 3"}'` | `exit_code: 3`, with `out` under stdout and `err` under stderr |
| 4.4 | `rt exec '{"node":"a","argv":["sleep","30"],"timeout_sec":2}'` | after ~2 s: `exit_code: -1 ... [timed out; process tree killed]` |
| 4.5 | `rt exec '{"node":"b","argv":["echo","hi"]}'` | `exec is disabled on this node (start it with --allow-exec)` |
| 4.6 | `rt exec '{"node":"nope","argv":["echo"]}'` | `node "nope" is not connected; connected nodes: a, b` |

---

## Part 5. The jail: nodes only touch their roots

The node enforces this itself, whatever the server or policy says.

| # | Run | Expect |
|---|---|---|
| 5.1 | `rt fs_read '{"node":"a","path":"../b/x"}'` | `... is outside this node's roots` |
| 5.2 | `rt fs_read '{"node":"a","path":"/etc/hosts"}'` | `... is outside this node's roots` |
| 5.3 | `ln -s /etc ~/relay-test/a/etc-link && rt fs_list '{"node":"a","path":"etc-link"}'` | `outside this node's roots` (a symlink can't escape) |
| 5.4 | `rt exec '{"node":"a","argv":["ls"],"cwd":"/tmp"}'` | `outside this node's roots` (applies to `cwd` too) |
| 5.5 | `rt fs_remove '{"node":"a","path":"etc-link"}'`, then `ls /etc \| head -3` | `removed symlink (its target was not touched) ...`, and `/etc` is still there |
| 5.6 | `rt fs_remove '{"node":"a","path":".","recursive":true}'` | `refusing to remove a node root` |

---

## Part 6. File tools

Run these in order, since each builds on the last.

| # | Run | Expect |
|---|---|---|
| 6.1 | `rt fs_write '{"node":"a","path":"proj/hello.txt","content":"line one\nline two\n"}'` | `wrote 18 bytes to .../proj/hello.txt` (parent folder created) |
| 6.2 | `rt fs_edit '{"node":"a","path":"proj/hello.txt","old_string":"two","new_string":"2"}'` | `replaced 1 occurrence(s)` |
| 6.3 | `rt fs_read '{"node":"a","path":"proj/HELLO.TXT"}'` | On a case-insensitive disk (the macOS default), the two numbered lines, `line 2` included. On a case-sensitive disk, `no such file`. Either way, it matches `roots_case_insensitive` from 4.1 |
| 6.4 | `rt fs_glob '{"node":"a","pattern":"**/*.txt"}'` | `proj/hello.txt` |
| 6.5 | `rt fs_grep '{"node":"a","pattern":"line \\d"}'` | `proj/hello.txt:2: line 2` |
| 6.6 | `rt fs_stat '{"node":"a","path":"proj/hello.txt","sha256":true}'` | `file, 16 bytes, ...` plus a `sha256` line |
| 6.7 | `rt fs_mkdir '{"node":"a","path":"proj/x/y"}'`, then `rt fs_list '{"node":"a","path":"proj"}'` | `x/` listed before `hello.txt` (folders first) |
| 6.8 | `rt fs_move '{"node":"a","src":"proj/hello.txt","dst":"proj/Hello.txt"}'` | `moved to .../proj/Hello.txt` (a case-only rename works even on a case-insensitive disk) |
| 6.9 | `rt fs_remove '{"node":"a","path":"proj/x"}'` | refused: `non-empty directory (set recursive ...)` |
| 6.10 | `rt fs_remove '{"node":"a","path":"proj/x","recursive":true}'` | `removed directory ...` |

---

## Part 7. Transfer between nodes

```bash
rt exec '{"node":"a","argv":["sh","-c","mkdir -p proj/data && head -c 30000000 /dev/urandom > proj/data/big.bin"]}'
```

| # | Run | Expect |
|---|---|---|
| 7.1 | `rt transfer '{"src_node":"a","src_path":"proj","dst_node":"b","dst_path":"copy"}'` | `copied a:... → b:... (2 files, 28.6 MiB) in 0.Xs`, then `every file's sha256 was verified` |
| 7.2 | `rt fs_stat '{"node":"a","path":"proj/data/big.bin","sha256":true}'` and the same for `{"node":"b","path":"copy/data/big.bin",...}` | the same sha256 on both |
| 7.3 | repeat 7.1 | refused: `already exists on b (set overwrite to merge into it ...)` |
| 7.4 | repeat 7.1 with `"overwrite":true` | copied again |
| 7.5 | `rt transfer '{"src_node":"b","src_path":"copy/Hello.txt","dst_node":"a","dst_path":"back.txt"}'` | copied the other way (b has exec off, which transfer doesn't need) |
| 7.6 | `ls -a ~/relay-test/b/copy/data` | only `big.bin`, with no leftover `.relay-up-*` temp files |

---

## Part 8. Background jobs

### 8.1 Start a job and follow it

```bash
rt exec '{"node":"a","command":"for i in $(seq 1 40); do echo tick $i; sleep 1; done; echo done","background":true}'
```

✅ It returns at once: `started job j1a2b3c4 on node a`. Put that id in
`JOB`:

```bash
JOB=j1a2b3c4
rt job_logs '{"node":"a","job_id":"'$JOB'"}'
```

✅ `running`, a few `tick` lines, and `--- next_offset: N ---`. Pass that N back
as `offset` with `wait_sec`, and you get only the new lines:

```bash
rt job_logs '{"node":"a","job_id":"'$JOB'","offset":N,"wait_sec":5}'
```

### 8.2 Jobs keep running when the server restarts

While the job is still running, press **Ctrl-C on the server** (terminal 1),
wait 5 seconds, and start it again with the same command.

✅ The nodes log `link down ... reconnecting` and then `connected` again.
`rt job_logs '{"node":"a","job_id":"'$JOB'","tail":true}'` shows the ticks
continued while the server was down, and the job finishes with `exited 0` and
`done`.

### 8.3 Kill a job and its children

```bash
rt exec '{"node":"a","command":"sleep 300 & sleep 300","background":true}'
rt job_kill '{"node":"a","job_id":"<new id>"}'
pgrep -fl 'sleep 300'
```

✅ `job_kill` shows the job as `killed`, and `pgrep` finds nothing, because
the shell's background child was killed too.

`rt jobs_list '{"node":"a"}'` lists every job, running or recently finished,
with `exited 0`, `exited 5`, `killed` and so on.

---

## Part 9. Policy and approvals

### 9.1 Write a test policy

```bash
cat > ~/relay-test/policy.json <<'EOF'
{
  "default": "deny",
  "approval_timeout_sec": 60,
  "rules": [
    {"tools": ["nodes_list", "node_info", "fs_read", "fs_list", "fs_stat", "fs_glob", "fs_grep", "job_logs", "jobs_list"], "action": "allow"},
    {"tools": ["fs_write", "fs_edit", "fs_move", "fs_remove"], "paths": ["**/.git/**", "**/*.env"], "action": "deny", "reason": "secrets and git internals"},
    {"tools": ["exec"], "commands": ["(?i)\\b(rm|del|Remove-Item)\\b"], "action": "ask"},
    {"tools": ["exec"], "commands": ["^(git|echo|ls)\\b"], "action": "allow"},
    {"tools": ["fs_write", "fs_mkdir"], "action": "allow"},
    {"tools": ["exec", "fs_edit", "fs_move", "fs_remove"], "action": "ask"}
  ]
}
EOF
./relay policy check --policy ~/relay-test/policy.json
./relay policy check --policy ~/relay-test/policy.json --node a --os darwin --tool fs_write --path proj/.GIT/config
./relay policy check --policy ~/relay-test/policy.json --node a --tool exec --command "rm -rf build"
```

✅ `policy ok: 6 rules, default deny, 0 agents`, then `-> deny (rule 2):
secrets and git internals`, then `-> ask (rule 3)`.

Restart the server (terminal 1) with the policy:

```bash
./relay serve --listen 127.0.0.1:8787 --policy ~/relay-test/policy.json
```

✅ `policy .../policy.json: 6 rules, default deny, 0 named agents`.

### 9.2 Allow and deny

| # | Run | Expect |
|---|---|---|
| 9.2a | `rt exec '{"node":"a","argv":["git","--version"]}'` | runs (rule 4 allows `git`) |
| 9.2b | `rt fs_write '{"node":"a","path":"proj/.GIT/config","content":"x"}'` | `denied by policy deny (rule 2) ... secrets and git internals`. `.GIT` is caught because node `a`'s disk ignores case |
| 9.2c | `rt fs_read '{"node":"a","path":"proj/Hello.txt"}'` | allowed: the two lines |
| 9.2d | `rt exec '{"node":"a","argv":["python3","-V"]}'` | blocks: rule 6 says ask. Ctrl-C it; 9.3 does this properly |

### 9.3 Ask, then approve or deny from the CLI

Run a call that needs approval. It **blocks**, so add `&` to keep the terminal:

```bash
rt exec '{"node":"a","argv":["python3","-c","print(1)"]}' &
./relay approvals
```

✅ `3f159bf6  agent=default node=a tool=exec  ask (rule 6)  (expires ...)`
and the command. Then deny it:

```bash
./relay deny 3f159bf6 --reason "not now"
```

✅ The blocked call returns `denied by a human approver: ... — not now`.

Repeat with `./relay approve <id>` and it runs instead.

### 9.4 Approve from the web page

```bash
rt exec '{"node":"a","command":"rm -f back.txt"}' &
```

Open <http://127.0.0.1:8787/admin/> and paste `$RELAY_ADMIN_TOKEN`
(`echo $RELAY_ADMIN_TOKEN`). ✅ The request shows with **Allow**, **Allow
always** and **Deny**. Click **Allow always**: the call runs.

Run the same `rm -f back.txt` command again. ✅ It runs at once with no prompt,
because "always" covers identical calls until the server restarts. A different
command (`rm -f other.txt`) asks again.

### 9.5 Timeout

Set `"approval_timeout_sec": 5` in the policy file and save. **Don't restart.**
Within 2 s the server logs `policy_reloaded`. Run
`rt exec '{"node":"a","argv":["python3","-V"]}'` and approve nothing.

✅ After 5 s: `approval ... timed out after 5s; nobody approved it`.

### 9.6 A broken edit keeps the old policy

Add a stray `broken` anywhere in the policy file and save.

✅ The server logs `policy_reload_failed` with the JSON error, and
`rt exec '{"node":"a","argv":["git","--version"]}'` still runs under the old
rules. Fix the file and it logs `policy_reloaded`.

### 9.7 Named agents

Give a second agent (say, a CI box) its own token, with read-only rights:

```bash
CI_TOKEN=$(./relay token); echo $CI_TOKEN | ./relay hash
```

In the policy, add `"agents": [{"name": "ci", "token_sha256": "<the hash>"}],`
at the top level, and this as the **first** rule:

```json
{"agents": ["ci"], "tools": ["exec", "fs_write", "fs_edit", "fs_move", "fs_remove", "fs_mkdir"], "action": "deny", "reason": "ci is read-only"},
```

| # | Run | Expect |
|---|---|---|
| 9.7a | `RELAY_AGENT_TOKEN=$CI_TOKEN rt exec '{"node":"a","argv":["echo","hi"]}'` | `denied ... (rule 1) ... ci is read-only` |
| 9.7b | `RELAY_AGENT_TOKEN=$CI_TOKEN rt fs_list '{"node":"a"}'` | allowed |
| 9.7c | `rt exec '{"node":"a","argv":["echo","hi"]}'` | allowed: the default agent isn't affected |

### 9.8 Transfer under policy

`rt transfer '{"src_node":"a","src_path":"proj","dst_node":"b","dst_path":"copy2"}'`

✅ Allowed, because policy checks `fs_read` on every source file (rule 1) and
`fs_write` on every destination file (rule 5). Adding `"transfer"` to a rule's
`tools` is rejected on load, on purpose.

### 9.9 The audit log

```bash
tail -3 relay-audit.jsonl
```

(It's in the folder where you started the server.) ✅ One JSON line per event:
`tool_call` with agent, args, policy decision (`ask (rule 6), timed out`…),
`ok` and `ms`; plus `approval`, `node_connected`, `node_auth_failed` and
`policy_reloaded`.

---

## Part 10. With a real agent (Claude Code)

Restart the server **without** `--policy` (or keep it, and approve calls as
they come). Then register relay in Claude Code, **from a folder that isn't this
repo**, so the agent can't simply read the files locally:

```bash
mkdir -p ~/relay-test/agent && cd ~/relay-test/agent
claude mcp add --transport http relay http://127.0.0.1:8787/mcp --header "Authorization: Bearer $RELAY_AGENT_TOKEN"
claude
```

In Claude Code, `/mcp` should show `relay` connected with 17 tools. Try:

1. "Which relay nodes are connected, and what OS and shell does each have?"
2. "On node a, create `demo/app.py` that prints the first 10 primes, run it, and show the output."
3. "Copy the `demo` folder from node a to node b, and prove the copies match."
4. "On node a, start a background job that counts to 30 one second at a time, and tell me when it's done."
5. "Find every `.txt` file on node b and grep them for `line`."
6. "Delete `demo` on node b." (With the policy loaded, this one waits for your approval in `/admin/`.)

✅ The agent picks the relay tools by itself, uses `argv` or the node's shell
correctly, and verifies copies with `fs_stat` sha256. Watch each call arrive in
the server's audit output.

Remove it afterwards: `claude mcp remove relay`.

---

## Part 11. A Windows or Linux node

Same server, now reachable from the LAN. On the Mac, **terminal 1**:

```bash
ipconfig getifaddr en0                       # the Mac's LAN address
./relay serve --listen 0.0.0.0:8787
```

(If macOS asks whether `relay` may accept incoming connections, allow it.)

Build the binaries (`dist/` is not committed):

```bash
for p in windows/amd64 windows/arm64 linux/amd64 linux/arm64; do
  GOOS=${p%/*} GOARCH=${p#*/} go build -o dist/relay-${p%/*}-${p#*/}$([ ${p%/*} = windows ] && echo .exe) .
done
```

Copy the right one to the other machine, and start a node there with the
**same** `RELAY_NODE_TOKEN` (`echo $RELAY_NODE_TOKEN` on the Mac):

```powershell
# Windows (PowerShell). Use the arm64 build if $env:PROCESSOR_ARCHITECTURE is ARM64.
mkdir C:\relay-test -Force; Unblock-File .\relay-windows-amd64.exe
$env:RELAY_NODE_TOKEN = "<node token>"
.\relay-windows-amd64.exe node --server http://<mac ip>:8787 --name win --root C:\relay-test --allow-exec
```

```bash
# Linux
mkdir -p ~/relay-test && chmod +x relay-linux-amd64
RELAY_NODE_TOKEN=<node token> ./relay-linux-amd64 node --server http://<mac ip>:8787 --name linux --root ~/relay-test --allow-exec
```

Then, on the Mac (with node `a` still connected, as the transfer peer):

```bash
python3 tests/node_smoke.py --node win --peer a      # or --node linux
```

✅ `24 passed, 0 failed`. On Windows, `node_info` should show
`shell_kind: powershell`, `path_sep: \`, and `roots_case_insensitive: [true]`.
If anything fails, paste the full output.

Also worth trying by hand on Windows:
- `rt exec '{"node":"win","command":"Get-ChildItem Env: | Select -First 3"}'` (PowerShell syntax)
- `rt fs_write '{"node":"win","path":"crlf.txt","content":"a\r\nb\r\n"}'`, then
  `fs_edit` with `"old_string":"a\nb"`. It still matches, and the file keeps
  its CRLF line endings.
- `rt fs_read '{"node":"win","path":"C:/Windows/win.ini"}'`: outside the root, so refused.

This setup sends tokens over plain HTTP, so keep it to a trusted LAN.

---

## Part 12. One-command setup and services

This part uses its own `RELAY_HOME` and port, so it doesn't touch Parts 1–11
or your real `~/.relay`. Stop the server and nodes from Part 1 first, or keep
them: nothing here uses port 8787.

### 12.1 Set up a server

```bash
export RELAY_HOME=~/relay-test/home
unset RELAY_NODE_TOKEN RELAY_AGENT_TOKEN RELAY_ADMIN_TOKEN RELAY_SERVER
./relay init --listen 127.0.0.1:8790 --url http://127.0.0.1:8790
```

✅ It writes `~/relay-test/home/server/server.json` and `policy.json`, both
`-rw-------`, and prints four numbered steps: `relay serve`, a
`relay join rj1_...` line, a `claude mcp add` line, and the admin page.
Running `relay init` again refuses: `already exists ... relay invite`.

**Terminal 1:** `RELAY_HOME=~/relay-test/home ./relay serve` (no flags).

✅ `settings from .../server.json`, `policy ...: 2 rules, default ask`, and
`reachable as http://127.0.0.1:8790`.

### 12.2 Join a node

In terminal 4, copy the code from `./relay invite`, then try the mistakes first:

| # | Run | Expect |
|---|---|---|
| 12.2a | `./relay join <code>` | `give at least one --root ...` |
| 12.2b | `./relay join <code> --root ~/nope` | `--root ... is not a folder` |
| 12.2c | `./relay join rj1_garbage --root ~/relay-test/a` | `join code is damaged ...` |
| 12.2d | `./relay join <code> --root ~/relay-test/a --name mac --allow-exec` | `checking http://127.0.0.1:8790 ... ok`, `saved .../node.json`, then the node runs: `connected as "mac"` |

Stop the server (Ctrl-C) and run 12.2d again. ✅ `cannot reach the server
at ...`: nothing is saved. Start the server again.

### 12.3 Use it with no environment variables

With the node from 12.2d running, in another terminal:

```bash
export RELAY_HOME=~/relay-test/home
AT=$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/relay-test/home/server/server.json')))['agent-token'])")
RELAY_SERVER=http://127.0.0.1:8790 RELAY_AGENT_TOKEN=$AT python3 tests/mcp.py exec '{"node":"mac","argv":["echo","hi"]}' &
./relay approvals
```

✅ The call waits (`ask (default)`), and `relay approvals` lists it with no
token or URL set: it reads them from the server's settings. `./relay approve
<id>` lets it run. A write to `x/.git/config` is denied by the preset's rule 2.

### 12.4 Run the node as a service

Stop the foreground node (Ctrl-C), then:

```bash
./relay service install
```

✅ `installed ghostrelay-node-mac: running, pid N`, the settings and log
paths, and the last log lines ending in `connected as "mac"`. Then:

| # | Run | Expect |
|---|---|---|
| 12.4a | `./relay service status` | `ghostrelay-node-mac: running, pid N` |
| 12.4b | `./relay service logs -n 5` | the node's last log lines |
| 12.4c | `kill <pid>`, wait 10 s, `./relay service status` | running again, with a new pid (macOS restarts it within 10 s, Linux within 5 s, Windows within a minute) |
| 12.4d | `ls ~/relay-test/home/bin` | a copy of `relay`: the service doesn't depend on the file you downloaded |
| 12.4e | log out and back in (or reboot), then `./relay service status` | running |
| 12.4f | `./relay service uninstall`, then `./relay service status` | `removed ghostrelay-node-mac ...`, then `not installed` |

Where it lives: macOS `~/Library/LaunchAgents/dev.ghostrelay.node.mac.plist`;
Linux `~/.config/systemd/user/ghostrelay-node-mac.service`; Windows Task
Scheduler, task `ghostrelay-node-mac`. On Windows the console window flashes
once at logon and closes; the node keeps running in the background.

The server can be a service too: `./relay service install server` (and
`status server`, `logs server`, `uninstall server`).

**Unset `RELAY_HOME`** when you're done with this part, or later commands keep
using the test settings.

---

## Cleanup

Ctrl-C the server and the nodes, then:

```bash
./relay service uninstall 2>/dev/null; ./relay service uninstall server 2>/dev/null   # with RELAY_HOME still set, if you ran Part 12
rm -rf ~/relay-test
rm -f relay-audit.jsonl                      # in the folder you ran the server from
claude mcp remove relay 2>/dev/null
```

Node job logs live in the user cache dir (`~/Library/Caches/relay-node/` on
macOS, `~/.cache/relay-node/` on Linux, `%LocalAppData%\relay-node\` on
Windows). Delete that folder too if you like.
