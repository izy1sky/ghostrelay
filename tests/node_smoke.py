#!/usr/bin/env python3
"""End-to-end smoke test for one relay node, on any OS.

It asks the node what it is (node_info: OS, shell_kind, path separator,
case sensitivity of its root) and picks shell snippets to match. Everything
else goes through the OS-neutral tools, so the same checks run on macOS,
Linux and Windows. With --peer it also tests transfer in both directions.

Usage (needs only a running server and nodes; no policy, or one that allows all):
  RELAY_AGENT_TOKEN=... python3 tests/node_smoke.py --node win --peer mac
  [--server http://127.0.0.1:8787]

Prints PASS / FAIL / INFO / SKIP per check. Paste the whole output back.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.request

SERVER = TOKEN = NODE = ""
results = []

# Shell snippets per shell_kind. "posix" covers bash and sh.
SNIP = {
    "echo_utf8": {"powershell": 'Write-Output "hello 世界"', "posix": 'echo "hello 世界"'},
    "exit3": {"powershell": "exit 3", "posix": "exit 3"},
    "stderr": {"powershell": 'Write-Output out; [Console]::Error.WriteLine("oops")', "posix": "echo out; echo oops >&2"},
    "pwd": {"powershell": "(Get-Location).Path", "posix": "pwd"},
    # Starts a child that outlives the shell unless the whole tree is killed.
    "tree_101": {"powershell": "Start-Process -NoNewWindow ping -ArgumentList '-n','101','127.0.0.1'; ping -n 101 127.0.0.1 | Out-Null",
                 "posix": "sleep 101 & sleep 101"},
    "count_101": {"powershell": "@(Get-CimInstance Win32_Process -Filter \"Name='PING.EXE'\" | Where-Object { $_.CommandLine -like '*-n 101 *' }).Count",
                  "posix": "pgrep -f 'sleep 10[1]' | wc -l | tr -d ' '"},
    "tree_201": {"powershell": "ping -n 201 127.0.0.1", "posix": "sleep 201 & sleep 201"},
    "count_201": {"powershell": "@(Get-CimInstance Win32_Process -Filter \"Name='PING.EXE'\" | Where-Object { $_.CommandLine -like '*-n 201 *' }).Count",
                  "posix": "pgrep -f 'sleep 20[1]' | wc -l | tr -d ' '"},
    "job_loop": {"powershell": '1..4 | ForEach-Object { "tick $_"; Start-Sleep 1 }; "done 完成"',
                 "posix": 'for i in 1 2 3 4; do echo "tick $i"; sleep 1; done; echo "done 完成"'},
    "job_exit5": {"powershell": "Start-Sleep 1; exit 5", "posix": "sleep 1; exit 5"},
    "big_binary": {"powershell": '$b = New-Object byte[] (20MB); (New-Object Random 42).NextBytes($b); '
                                 '[IO.File]::WriteAllBytes((Join-Path (Get-Location) "smoke/big.bin"), $b)',
                   "posix": "head -c 20971520 /dev/urandom > smoke/big.bin"},
    "small_binary": {"powershell": '[IO.File]::WriteAllBytes((Join-Path (Get-Location) "smoke/tree/sub/b.bin"), [byte[]](0,1,2,255))',
                     "posix": r"printf '\000\001\002\377' > smoke/tree/sub/b.bin"},
}
ARGV = {
    "exit7": {"windows": ["cmd", "/c", "exit", "7"], "other": ["sh", "-c", "exit 7"]},
}


def call(tool, **args):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": tool, "arguments": args}}).encode()
    req = urllib.request.Request(SERVER + "/mcp", data=body, headers={
        "Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        resp = json.load(r)
    if "error" in resp:
        return False, "rpc error: " + resp["error"]["message"]
    res = resp["result"]
    return not res.get("isError"), res["content"][0]["text"]


def parse_exec(text):
    m = re.match(r"exit_code: (-?\d+)", text)
    out = re.search(r"--- stdout ---\n(.*?)(?=\n--- stderr ---|\[stdout truncated\]|\Z)", text, re.S)
    err = re.search(r"--- stderr ---\n(.*?)(?=\[stderr truncated\]|\Z)", text, re.S)
    return (int(m.group(1)) if m else None, out.group(1).strip() if out else "", err.group(1).strip() if err else "")


class Node:
    def __init__(self, name):
        self.name = name
        ok, text = call("node_info", node=name)
        if not ok:
            sys.exit(f"node_info({name}) failed: {text}")
        self.info = json.loads(text)
        self.os = self.info.get("os", "")
        self.kind = "powershell" if self.info.get("shell_kind") == "powershell" else "posix"
        self.sep = self.info.get("path_sep") or ("\\" if self.os == "windows" else "/")
        ci = self.info.get("roots_case_insensitive")
        self.case_insensitive = ci[0] if ci else None

    def sh(self, key, **kw):
        ok, text = call("exec", node=self.name, command=SNIP[key][self.kind], **kw)
        code, out, err = parse_exec(text) if ok else (None, "", "")
        return ok, code, out, err, text

    def argv(self, argv, **kw):
        ok, text = call("exec", node=self.name, argv=argv, **kw)
        code, out, err = parse_exec(text) if ok else (None, "", "")
        return ok, code, out, err, text

    def sha(self, path):
        ok, text = call("fs_stat", node=self.name, path=path, sha256=True)
        m = re.search(r"sha256 ([0-9a-f]{64})", text)
        return m.group(1) if ok and m else text


def check(name, info=False):
    def wrap(fn):
        t0 = time.time()
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {e}"
        if ok is None:
            status = "SKIP"
        elif info:
            status = "INFO"
        else:
            status = "PASS" if ok else "FAIL"
        results.append((status, name))
        line = f"{status:4}  {name}  ({time.time() - t0:.1f}s)"
        if detail and (status in ("FAIL", "INFO", "SKIP")):
            line += "\n      " + str(detail).strip().replace("\n", "\n      ")[:1500]
        print(line, flush=True)
        return fn
    return wrap


def job_until_done(node, job_id, limit=60):
    off, out, text = 0, "", ""
    deadline = time.time() + limit
    while time.time() < deadline:
        ok, text = call("job_logs", node=node, job_id=job_id, offset=off, wait_sec=10)
        if not ok:
            return False, out, text
        body = re.search(r"--- output bytes \d+-\d+ of \d+ ---\n(.*)\n--- next_offset: (\d+)", text, re.S)
        if body:
            out += body.group(1)
            off = int(body.group(2))
        if "this is the end" in text:
            return True, out, text
    return False, out, text


def main():
    global SERVER, TOKEN, NODE
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default=os.environ.get("RELAY_SERVER", "http://127.0.0.1:8787"))
    ap.add_argument("--node", required=True, help="node to test")
    ap.add_argument("--peer", help="second node, for transfer tests in both directions")
    a = ap.parse_args()
    SERVER, NODE = a.server.rstrip("/"), a.node
    TOKEN = os.environ.get("RELAY_AGENT_TOKEN", "")
    if not TOKEN:
        sys.exit("set RELAY_AGENT_TOKEN")

    n = Node(NODE)
    peer = Node(a.peer) if a.peer else None
    win = n.os == "windows"
    print(f"node {n.name}: {n.os}/{n.info.get('arch')} shell={n.info.get('shell_kind')} ({n.info.get('shell')}) "
          f"sep={n.sep!r} root={n.info['roots'][0]} case_insensitive={n.case_insensitive} version={n.info.get('version')}")
    if peer:
        print(f"peer {peer.name}: {peer.os}/{peer.info.get('arch')} shell={peer.info.get('shell_kind')} "
              f"case_insensitive={peer.case_insensitive}")
    print()

    call("fs_remove", node=NODE, path="smoke", recursive=True)
    call("fs_mkdir", node=NODE, path="smoke")
    peer_dir = f"smoke-from-{NODE}"
    if peer:
        call("fs_remove", node=peer.name, path=peer_dir, recursive=True)

    @check("node reports a v0.5+ system probe (shell_kind, path_sep, case sensitivity)")
    def _():
        return n.info.get("shell_kind") in ("powershell", "bash", "sh") and n.case_insensitive is not None, n.info

    @check("probe agrees with the filesystem (mixed-case read)")
    def _():
        call("fs_write", node=NODE, path="smoke/sub/Notes.TXT", content="line1\nline2\n")
        ok, t = call("fs_read", node=NODE, path="SMOKE/SUB/notes.txt")
        return ok == bool(n.case_insensitive), f"case_insensitive={n.case_insensitive}, mixed-case read ok={ok}\n{t}"

    # ---- exec ------------------------------------------------------------
    @check("exec argv: hostname matches node_info, exit code 0")
    def _():
        ok, code, out, err, raw = n.argv(["hostname"])
        return ok and code == 0 and out.lower().split(".")[0] == n.info["hostname"].lower().split(".")[0], raw

    @check("exec argv: program's own exit code (7)")
    def _():
        ok, code, out, err, raw = n.argv(ARGV["exit7"]["windows" if win else "other"])
        return code == 7, raw

    @check("exec argv: arguments reach the program verbatim (no shell)")
    def _():
        if win:
            return None, "no portable echo-like program on Windows; covered by the argv exit-code check"
        ok, code, out, err, raw = n.argv(["printf", "%s|", "a b", "$HOME", "中文"])
        return out == "a b|$HOME|中文|", raw

    @check("exec argv: a missing program is a clear error")
    def _():
        ok, t = call("exec", node=NODE, argv=["no-such-program-xyz"])
        return not ok and ("not found" in t or "cannot find" in t.lower()), t

    @check("exec shell: UTF-8 output (hello 世界)")
    def _():
        ok, code, out, err, raw = n.sh("echo_utf8")
        return ok and code == 0 and out == "hello 世界", raw

    @check("exec shell: exit code 3")
    def _():
        ok, code, out, err, raw = n.sh("exit3")
        return code == 3, raw

    @check("exec shell: stderr captured separately")
    def _():
        ok, code, out, err, raw = n.sh("stderr")
        return ok and out == "out" and "oops" in err, raw

    @check("exec: timeout kills the whole process tree")
    def _():
        ok, code, out, err, raw = n.sh("tree_101", timeout_sec=3)
        time.sleep(1.5)
        _, _, left, _, _ = n.sh("count_101")
        return "[timed out" in raw and left == "0", f"left running: {left}\n{raw}"

    @check("exec: cwd with spaces and Chinese (created with fs_mkdir)")
    def _():
        call("fs_mkdir", node=NODE, path="smoke/dir with space/中文")
        ok, code, out, err, raw = n.sh("pwd", cwd="smoke/dir with space/中文")
        return ok and out.endswith("dir with space" + n.sep + "中文"), raw

    if win:
        @check("exec: native program printing Chinese (cmd /c echo 中文)", info=True)
        def _():
            ok, t = call("exec", node=NODE, command="cmd /c echo 中文")
            code, out, err = parse_exec(t)
            return out == "中文", f"got {out!r} (garbled means the console code page, e.g. GBK, not UTF-8)"

    if "python" in (n.info.get("tools") or {}) or "python3" in (n.info.get("tools") or {}):
        @check("exec: python printing Chinese", info=True)
        def _():
            py = "python" if "python" in n.info["tools"] else "python3"
            ok, code, out, err, raw = n.argv([py, "-c", "print('中文')"])
            return out == "中文", f"got {out!r}"

    # ---- jail ------------------------------------------------------------
    @check("jail: absolute path outside the root, ../ escape, and cwd outside are refused")
    def _():
        outside = "C:\\Windows\\win.ini" if win else "/etc/hosts"
        ok1, t1 = call("fs_read", node=NODE, path=outside)
        ok2, t2 = call("fs_read", node=NODE, path="../../../../outside.txt")
        ok3, t3 = call("exec", node=NODE, argv=["hostname"], cwd="C:\\Windows" if win else "/")
        return not (ok1 or ok2 or ok3) and all("outside" in t for t in (t1, t2, t3)), f"{t1}\n{t2}\n{t3}"

    # ---- OS-neutral fs tools ----------------------------------------------
    @check("fs_edit on a CRLF file keeps CRLF (checked by sha256)")
    def _():
        call("fs_write", node=NODE, path="smoke/crlf.txt", content="a\r\nb\r\nc\r\n")
        ok, t = call("fs_edit", node=NODE, path="smoke/crlf.txt", old_string="b\nc", new_string="B\nC")
        want = hashlib.sha256(b"a\r\nB\r\nC\r\n").hexdigest()
        return ok and n.sha("smoke/crlf.txt") == want, t

    @check("fs_mkdir / fs_move / fs_glob / fs_grep / fs_remove")
    def _():
        call("fs_write", node=NODE, path="smoke/m/x.txt", content="needle here\n")
        ok1, t1 = call("fs_move", node=NODE, src="smoke/m/x.txt", dst="smoke/m2/y.txt")
        ok2, t2 = call("fs_glob", node=NODE, path="smoke", pattern="**/*.txt")
        ok3, t3 = call("fs_grep", node=NODE, path="smoke", pattern="needle")
        ok4, t4 = call("fs_remove", node=NODE, path="smoke/m2", recursive=True)
        ok5, t5 = call("fs_stat", node=NODE, path="smoke/m2")
        good = (ok1 and ok2 and "m2/y.txt" in t2 and "m/x.txt" not in t2 and ok3 and "m2/y.txt:1: needle here" in t3
                and ok4 and ok5 and "does not exist" in t5)
        return good, "\n".join((t1, t2, t3, t4, t5))

    @check("fs_move: case-only rename")
    def _():
        call("fs_write", node=NODE, path="smoke/case.txt", content="x")
        ok, t = call("fs_move", node=NODE, src="smoke/case.txt", dst="smoke/CASE.txt")
        ok2, t2 = call("fs_glob", node=NODE, path="smoke", pattern="CASE.txt")
        return ok and "CASE.txt" in t2, f"{t}\n{t2}"

    @check("fs_remove refuses a non-empty directory without recursive")
    def _():
        call("fs_write", node=NODE, path="smoke/full/f.txt", content="x")
        ok, t = call("fs_remove", node=NODE, path="smoke/full")
        return not ok and "recursive" in t, t

    # ---- jobs --------------------------------------------------------------
    @check("job: background job followed by offset to the end, exit 0")
    def _():
        ok, t = call("exec", node=NODE, background=True, command=SNIP["job_loop"][n.kind])
        m = re.search(r"started job (\S+)", t)
        if not ok or not m:
            return False, t
        done, out, last = job_until_done(NODE, m.group(1))
        return done and "tick 4" in out and "done 完成" in out and " exited 0 " in last, f"{out!r}\n{last}"

    @check("job: background job exit code (5)")
    def _():
        ok, t = call("exec", node=NODE, background=True, command=SNIP["job_exit5"][n.kind])
        m = re.search(r"started job (\S+)", t)
        done, out, last = job_until_done(NODE, m.group(1)) if m else (False, "", t)
        return done and " exited 5 " in last, last

    @check("job: argv background job")
    def _():
        ok, t = call("exec", node=NODE, background=True, argv=["hostname"])
        m = re.search(r"started job (\S+)", t)
        done, out, last = job_until_done(NODE, m.group(1)) if m else (False, "", t)
        return done and " exited 0 " in last and out.strip() != "", last

    @check("job: job_kill stops the job and its children")
    def _():
        ok, t = call("exec", node=NODE, background=True, command=SNIP["tree_201"][n.kind])
        m = re.search(r"started job (\S+)", t)
        if not m:
            return False, t
        time.sleep(1.5)
        _, _, before, _, _ = n.sh("count_201")
        ok, k = call("job_kill", node=NODE, job_id=m.group(1))
        time.sleep(1)
        _, _, after, _, _ = n.sh("count_201")
        return ok and "killed" in k and before not in ("", "0") and after == "0", f"before={before} after={after}\n{k}"

    # ---- transfer ----------------------------------------------------------
    if not peer:
        print("SKIP  transfer checks (no --peer)")
    else:
        @check(f"transfer: 20 MiB binary {NODE} -> {peer.name}, sha256 matches")
        def _():
            ok, code, out, err, raw = n.sh("big_binary")
            if code != 0:
                return False, raw
            ok, t = call("transfer", src_node=NODE, src_path="smoke/big.bin",
                         dst_node=peer.name, dst_path=f"{peer_dir}/big.bin", overwrite=True)
            a, b = n.sha("smoke/big.bin"), peer.sha(f"{peer_dir}/big.bin")
            return ok and a == b, f"{t}\n{NODE} sha256={a}\n{peer.name} sha256={b}"

        @check(f"transfer: back {peer.name} -> {NODE}, sha256 matches")
        def _():
            ok, t = call("transfer", src_node=peer.name, src_path=f"{peer_dir}/big.bin",
                         dst_node=NODE, dst_path="smoke/back.bin", overwrite=True)
            return ok and n.sha("smoke/back.bin") == n.sha("smoke/big.bin"), t

        @check(f"transfer: directory with Chinese names and binary {NODE} -> {peer.name}")
        def _():
            call("fs_write", node=NODE, path="smoke/tree/中文.txt", content="你好")
            call("fs_write", node=NODE, path="smoke/tree/a.txt", content="a")
            call("fs_mkdir", node=NODE, path="smoke/tree/sub")
            _, code, _, _, raw = n.sh("small_binary")
            if code != 0:
                return False, raw
            ok, t = call("transfer", src_node=NODE, src_path="smoke/tree", dst_node=peer.name, dst_path=f"{peer_dir}/tree")
            files = ["中文.txt", "a.txt", "sub/b.bin"]
            diffs = [f for f in files if n.sha(f"smoke/tree/{f}") != peer.sha(f"{peer_dir}/tree/{f}")]
            want_bin = hashlib.sha256(bytes([0, 1, 2, 255])).hexdigest()
            return ok and not diffs and peer.sha(f"{peer_dir}/tree/sub/b.bin") == want_bin, f"{t}\ndiffering: {diffs}"

        @check("transfer: refuses to overwrite without overwrite=true")
        def _():
            ok, t = call("transfer", src_node=NODE, src_path="smoke/big.bin", dst_node=peer.name, dst_path=f"{peer_dir}/big.bin")
            return not ok and "already exists" in t, t

    fails = [x for s, x in results if s == "FAIL"]
    print(f"\n{sum(s == 'PASS' for s, _ in results)} passed, {len(fails)} failed, "
          f"{sum(s == 'INFO' for s, _ in results)} info, {sum(s == 'SKIP' for s, _ in results)} skipped")
    for x in fails:
        print("  FAIL:", x)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
