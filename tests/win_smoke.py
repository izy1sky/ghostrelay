#!/usr/bin/env python3
"""Smoke test for a Windows relay node, run from the agent machine (the Mac).

Setup (see the README section "Testing a Windows node"):
  - relay serve running, reachable from the Windows box
  - a Windows node named "win" with --allow-exec
  - a Mac node named "mac" with --allow-exec, whose first --root is MAC_ROOT
  - no --policy on the server (or one that allows everything)

Usage:
  RELAY_AGENT_TOKEN=... python3 tests/win_smoke.py --mac-root ~/relay-test
  [--server http://127.0.0.1:8787] [--win win] [--mac mac]

Prints PASS / FAIL / INFO per check. Paste the whole output back.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
import time
import urllib.request

results = []


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


def ps(cmd, **kw):
    """Run a command on the Windows node; return (ok, exit_code, stdout, stderr, raw)."""
    ok, text = call("exec", node=WIN, command=cmd, **kw)
    if not ok:
        return False, None, "", "", text
    m = re.match(r"exit_code: (-?\d+)", text)
    out = re.search(r"--- stdout ---\n(.*?)(?=\n--- stderr ---|\[stdout truncated\]|\Z)", text, re.S)
    err = re.search(r"--- stderr ---\n(.*?)(?=\[stderr truncated\]|\Z)", text, re.S)
    return (True, int(m.group(1)) if m else None,
            out.group(1).strip() if out else "", err.group(1).strip() if err else "", text)


def check(name, info=False):
    def wrap(fn):
        t0 = time.time()
        try:
            ok, detail = fn()
        except Exception as e:  # keep going; report the crash as a failure
            ok, detail = False, f"{type(e).__name__}: {e}"
        status = ("INFO" if info else "PASS") if ok else ("INFO" if info else "FAIL")
        results.append((status, name))
        line = f"{status:4}  {name}  ({time.time() - t0:.1f}s)"
        if detail and (not ok or info):
            line += "\n      " + str(detail).strip().replace("\n", "\n      ")[:1500]
        print(line, flush=True)
        return fn
    return wrap


def job_until_done(job_id, limit=60):
    off, out, text = 0, "", ""
    deadline = time.time() + limit
    while time.time() < deadline:
        ok, text = call("job_logs", node=WIN, job_id=job_id, offset=off, wait_sec=10)
        if not ok:
            return False, out, text
        body = re.search(r"--- output bytes \d+-\d+ of \d+ ---\n(.*)\n--- next_offset: (\d+)", text, re.S)
        if body:
            out += body.group(1)
            off = int(body.group(2))
        if "this is the end" in text:
            return True, out, text
    return False, out, text


def ping_count(n):
    _, _, out, _, _ = ps(f"@(Get-CimInstance Win32_Process -Filter \"Name='PING.EXE'\" | "
                         f"Where-Object {{ $_.CommandLine -like '*-n {n} *' }}).Count")
    return out


def main():
    global SERVER, TOKEN, WIN
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default=os.environ.get("RELAY_SERVER", "http://127.0.0.1:8787"))
    ap.add_argument("--win", default="win")
    ap.add_argument("--mac", default="mac")
    ap.add_argument("--mac-root", required=True, help="first --root of the Mac node")
    a = ap.parse_args()
    SERVER, WIN, mac = a.server.rstrip("/"), a.win, a.mac
    TOKEN = os.environ.get("RELAY_AGENT_TOKEN", "")
    if not TOKEN:
        sys.exit("set RELAY_AGENT_TOKEN")
    mac_root = os.path.realpath(os.path.expanduser(a.mac_root))
    local = os.path.join(mac_root, "relay-smoke")
    shutil.rmtree(local, ignore_errors=True)
    os.makedirs(local)

    @check("nodes connected")
    def _():
        ok, text = call("nodes_list")
        names = [l.split("\t")[0] for l in text.splitlines()]
        return ok and WIN in names and mac in names, text

    @check("node_info: OS, shell, version, probed tools", info=True)
    def _():
        ok, text = call("node_info", node=WIN)
        info = json.loads(text) if ok else {}
        return info.get("os") == "windows", (
            f"os={info.get('os')} arch={info.get('arch')} version={info.get('version')} shell={info.get('shell')}\n"
            f"roots={info.get('roots')} tools={sorted((info.get('tools') or {}).keys())}") if ok else text

    ps("Remove-Item -Recurse -Force smoke -ErrorAction SilentlyContinue; "
       "New-Item -ItemType Directory -Force smoke | Out-Null")

    @check("exec: PowerShell runs, UTF-8 output (hello 世界)")
    def _():
        ok, code, out, err, raw = ps('Write-Output "hello 世界"')
        return ok and code == 0 and out == "hello 世界", raw

    @check("exec: exit codes (exit 3 / native cmd /c exit 7)")
    def _():
        _, c1, _, _, r1 = ps("exit 3")
        _, c2, _, _, r2 = ps("cmd /c exit 7")
        return c1 == 3 and c2 == 7, f"exit 3 -> {c1}; cmd /c exit 7 -> {c2}\n{r1}\n{r2}"

    @check("exec: stderr captured separately")
    def _():
        ok, code, out, err, raw = ps('Write-Output out; [Console]::Error.WriteLine("oops")')
        return ok and out == "out" and "oops" in err, raw

    @check("exec: native program output with Chinese (cmd /c echo 中文)", info=True)
    def _():
        ok, code, out, err, raw = ps("cmd /c echo 中文")
        return ok and out == "中文", f"got {out!r} (if garbled, native output is in the console code page, e.g. GBK)"

    @check("exec: python output with Chinese", info=True)
    def _():
        ok, code, out, err, raw = ps("python -c \"print('中文')\"")
        if code != 0:
            return False, "python not available or failed:\n" + raw
        return out == "中文", f"got {out!r}"

    @check("exec: timeout kills the whole process tree (taskkill /T)")
    def _():
        ok, code, out, err, raw = ps("Start-Process -NoNewWindow ping -ArgumentList '-n','101','127.0.0.1'; "
                                     "ping -n 101 127.0.0.1 | Out-Null", timeout_sec=3)
        time.sleep(1.5)
        left = ping_count(101)
        return "[timed out" in raw and left == "0", f"ping -n 101 still running: {left}\n{raw}"

    @check("exec: cwd with spaces and Chinese")
    def _():
        ps('New-Item -ItemType Directory -Force "smoke\\dir with space\\中文" | Out-Null')
        ok, code, out, err, raw = ps("(Get-Location).Path", cwd="smoke/dir with space/中文")
        return ok and out.endswith("dir with space\\中文"), raw

    @check("jail: C:\\Windows\\win.ini and ..\\..\\ are refused")
    def _():
        ok1, t1 = call("fs_read", node=WIN, path="C:\\Windows\\win.ini")
        ok2, t2 = call("fs_read", node=WIN, path="..\\..\\..\\Windows\\win.ini")
        ok3, _, _, _, t3 = ps("Get-Location", cwd="C:\\Windows")
        return (not ok1 and "outside" in t1 and not ok2 and "outside" in t2 and not ok3 and "outside" in t3), f"{t1}\n{t2}\n{t3}"

    @check("fs: write/read with backslash and mixed-case paths")
    def _():
        ok, t = call("fs_write", node=WIN, path="smoke\\Notes.TXT", content="line1\nline2\n")
        ok2, t2 = call("fs_read", node=WIN, path="SMOKE/notes.txt")
        return ok and ok2 and "line2" in t2, f"{t}\n{t2}"

    @check("fs_edit on a CRLF file keeps CRLF")
    def _():
        call("fs_write", node=WIN, path="smoke/crlf.txt", content="a\r\nb\r\nc\r\n")
        ok, t = call("fs_edit", node=WIN, path="smoke/crlf.txt", old_string="b\nc", new_string="B\nC")
        _, _, out, _, raw = ps('if ([IO.File]::ReadAllText((Join-Path (Get-Location) "smoke\\crlf.txt")) '
                               '-eq "a`r`nB`r`nC`r`n") { "True" } else { "False" }')
        ok3, t3 = call("fs_read", node=WIN, path="smoke/crlf.txt")
        return ok and out == "True" and "CRLF" in t3, f"{t}\n{raw}\n{t3}"

    @check("fs_list")
    def _():
        ok, t = call("fs_list", node=WIN, path="smoke")
        return ok and "crlf.txt" in t and "dir with space/" in t, t

    @check("job: background job, followed by offset to the end, exit 0")
    def _():
        ok, t = call("exec", node=WIN, background=True,
                     command='1..4 | ForEach-Object { "tick $_"; Start-Sleep 1 }; "done 完成"')
        m = re.search(r"started job (\S+)", t)
        if not ok or not m:
            return False, t
        done, out, last = job_until_done(m.group(1))
        return done and "tick 4" in out and "done 完成" in out and " exited 0 " in last, f"{out!r}\n{last}"

    @check("job: exit code of a background job (exit 5)")
    def _():
        ok, t = call("exec", node=WIN, background=True, command="Start-Sleep 1; exit 5")
        m = re.search(r"started job (\S+)", t)
        done, out, last = job_until_done(m.group(1)) if m else (False, "", t)
        return done and " exited 5 " in last, last

    @check("job: job_kill stops the job and its children")
    def _():
        ok, t = call("exec", node=WIN, background=True, command="ping -n 201 127.0.0.1")
        m = re.search(r"started job (\S+)", t)
        if not m:
            return False, t
        time.sleep(1.5)
        before = ping_count(201)
        ok, k = call("job_kill", node=WIN, job_id=m.group(1))
        time.sleep(1)
        after = ping_count(201)
        return ok and "killed" in k and before == "1" and after == "0", f"ping before={before} after={after}\n{k}"

    @check("transfer: 20 MiB binary mac -> win, sha256 matches")
    def _():
        data = secrets.token_bytes(20 << 20)
        with open(os.path.join(local, "big.bin"), "wb") as f:
            f.write(data)
        ok, t = call("transfer", src_node=mac, src_path="relay-smoke/big.bin",
                     dst_node=WIN, dst_path="smoke/big.bin", overwrite=True)
        _, _, out, _, raw = ps("(Get-FileHash smoke\\big.bin -Algorithm SHA256).Hash.ToLower()")
        want = hashlib.sha256(data).hexdigest()
        return ok and out == want, f"{t}\nwindows sha256={out}\nmac sha256={want}"

    @check("transfer: directory win -> mac, with Chinese file names and binary")
    def _():
        ps('New-Item -ItemType Directory -Force smoke\\tree\\sub | Out-Null; '
           '[IO.File]::WriteAllText((Join-Path (Get-Location) "smoke\\tree\\中文.txt"), "你好"); '
           '[IO.File]::WriteAllText((Join-Path (Get-Location) "smoke\\tree\\a.txt"), "a"); '
           '[IO.File]::WriteAllBytes((Join-Path (Get-Location) "smoke\\tree\\sub\\b.bin"), [byte[]](0,1,2,255))')
        ok, t = call("transfer", src_node=WIN, src_path="smoke/tree", dst_node=mac, dst_path="relay-smoke/from-win")
        base = os.path.join(local, "from-win")
        try:
            zh = open(os.path.join(base, "中文.txt"), encoding="utf-8").read()
            b = open(os.path.join(base, "sub", "b.bin"), "rb").read()
        except OSError as e:
            return False, f"{t}\n{e}"
        return ok and zh == "你好" and b == bytes([0, 1, 2, 255]), f"{t}\n中文.txt={zh!r} b.bin={b!r}"

    @check("transfer: refuses to overwrite without overwrite=true")
    def _():
        ok, t = call("transfer", src_node=mac, src_path="relay-smoke/big.bin", dst_node=WIN, dst_path="smoke/big.bin")
        return not ok and "already exists" in t, t

    fails = [n for s, n in results if s == "FAIL"]
    print(f"\n{len(results) - len(fails)} of {len(results)} passed or informational; {len(fails)} failed")
    for n in fails:
        print("  FAIL:", n)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
