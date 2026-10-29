#!/usr/bin/env python3
"""End-to-end test of the one-command setup, on any OS.

  python3 tests/e2e.py ./relay            (relay.exe on Windows)

In a temporary RELAY_HOME it runs what a user would: relay init, relay serve
with no arguments, relay join twice (nodes a and b), then tests/node_smoke.py
against them. Everything is stopped and removed afterwards. CI runs this on
Linux and Windows; it needs nothing else running.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    relay = os.path.abspath(sys.argv[1])
    home = tempfile.mkdtemp(prefix="relay-e2e-")
    env = dict(os.environ, RELAY_HOME=os.path.join(home, "home"), PYTHONUTF8="1")
    for k in ("RELAY_NODE_TOKEN", "RELAY_AGENT_TOKEN", "RELAY_ADMIN_TOKEN", "RELAY_SERVER"):
        env.pop(k, None)
    port = free_port()
    url = f"http://127.0.0.1:{port}"
    procs = []

    def start(name, *args):
        log = open(os.path.join(home, name + ".log"), "w", encoding="utf-8")
        p = subprocess.Popen([relay, *args], env=env, stdout=log, stderr=subprocess.STDOUT)
        procs.append((name, p))
        return p

    try:
        out = subprocess.run([relay, "init", "--listen", f"127.0.0.1:{port}", "--url", url, "--policy", "open"],
                             env=env, capture_output=True, text=True, encoding="utf-8")
        print(out.stdout + out.stderr)
        if out.returncode != 0:
            sys.exit("relay init failed")
        code = re.search(r"rj1_[A-Za-z0-9_-]+", out.stdout).group(0)
        with open(os.path.join(env["RELAY_HOME"], "server", "server.json"), encoding="utf-8") as f:
            agent_token = json.load(f)["agent-token"]

        start("server", "serve")
        for _ in range(50):
            try:
                urllib.request.urlopen(url + "/healthz", timeout=1)
                break
            except OSError:
                time.sleep(0.2)
        else:
            sys.exit("server did not start")

        for name in ("a", "b"):
            root = os.path.join(home, "roots", name)
            os.makedirs(root)
            start("node-" + name, "join", code, "--name", name, "--root", root, "--allow-exec",
                  "--config", os.path.join(env["RELAY_HOME"], name + ".json"))

        env_agent = dict(env, RELAY_AGENT_TOKEN=agent_token, RELAY_SERVER=url)
        for _ in range(50):
            res = subprocess.run([sys.executable, os.path.join(HERE, "mcp.py"), "nodes_list"],
                                 env=env_agent, capture_output=True, text=True, encoding="utf-8")
            if res.stdout.count("\n") >= 2 and "a\t" in res.stdout and "b\t" in res.stdout:
                break
            time.sleep(0.2)
        else:
            sys.exit("nodes did not connect:\n" + res.stdout + res.stderr)
        print("nodes connected:\n" + res.stdout)

        smoke = subprocess.run([sys.executable, os.path.join(HERE, "node_smoke.py"), "--server", url,
                                "--node", "a", "--peer", "b"], env=env_agent)
        sys.exit(smoke.returncode)
    finally:
        for name, p in reversed(procs):
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        for name, _ in procs:
            with open(os.path.join(home, name + ".log"), encoding="utf-8", errors="replace") as f:
                text = f.read()
            print(f"--- {name} log (last 15 lines) ---")
            print("\n".join(text.splitlines()[-15:]))
        shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    main()
