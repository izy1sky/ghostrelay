#!/usr/bin/env python3
"""Call one relay tool from the command line, the way an agent would.

  python3 tests/mcp.py <tool> ['<json arguments>']
  python3 tests/mcp.py nodes_list
  python3 tests/mcp.py exec '{"node": "a", "argv": ["git", "--version"]}'
  python3 tests/mcp.py --list            # tools/list: names only

Reads RELAY_AGENT_TOKEN, and RELAY_SERVER (default http://127.0.0.1:8787).
Prints the tool's text result. Exit status: 0 ok, 1 tool error, 2 HTTP or
JSON-RPC error. Works the same on macOS, Linux and Windows.
"""

import json
import os
import sys
import urllib.error
import urllib.request


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    server = os.environ.get("RELAY_SERVER", "http://127.0.0.1:8787").rstrip("/")
    token = os.environ.get("RELAY_AGENT_TOKEN", "")
    if sys.argv[1] == "--list":
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    else:
        args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": sys.argv[1], "arguments": args}}
    req = urllib.request.Request(server + "/mcp", data=json.dumps(msg).encode(), headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=900) as r:
            resp = json.load(r)
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode().strip()}")
        sys.exit(2)
    except urllib.error.URLError as e:
        print(f"cannot reach {server}: {e.reason}")
        sys.exit(2)
    if "error" in resp:
        print("rpc error:", resp["error"].get("message"))
        sys.exit(2)
    res = resp["result"]
    if sys.argv[1] == "--list":
        print("\n".join(t["name"] for t in res["tools"]))
        return
    for c in res.get("content", []):
        print(c.get("text", ""))
    if res.get("isError"):
        print("[tool error]")
        sys.exit(1)


if __name__ == "__main__":
    main()
