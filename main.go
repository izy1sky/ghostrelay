// Command relay connects resource hosts (nodes) to a central server that
// exposes their files and shells to agents as MCP tools.
//
//	relay         open the setup page in a browser (same as relay ui)
//	relay serve   run the server (needs a reachable address)
//	relay node    run a node (dials out to the server)
//	relay token   print a random token
//	relay approve / deny / approvals   decide calls the policy marks "ask"
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// version is set at release time with -ldflags "-X main.version=..."
var version = "0.8.0-dev"

func main() {
	if len(os.Args) < 2 {
		runApp(nil) // double-clicked, or typed with nothing else: the setup page
		return
	}
	switch os.Args[1] {
	case "ui":
		runApp(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	case "node":
		runNode(os.Args[2:])
	case "init":
		runInit(os.Args[2:])
	case "invite":
		runInvite(os.Args[2:])
	case "join":
		runJoin(os.Args[2:])
	case "service":
		runService(os.Args[2:])
	case "token":
		fmt.Println(newToken())
	case "hash":
		runHash()
	case "approvals":
		runApprovals(os.Args[2:])
	case "grants":
		runGrants(os.Args[2:])
	case "approve":
		runDecide(os.Args[2:], false)
	case "deny":
		runDecide(os.Args[2:], true)
	case "policy":
		if len(os.Args) < 3 || os.Args[2] != "check" {
			usage()
			os.Exit(2)
		}
		runPolicyCheck(os.Args[3:])
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  relay                 open the setup page in your browser: share this computer, or set up the hub
  relay ui              the same, with flags  [--no-browser] [--listen 127.0.0.1:PORT]
  relay init            set up a server here: tokens, policy, join code
  relay invite          print the join code and agent setup again
  relay join <code>     set up this machine as a node  [--root DIR] [--allow-exec] [--install]
  relay service ...     install | uninstall | status | logs   [node|server]
  relay serve [flags]   run the server   (relay serve -h; no flags: settings from relay init)
  relay node  [flags]   run a node       (relay node -h;  no flags: settings from relay join)
  relay token           print a random token
  relay hash            print sha256 of a token read from stdin (for policy agents)
  relay policy check    validate a policy file and test a call against it
  relay approvals       list calls waiting for approval    (needs RELAY_ADMIN_TOKEN)
  relay approve <id>    approve one  [--similar | --node] [--for 1h]  [--always]
  relay grants          list active grants   (relay grants revoke <id>)
  relay deny <id>       deny one     [--reason "..."]
  relay version`)
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// tokenFrom prefers the environment variable, so secrets stay out of `ps`.
func tokenFrom(flagVal, env string) string {
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		return v
	}
	return strings.TrimSpace(flagVal)
}
