// Command relay connects resource hosts (nodes) to a central server that
// exposes their files and shells to agents as MCP tools.
//
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

const version = "0.5.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "node":
		runNode(os.Args[2:])
	case "token":
		fmt.Println(newToken())
	case "hash":
		runHash()
	case "approvals":
		runApprovals(os.Args[2:])
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
  relay serve [flags]   run the server   (relay serve -h)
  relay node  [flags]   run a node       (relay node -h)
  relay token           print a random token
  relay hash            print sha256 of a token read from stdin (for policy agents)
  relay policy check    validate a policy file and test a call against it
  relay approvals       list calls waiting for approval    (needs RELAY_ADMIN_TOKEN)
  relay approve <id>    approve one  [--always]
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
