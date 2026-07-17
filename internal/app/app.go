// Package app implements the urlscan-lookup command-line interface:
// subcommand dispatch plus the scan / search / result / screenshot / quota /
// cache / mcp commands. Core logic lives in the engine, urlscan, cache,
// config, and validate packages; this package is the thin I/O shell around
// them.
package app

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/nlink-jp/urlscan-lookup/internal/config"
	"github.com/nlink-jp/urlscan-lookup/internal/engine"
	"github.com/nlink-jp/urlscan-lookup/internal/mcp"
)

// Exit codes. A malicious verdict is a successful scan, so it is exit 1 only
// when the caller opts in via --fail-on-malicious; otherwise a completed scan
// is exit 0 regardless of verdict.
const (
	exitOK        = 0 // command succeeded
	exitMalicious = 1 // scan completed and was flagged malicious (--fail-on-malicious)
	exitError     = 2 // usage / validation / network error
)

// Run dispatches a subcommand and returns a process exit code.
func Run(args []string, version string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return exitError
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "scan":
		return runScan(rest, version, os.Stdout, os.Stderr)
	case "search":
		return runSearch(rest, version, os.Stdout, os.Stderr)
	case "result":
		return runResult(rest, version, os.Stdout, os.Stderr)
	case "screenshot":
		return runScreenshot(rest, version, os.Stdout, os.Stderr)
	case "quota":
		return runQuota(rest, version, os.Stdout, os.Stderr)
	case "cache":
		return runCache(rest, os.Stdout, os.Stderr)
	case "mcp":
		return cmdMCP(rest, version)
	case "version", "--version", "-v":
		fmt.Println("urlscan-lookup " + version)
		fmt.Println("Data: urlscan.io API v1 (https://urlscan.io/docs/api/). Requires a free-plan API key.")
		return exitOK
	case "help", "-h", "--help":
		usage(os.Stdout)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage(os.Stderr)
		return exitError
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `urlscan-lookup — investigate a suspicious URL via the urlscan.io API (CLI + MCP)

Usage:
  urlscan-lookup <command> [flags] [args]

Commands:
  scan <url>          Submit a new scan and poll for the result (active)
  search <query>      Search the historical public-scan database (passive)
  result <uuid>       Fetch an existing scan result
  screenshot <uuid>   Save a scan's screenshot PNG
  quota               Show remaining API quota per action
  cache status|clear  Show or clear the local result/search cache
  mcp                 Run as a local MCP server (stdio)
  version             Print the version

scan flags:
  --visibility private|unlisted|public   Scan visibility (default: private)
  --no-wait                              Submit only; print the UUID, do not poll
  --country <cc>                         Scanning PoP country (e.g. jp, de)
  --tags <t1,t2>                         Tags to attach to the scan
  --referer <url>                        Referer header to send
  --user-agent <ua>                      User-Agent to send
  --fail-on-malicious                    Exit 1 if the scan is flagged malicious
  -j, --json                             JSON output

search flags:
  --size <n>            Number of results (default 100)
  --search-after <s>    Pagination cursor (sort value of the last row)
  -j, --json            JSONL output (one hit per line)

result/screenshot/quota flags:
  --refresh             Bypass the cache and re-fetch (result)
  -o, --output <path>   Screenshot output path (default <uuid>.png)
  -j, --json            JSON output

Common flags:
  -c, --config <path>   Config file (default ~/.config/urlscan-lookup/config.toml)

Authentication:
  A urlscan.io free-plan API key is required, supplied via the URLSCAN_API_KEY
  environment variable (preferred) or the config file. The key is sent in the
  API-Key header and is never logged.

Safety:
  Active scans default to private visibility — the target URL is recorded only
  in your own account. Requesting public visibility (which publishes the scan
  to the world, including the attacker) requires --visibility public.
`)
}

// cmdMCP runs the stdio MCP server until stdin closes (MCP has no protocol
// cancel; a closing stdin is the shutdown signal).
func cmdMCP(args []string, version string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfgPath := fs.String("config", "", "config file path")
	fs.StringVar(cfgPath, "c", "", "config file path (shorthand)")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	cfg, err := config.Load(*cfgPath, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	if err := mcp.Serve(engine.New(cfg, version), cfg, version, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "mcp: %v\n", err)
		return exitError
	}
	return exitOK
}
