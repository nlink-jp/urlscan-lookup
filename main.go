// Command urlscan-lookup investigates a suspicious URL via the urlscan.io
// free-plan API, as a CLI and a local MCP server. It submits the URL to
// urlscan's sandbox browser to capture its real behaviour — final URL, loaded
// resources, observed IPs/domains, threat verdicts, and a screenshot (active
// scan) — and searches the historical public-scan database (passive search).
// Active scans default to private visibility; public must be requested
// explicitly. The URL-layer, single-binary sibling of whois-lookup
// (registration), asn-lookup (attribution), abuse-lookup (reputation),
// tor-exit-lookup / icloud-relay-lookup (exit-IP classification), and
// doh-lookup (DNS resolution): it feeds the IPs and domains it extracts into
// those IP/domain-layer tools.
package main

import (
	"os"

	"github.com/nlink-jp/urlscan-lookup/internal/app"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(app.Run(os.Args[1:], version))
}
