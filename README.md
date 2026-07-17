# urlscan-lookup

Investigate a suspicious URL via the [urlscan.io](https://urlscan.io) API v1 —
as a CLI and a local MCP server. Submit a URL to urlscan's sandbox browser and
capture its real behaviour (final URL, loaded resources, observed IPs/domains,
threat verdicts, screenshot), or search the historical public-scan database
without touching the target.

Active scans default to **private** visibility — the scan is recorded only in
your own account. Publishing a scan to the world (including the attacker)
requires an explicit `--visibility public`.

The URL-layer sibling of the cybersecurity-series lookups — `whois-lookup`
(registration), `asn-lookup` (attribution), `abuse-lookup` (reputation),
`tor-exit-lookup` / `icloud-relay-lookup` (exit-IP classification), and
`doh-lookup` (DNS). It feeds the IPs and domains it extracts into those tools.

> Requires a **urlscan.io free-plan API key**. Create one at
> <https://urlscan.io/user/profile/> and supply it via the `URLSCAN_API_KEY`
> environment variable.

## Install

Homebrew (Apple Silicon, notarized prebuilt binary):

```bash
brew install nlink-jp/tap/urlscan-lookup
```

Or download a release archive for your platform from the
[Releases](https://github.com/nlink-jp/urlscan-lookup/releases) page and put
the binary on your `PATH`.

## Usage

```bash
export URLSCAN_API_KEY=your-free-plan-key

# Active scan (private by default), polled to completion:
urlscan-lookup scan https://suspicious.example/login

# Submit only, get the UUID back immediately:
urlscan-lookup scan https://suspicious.example/ --no-wait

# Scan from a specific country PoP (defeats geo-fenced phishing):
urlscan-lookup scan https://suspicious.example/ --country jp

# Passive search of the historical database (OpSec-safe):
urlscan-lookup search 'domain:suspicious.example'
urlscan-lookup search 'page.ip:203.0.113.10'

# Fetch an existing scan result / screenshot:
urlscan-lookup result 01234567-89ab-cdef-0123-456789abcdef --json
urlscan-lookup screenshot 01234567-89ab-cdef-0123-456789abcdef -o shot.png

# Check remaining API quota (free-plan quotas are low):
urlscan-lookup quota

# Run as a local MCP server (stdio):
urlscan-lookup mcp
```

`scan` and `result` print a human-readable summary by default (final URL,
verdict, primary IP/ASN/country, observed counts); add `-j`/`--json` for the
full normalized JSON. `--fail-on-malicious` makes `scan` exit `1` when the
verdict is malicious (for SOC scripting).

### MCP tools

`scan_url`, `get_result`, `search`, `get_screenshot`, `get_quota`,
`get_usage`. Scans are asynchronous: `scan_url` returns a UUID immediately and
`get_result` polls (a `processing` status is normal). Call `get_usage` for the
full reference.

## Build & test

```bash
make build       # → dist/urlscan-lookup  (never `go build` directly)
make test        # go test -race -cover ./...
make build-all   # cross-compile all platforms
```

Go 1.25+. No external dependencies — standard library only.

## Configuration

A urlscan.io API key is required. Prefer the `URLSCAN_API_KEY` environment
variable over the config file (a key in plaintext TOML is a secret at rest).
Optional settings live in `~/.config/urlscan-lookup/config.toml` — see
[config.example.toml](config.example.toml). Precedence: flag > env > config >
default.

| Setting | Env | Default |
|---|---|---|
| API key | `URLSCAN_API_KEY` | (required) |
| Default visibility | `URLSCAN_LOOKUP_VISIBILITY` | `private` |
| Scan PoP country | `URLSCAN_LOOKUP_COUNTRY` | (urlscan default) |
| Cache TTL (hours) | `URLSCAN_LOOKUP_CACHE_TTL_HOURS` | 24 |
| Cache dir | `URLSCAN_LOOKUP_CACHE_DIR` | `~/.cache/urlscan-lookup` |
| Network timeout (s) | `URLSCAN_LOOKUP_TIMEOUT_SECONDS` | 30 |

## Data source

[urlscan.io API v1](https://urlscan.io/docs/api/). The key is sent in the
`API-Key` header and is never logged. Free-plan quotas are per-action (scan
public/unlisted/private, search, retrieve) and low; the tool reads remaining
quota from `/user/quotas/` and the `X-Rate-Limit-*` response headers rather
than hardcoding limits.

## License

[MIT](LICENSE)
