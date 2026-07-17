# CLAUDE.md — urlscan-lookup

**Organization rules (mandatory): https://github.com/nlink-jp/.github/blob/main/CONVENTIONS.md**

## Purpose

CLI + local MCP server that investigates a suspicious URL via the
**urlscan.io API v1**. It submits the URL to urlscan's sandbox browser to
capture its real behaviour — final URL, loaded resources, observed
IPs/domains, threat verdicts, and a screenshot (**active scan**) — and
searches the historical public-scan database (**passive search**). Active
scans default to **private** visibility; `public` must be requested
explicitly. The URL-layer sibling of `whois-lookup` (registration),
`asn-lookup` (attribution), `abuse-lookup` (reputation), `tor-exit-lookup` /
`icloud-relay-lookup` (exit-IP classification), and `doh-lookup` (DNS): it
feeds the IPs/domains it extracts into those IP/domain-layer tools.

## Build & test

```bash
make build       # Build → dist/urlscan-lookup  (never `go build` directly)
make test        # Tests with race detector + coverage
go test ./...    # Same without Makefile
```

Go 1.25+. **No external dependencies — standard library only.**

## Architecture

```
main.go                 CLI entry: main.version → app.Run
internal/validate/      Pre-network safety gate: URL (scheme/host/CRLF) + UUID (RFC 4122)
internal/urlscan/       urlscan API v1 client (API-Key header, backoff+jitter, X-Rate-Limit) + normalizers
internal/cache/         Per-key TTL cache for result/search (scan never cached), atomic writes
internal/config/        Sectioned-TOML subset + URLSCAN_LOOKUP_* / URLSCAN_API_KEY env/flag resolution
internal/engine/        validate → cache → client; Submit/Poll split for async; shared by CLI + MCP
internal/workspace/     Agent-provided output dir + os.Root containment (MCP file-mediated screenshots)
internal/app/           Dispatch + scan/search/result/screenshot/quota/cache/mcp; --json etc.
internal/mcp/           Zero-dep stdio JSON-RPC 2.0 server; async job style
  usage.md              Embedded get_usage manual
```

Core logic takes injected dependencies (the HTTP client is the `urlscan.Doer`
interface; the engine depends on the `engine.Client` interface), mocked in
tests. **No external dependencies — standard library only.**

## Key conventions

- **Visibility default is `private` — this is the OpSec core.** An active
  scan records the target URL on urlscan's infrastructure; a `public` scan is
  indexed to the whole world (including the attacker). Default `private`;
  `public` requires an explicit `--visibility public` / `visibility:
  "public"`. Never flip the default.
- **Validation gate is a safety mechanism, not UX.** A scan URL must be
  http/https with a host and no control chars/CRLF; a UUID must be the 36-char
  RFC 4122 form. Rejected **before any network I/O**.
- **MCP is asynchronous (job style).** `scan_url` submits and returns the UUID
  immediately (never blocks the MCP request); `get_result` polls. A
  "processing" status is a **normal response**, not an error. The CLI `scan`
  wraps submit+poll for convenience (`--no-wait` to skip the poll). Poll
  timing follows urlscan: wait 10s, then poll every 2s.
- **No nlk; backoff is in-house.** This tool carries no LLM, so backoff/retry
  is standard-library exponential + jitter, honoring `Retry-After` /
  `X-Rate-Limit-Reset`. nlk (LLM I/O defense) is intentionally not a dependency.
- **Quota is dynamic, never hardcoded.** Free-plan per-action quotas are low
  and vary; read them from `GET /user/quotas/` and the `X-Rate-Limit-*`
  headers. Surfaced via `quota` / `get_quota`.
- **Cache is etiquette.** `result` / `search` use a TTL cache (default 24h) to
  save the low quota. `scan` (new generation) is never cached.
- **Key is a secret.** `URLSCAN_API_KEY` is canonical; sent via the `API-Key`
  header (strictly that name); never logged or placed in a URL.
- **No LLM judgment.** The tool retrieves raw material; verdicts are urlscan's,
  and analysis is left to the calling agent/tool (built for MCP use).
- **Exit codes:** `0` success / `2` error. `--fail-on-malicious` makes a
  malicious verdict exit `1` (opt-in, for SOC scripting).
- **Engine is shared** by CLI and MCP so their behaviour cannot diverge.

## Status

Scaffolding complete and **validated against the real free-plan API**
(2026-07-17): `quota` / `search` / `scan` (private, submit→poll→result) /
`result` (cache hit) / `screenshot` / MCP `get_quota` + `get_result` all work.
Confirmed private scans are available on the free plan at **50/day** (so the
default-`private` design needs no fallback). Remaining: release (Phase 3 —
sign/notarize, submodule, catalog, brew, check-org). Design:
[docs/ja/urlscan-lookup-rfp.ja.md](docs/ja/urlscan-lookup-rfp.ja.md).

## Communication Language

All communication between contributors and Claude Code is conducted in
**Japanese**.
