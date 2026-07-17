# AGENTS.md — urlscan-lookup

## What this is

A CLI + local MCP server that investigates a suspicious URL via the
**urlscan.io API v1**. It has two modes: an **active scan** (submit the URL to
urlscan's sandbox browser and capture its behaviour) and a **passive search**
(query the historical public-scan database without touching the target). It
caches result/search responses locally with a TTL so repeated lookups do not
re-spend the low free-plan quota. The URL-layer sibling of `whois-lookup`,
`asn-lookup`, `abuse-lookup`, `tor-exit-lookup`, `icloud-relay-lookup`, and
`doh-lookup`.

## Build & test

```bash
make build      # → dist/urlscan-lookup  (NEVER `go build` directly)
make test       # go test -race -cover ./...
make check      # lint + test + build-all
make build-all  # cross-compile linux/{amd64,arm64}, darwin/arm64, windows/amd64
```

Go 1.25+. **No external dependencies** — standard library only. A urlscan.io
free-plan API key is required at runtime (`URLSCAN_API_KEY`).

## Layout

```
main.go                 Entry point; sets main.version, calls app.Run.
internal/validate/      Pre-network safety gate: URL + UUID + visibility.
internal/urlscan/       urlscan API v1 client + response normalizers.
  client.go             Submit/Result/Search/Quota/Screenshot; API-Key header;
                        backoff+jitter on 429/5xx; ErrNotReady/ErrGone/ErrRateLimited.
  types.go              Normalized Result/SearchResult/Quota + lenient wire decode.
internal/cache/         TTL JSON cache; atomic write; key = namespace+hash(id).
internal/config/        Sectioned-TOML subset + env/flag resolution.
internal/engine/        Ties validate+client+cache. Submit and Poll are separate
                        (async job style); Result/Search/Quota are cache-aware.
internal/workspace/     Agent-provided output dir + os.Root containment.
internal/app/           CLI: dispatch, scan/search/result/screenshot/quota/cache/mcp, output.
internal/mcp/           Zero-dep stdio JSON-RPC 2.0 MCP server + tools.
  usage.md              Embedded get_usage manual.
```

## Key design decisions

- **Two modes, one engine.** Active `scan` (submit → poll) and passive
  `search`/`result` share the engine, so CLI and MCP cannot diverge.
- **Safe visibility default.** Active scans default to `private`; `public`
  (world-visible, indexed) requires an explicit flag. This asymmetry is the
  central OpSec decision — never change the default.
- **Async MCP.** urlscan's submit (UUID immediately) / result (404 until ready)
  is inherently async. `scan_url` returns the UUID immediately and never
  blocks; `get_result` polls and returns `{status:"processing"}` while running.
  The UUID is the job handle (no separate job id, unlike image-forge).
- **HTTP client is an interface** (`urlscan.Doer`, `engine.Client`) so the
  engine is tested without touching the network.
- **In-house backoff, no nlk.** Exponential + jitter with the standard library,
  honoring `Retry-After` / `X-Rate-Limit-Reset`. No LLM ⇒ no nlk dependency.
- **Dynamic quota.** Free-plan per-action quotas are low and vary; read them
  live from `/user/quotas/` and `X-Rate-Limit-*`, never hardcoded.
- **result/search cached; scan not.** A new scan always generates a new
  result, so it is never served from cache.
- **Screenshots are file-mediated** in MCP (asn-lookup / abuse-lookup pattern):
  `get_screenshot` writes the PNG to an agent-provided `workspace_root` (via
  `os.Root`) and returns the path — never image bytes.
- **No LLM judgment.** Verdicts are urlscan's; analysis is left to the caller.

## Gotchas

- The auth header name is **`API-Key`** exactly — urlscan rejects `x-api-key`.
- `result`/`screenshot` return **HTTP 404 while a scan is still running**
  (→ `ErrNotReady`, surfaced as "processing"), **410 when deleted** (→ `ErrGone`).
- Only **HTTP 200** responses consume quota; a 429 does not.
- Poll timing follows urlscan guidance: **wait 10s, then poll every 2s.**
- The free-plan **private-scan quota is 50/day** (50/hour, 5/minute; measured
  2026-07-17) — low, so check `quota` before batch scanning. Other free limits:
  public 5000/day, unlisted 1000/day, search 1000/day, retrieve 10000/day,
  livescan 0 (unavailable).
- The `/user/quotas/` `limits` object mixes per-action quotas with plan
  metadata (`features`, `queryableFields`, `maxSearchResults`, a nested `files`
  object); the client extracts only objects carrying a `day` window.
- `search` on a free key sees only public scans (`queryVisibility: ["public"]`).

## Status

Scaffolding complete and **validated against the real free-plan API**
(2026-07-17): `quota` / `search` / `scan` (private) / `result` / `screenshot`
and the MCP `get_quota` + `get_result` async path all work. Tests pass
(validate, config, cache, urlscan client, engine, mcp, workspace). Pending: the
release pipeline (Phase 3).
