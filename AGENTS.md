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
make verify-release  # gate: .notarized marker + freshness (run before upload)
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
- **Screenshots ride inline when they fit, and are always written to disk.**
  `get_screenshot` writes the PNG to an agent-provided `workspace_root` (via
  `os.Root`) and returns the path, and at or below `inlineImageBudget` (4 MiB)
  it *also* appends an MCP `image` content block (chrome-pilot-mcp uses the same
  ceiling). A screenshot is the one result here a model has to see, and a path
  alone is useless to a client that cannot read the server's disk. The file
  stays either way — it is what an oversized screenshot is served from.
  An image content block must not carry an empty `text` key: a client that only
  reads text would see an empty answer, which is why `contentItem`'s fields are
  `omitempty`.
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
- **Tool schemas are closed and the decoder enforces it.** Every `inputSchema`
  is built by `obj()` in `internal/mcp/tools.go`, which sets
  `additionalProperties: false` (org ADR-021 §10), and
  `TestEveryToolSchemaIsValidAndClosed` fails if a tool escapes it — so build a
  new schema with `obj()`, not a map literal. The flag is only the *declared*
  half; the enforcing half is `decodeArgs()` beside it
  (`json.Decoder.DisallowUnknownFields`), which every tool handler decodes
  through, including the argument-less ones. **A call carrying an argument this
  server does not declare now fails, naming the field, instead of being
  silently ignored** — deliberate, per ADR-021 §4, because the schema says what
  is allowed and the decoder is what actually refuses. `decodeArgs` also stops
  discarding the decode error, so a wrong-typed argument no longer runs the tool
  on zero values. Omitted or `null` arguments still mean the empty object. Do
  not add a `_ = json.Unmarshal` back, and do not add a compatibility shim: the
  ADR's one-release grace covers only the retired `workspace_root` spellings.
  **`get_screenshot` is the one handler deliberately left out**, because it
  still takes one of those spellings — see the next entry.
  `TestGetScreenshotArgumentsStayLenient` records that exemption as a test, so
  the work-dir migration is told to delete it rather than work around it.
- **`get_screenshot` still takes `workspace_root`, a spelling ADR-021 §1
  retired** in favour of `work_dir`. This server was not part of the work-dir
  migration, so renaming it is a separate job: it needs the transplanted
  `internal/mcp/workdir` package (resolution, the §4 validation list, the error
  codes) and the one-cycle compatibility reply that tells a stale caller the new
  name. Do not rename the argument on its own — the schema is now closed, so a
  caller passing `work_dir` today is refused by a validating client with no hint.

## Status

Scaffolding complete and **validated against the real free-plan API**
(2026-07-17): `quota` / `search` / `scan` (private) / `result` / `screenshot`
and the MCP `get_quota` + `get_result` async path all work. Tests pass
(validate, config, cache, urlscan client, engine, mcp, workspace). Pending: the
release pipeline (Phase 3).
