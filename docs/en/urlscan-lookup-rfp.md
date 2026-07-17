# RFP: urlscan-lookup

> Generated: 2026-07-17
> Status: Draft

## 1. Problem Statement

When SOC / CSIRT and individual security practitioners investigate a suspicious URL
(phishing, malware distribution, C2, etc.), visiting it directly in their own browser is
dangerous, and they need a safe way to observe "what actually happens" — the final
redirect target, the resources it loads, the cookies it sets, the observed IPs / domains,
the detected threat tags, and a screenshot. **urlscan-lookup is a CLI and local MCP server
that, via the urlscan.io free-plan API, has the target URL visited by urlscan's sandbox
browser to capture its real behaviour (active scan), and also searches the historical
public-scan database (passive search).** Its users are CTI / IR practitioners who want to
inspect a suspicious URL's real behaviour with safe OpSec, and investigation agents that
call it over MCP. It is a cybersecurity-series sibling alongside `whois-lookup`
(registration), `asn-lookup` (attribution), `abuse-lookup` (IP reputation),
`tor-exit-lookup` / `icloud-relay-lookup` (exit-IP classification) and `doh-lookup`
(DNS resolution). It owns the **URL layer** and acts as the "entry point of the
investigation chain", feeding the IPs / domains it extracts into the existing IP / domain
layer tools.

## 2. Functional Specification

### Commands / API Surface

**CLI subcommands** (following the sibling-tool conventions):

- `urlscan-lookup scan <url>` — primary (active) operation. Submits a new scan of the target URL and polls to completion, then prints the result
  - `--visibility private|unlisted|public` — visibility (**default `private`**; `public` must be requested explicitly)
  - `--no-wait` — only submit and return the UUID immediately (do not poll)
  - `--country <cc>` — pin the scanning PoP country (e.g. `jp`, `de`; to defeat geo-fenced phishing)
  - `--tags <t1,t2>` — tags to attach to the scan
  - `--referer <url>` / `--user-agent <ua>` — override the sent Referer / UA (to reproduce phishing gating conditions)
  - `--json` — structured output (normalized JSON close to raw)
  - `--fail-on-malicious` — exit 1 if the scan verdict is malicious (opt-in, for SOC scripting)
- `urlscan-lookup search <query>` — search historical scans (passive, OpSec-safe)
  - `--size <n>` — number of results (default 100)
  - `--search-after <sort>` — pagination (sort value of the last row of the previous page)
  - `--json` — JSONL output (one hit per line)
- `urlscan-lookup result <uuid>` — retrieve an existing scan result (`--json`)
- `urlscan-lookup screenshot <uuid>` — save the screenshot PNG (`--output <path>`)
- `urlscan-lookup quota` — show remaining quota (per action) via `GET /user/quotas/`
- `urlscan-lookup cache <status|clear>` — show / clear the cache
- `urlscan-lookup mcp` — start the local MCP server (stdio)
- `urlscan-lookup --version`

**MCP tools** (asynchronous job style; never block for long):

- `scan_url` — `{ url, visibility?, country?, tags?, referer?, user_agent? }` → **returns the UUID immediately** (never blocks). `visibility` defaults to `private`
- `get_result` — `{ uuid }` → if incomplete, `{ status:"processing", uuid, elapsed }`; if complete, the normalized result + metadata. urlscan's 404 (incomplete) / 410 (deleted) are caught and returned as **normal responses** ("processing" is a valid state, not an error)
- `search` — `{ query, size? }` → list of hits (large results mediated via a workspace file)
- `get_screenshot` — `{ uuid, workspace_root }` → saves the PNG under the workspace and returns the file path (never returns image bytes)
- `get_quota` — remaining quota per action
- `get_usage` — tool reference and error-recovery table

### Input / Output

- **Input validation gate (mandatory before any network I/O)**:
  - `scan` URL: allow only `http` / `https` schemes, reject control chars / CRLF, require a host part.
    Failing the gate yields CLI exit 2 / MCP `{code:"invalid_input"}`
  - `result` / `screenshot` UUID: validate the urlscan UUID format (RFC 4122) before hitting the API
- **Safe visibility default**: `scan` defaults to `private` (visible only to you). `public` (published and
  indexed to the whole world) takes effect only with an explicit `--visibility public`. This is the core
  OpSec spec that avoids inadvertently publishing the target URL (which may contain the attacker's assets
  or victim-identifying parameters)
- **Mode difference in waiting for completion**:
  - **CLI**: `scan` polls internally (**wait 10 s after submit → 2 s intervals**, capped by `--poll-timeout`,
    per official guidance) and returns the result. `--no-wait` returns the UUID immediately
  - **MCP**: `scan_url` returns the UUID immediately and never blocks. Call `get_result` to poll (the org
    standard async job pattern that avoids MCP request timeouts)
- **Summarized output (default, human-readable)**: the result JSON is large, so by default it is summarized
  to the essentials: submitted URL → final URL, overall verdict (malicious? / score / brands / tags),
  primary IP / ASN / country / server, unique-IP / domain / request / malicious-request counts,
  screenshot URL and report URL, and an excerpt of the main contacted domains / IPs
- **Full output**: `--json` (normalized structured JSON) provides all fields
- **Normalization**: extracted fields (`page.url` / `page.ip` / `page.asn` / `page.country` /
  `verdicts.overall` / `lists.ips` / `lists.domains` / `stats`, etc.) are normalized in one place
  (`internal/urlscan`) to absorb urlscan schema drift
- **Exit code contract**: `0` success / `2` error. Only with `--fail-on-malicious`, a malicious verdict yields `1`

### Configuration

`~/.config/urlscan-lookup/config.toml` (sectioned TOML, optional). `URLSCAN_LOOKUP_*` environment variables
override it. Because the API key is a secret, **the environment variable `URLSCAN_API_KEY` is canonical and
writing the key in plaintext TOML is discouraged** (accepted for local convenience, but `config.example.toml`
always keeps it commented out with a placeholder). Precedence is **flag > env > config > default**.

```toml
[auth]
# api_key = ""                       # discouraged; use the URLSCAN_API_KEY env var

[scan]
# default_visibility = "private"     # private | unlisted | public
# wait = true                        # CLI: poll to completion after submit
# poll_initial_delay_seconds = 10    # official guidance: wait 10 s before first poll
# poll_interval_seconds = 2          # official guidance: 2 s intervals
# poll_timeout_seconds = 120         # poll cutoff
# country = ""                       # scanning PoP country (e.g. "jp")

[search]
# size = 100

[cache]
# ttl_seconds = 3600                 # TTL for result / search (scan is not cached)
# dir = "~/.cache/urlscan-lookup"

[network]
# timeout_seconds = 30
```

### External Dependencies

- **Go standard library only** (`net/http` + `encoding/json`). Retry / backoff is **implemented in-house**
  (nlk not adopted).
- The only external service is **the urlscan.io public API**, authenticated via the `API-Key` HTTP header
  (one free-plan key). No other dependencies, OAuth, or IAM.

## 3. Design Decisions

- **Language = Go, minimal external dependencies.** Series standard (identical to whois / asn / abuse / tor /
  icloud-relay / doh). urlscan's JSON API is handled with the standard library alone and shipped as a single
  signed binary.
- **nlk not adopted; backoff in-house.** nlk's value is defending LLM I/O (guard / jsonfix / validate), and
  this tool carries no LLM. Adding a submodule dependency just for backoff is unjustified, so **exponential
  backoff + jitter is implemented with the standard library only**, honoring `Retry-After` /
  `X-Rate-Limit-Reset`.
- **The safe visibility default (`private`) is the OpSec core.** An active scan records the target URL on a
  third party's infrastructure (urlscan); a `public` default would index the investigation to the whole world
  and leak it to the attacker. The design centers on the asymmetry **default `private`, `public` requires an
  explicit flag**.
- **MCP is an async job pattern.** urlscan is inherently asynchronous: submit (UUID returned immediately) vs
  result (404 until complete). Splitting `scan_url` (submit) and `get_result` (poll) into separate tools
  avoids MCP request timeouts (same philosophy as the image-forge / voice-studio / video-studio job pattern;
  the UUID doubles as the job handle).
- **The engine is shared between CLI / MCP** with no behavioural divergence. The HTTP client is an injected
  interface, mocked in tests (testability by design). Pure parsers / formatters are tested against recorded
  urlscan-response fixtures.
- **Quota is fetched dynamically; numbers are never hardcoded.** The free plan has low per-action daily quotas
  (public / unlisted / private / search / result). Actual limits are read from `GET /user/quotas/` and the
  response `X-Rate-Limit-*` headers (Scope / Action / Limit / Remaining / Reset) and surfaced via the `quota`
  subcommand / `get_quota`.
- **Caching**: `result` / `search` use a TTL cache (to save quota, same philosophy as abuse-lookup).
  `scan` (new generation) is not cached.
- **Relationship to sibling tools**: it owns the URL layer and delegates enrichment of the IPs / domains
  extracted from scan results to `whois-lookup` / `asn-lookup` / `abuse-lookup` / `tor-exit-lookup` /
  `icloud-relay-lookup` (UNIX philosophy).
- **Out of scope (intentional)**:
  - urlscan **paid-plan-only features** (similarity search / large quotas / live scanning / Pro-equivalent features)
  - in-house browser rendering / scraping (active visiting is delegated to urlscan; this tool never touches the target directly)
  - **LLM judgment / summarization** of results (it sticks to raw retrieval; pass the result JSON to an upstream tool / agent if AI analysis is needed)
  - continuous monitoring / scheduled runs / persisting scan results in a DB (it sticks to one-shot investigation)

## 4. Development Plan

### Phase 1: Core (passive, CLI) — independently reviewable

- `internal/validate`: URL validation gate (scheme / control chars / CRLF / host presence), UUID validation
- `internal/config`: sectioned TOML + `URLSCAN_LOOKUP_*` env + `URLSCAN_API_KEY` + flags (precedence applied)
- `internal/urlscan`: HTTP client (`API-Key` header, **in-house exponential backoff + jitter**,
  `X-Rate-Limit-*` parsing, 429 / 5xx retry), `search` / `result` / `quotas` endpoints, response-type
  normalization
- `internal/cache`: TTL cache for `result` / `search`, atomic write
- `internal/engine`: validate → cache → fetch → normalize (summary field extraction)
- `internal/app`: `search` / `result` / `quota` / `cache` subcommands, `--json`, summary / full output, exit-code contract
- Full table-driven tests with mock HTTP + recorded fixtures

> Strategy: **solidify the passive (no-touch) features first**. The active `scan` is added in Phase 2 once the
> foundation is stable.

### Phase 2: Features (active + MCP) — independently reviewable

- `internal/engine`: `scan` (submit → poll, visibility / country / tags / referer / UA), `screenshot` retrieval
- `internal/app`: `scan` / `screenshot` subcommands, `--visibility` (default private) / `--no-wait` /
  `--fail-on-malicious`, poll control (wait 10 s → 2 s intervals)
- `internal/mcp`: zero-dep stdio JSON-RPC 2.0, tools `scan_url` / `get_result` / `search` / `get_screenshot` /
  `get_quota` / `get_usage`, structured errors `{code, message, details}`, large results / images mediated
  via a workspace file
- **E2E against the real API** (rate-controlled to respect the free quota). **At the start, empirically measure
  whether private scans actually work on the free key and the real daily limit**; if it differs from
  expectations, fold the fallback (e.g. dropping the default to unlisted) into the design.

### Phase 3: Release

- README.md / README.ja.md / CHANGELOG.md / AGENTS.md / config.example.toml / docs/{en,ja}
- Makefile + scripts (codesign / notarize / brew), build-all (linux amd64/arm64 / darwin arm64 /
  windows amd64), darwin sign + notarize, homebrew-tap formula
- submodule integration (cybersecurity-series umbrella) → two-surface sync of org profile + web-site catalog → check-org.sh

## 5. Required API Scopes / Permissions

No OAuth scopes / IAM roles are **required**. Only **one API key** issued on the urlscan.io free plan, sent in
the `API-Key` HTTP header (strictly this header name; `x-api-key` is not accepted). The key is supplied via the
`URLSCAN_API_KEY` environment variable.

## 6. Series Placement

Series: **cybersecurity-series**
Reason: it is a CTI / IR support tool that collects a suspicious URL's real behaviour with safe OpSec, belonging
to the same "CLI + MCP, single signed binary investigation lookup" family as `whois-lookup` / `asn-lookup` /
`abuse-lookup` / `tor-exit-lookup` / `icloud-relay-lookup` / `doh-lookup`. It owns the URL layer and is the
entry point into the other IP / domain layer tools.

## 7. External Platform Constraints

- **Low per-action free-plan quotas** (measured with a real key on 2026-07-17): as day/hour/minute —
  **public 5000/500/60, unlisted 1000/100/60, private 50/50/5, search 1000/1000/120, retrieve 10000/5000/120,
  livescan 0/0/0 (unavailable on free)**. Also: `search` visibility is `queryVisibility: ["public"]` (only
  public scans are searchable), retention 7 days, max 1000 search results. Because the numbers vary, they are
  **not hardcoded** but fetched dynamically from `GET /user/quotas/` and the response `X-Rate-Limit-*`
  headers (Scope / Action / Limit / Remaining / Reset). Exceeding a quota yields HTTP 429. Only successful
  (200) requests consume quota, with a fixed-window reset (per minute / per hour / midnight UTC).
  **Note**: the `/user/quotas/` `limits` object mixes per-action quotas with plan **metadata** (`features`,
  `queryableFields`, `maxSearchResults`, a nested `files` object, ...), so only objects carrying a `day`
  window are extracted as action quotas.
- **Official completion-wait convention**: after submit, **wait at least 10 s, then poll at 2 s intervals**.
  `result` is HTTP 404 while incomplete and HTTP 410 when deleted. No aggressive retries; polite pacing.
- **Strict auth header name**: `API-Key` (not `x-api-key`, etc.).
- **Visibility asymmetry risk**: a `public` scan is exposed on the urlscan front page / public search / info
  pages. `unlisted` is absent from public pages / search but visible to vetted security researchers. `private`
  is visible only to you. → Guaranteed via default `private` and requiring `public` explicitly.
- **Retrieved-asset endpoints**: screenshot = `https://urlscan.io/screenshots/$uuid.png`,
  DOM = `https://urlscan.io/dom/$uuid/`. Both are HTTP 404 when not yet generated.
- ~~**To verify (at the start of Phase 2)**: whether private scans are allowed on the free plan and the actual
  daily limit.~~ → **Confirmed (measured 2026-07-17)**: private scans **are available** on the free plan, at
  **50/day, 50/hour, 5/minute**. The default-`private` design stands; the fallback (dropping the default to
  unlisted) is **not needed**.

---

## Discussion Log

- **Origin**: a proposal for a CLI + MCP server investigating suspicious URLs via the urlscan.io free-plan API,
  following the same "CLI + MCP, minimal external dependencies, signed + notarized release" pattern as the
  existing cybersecurity-series siblings (whois / abuse / tor-exit lookup).
- **Confirmed and agreed on the active / passive split**: urlscan divides into (A) active scanning (have the
  target URL actually visited to generate a new scan) and (B) passive search (reference the existing public DB).
  Agreed to implement **both**.
- **Agreed on the safe visibility default**: active scans default to `private`, and `public` requires an explicit
  flag. The intermediate `unlisted` is also selectable (`--visibility {private|unlisted|public}`, default private).
- **Designed per-mode completion waiting**: the CLI polls internally (`--no-wait` available); MCP uses the async
  job pattern of `scan_url` (returns UUID immediately) + `get_result` (poll) to avoid MCP timeouts. The UUID
  doubles as the job handle.
- **Functional decisions**: output is summarized text by default + `--json` full; auth is `URLSCAN_API_KEY` env +
  TOML, key required and unified; `result` / `search` use a TTL cache, `scan` is not cached.
- **Design decisions**: Go / standard-library-centric, minimal external dependencies. **nlk not adopted** (no LLM,
  so backoff is in-house). CLI + MCP colocated in a single binary (`mcp` subcommand). MCP skeleton ported from
  data-toolbox-mcp. **LLM judgment not adopted** (built for agent use over MCP, so judgment is left to the caller).
- **Development order**: passive (search / result) in Phase 1, active scan + MCP in Phase 2. Phases 1 / 2 are
  independently reviewable.
- **Verified external constraints against urlscan's official docs**: no plan restriction on visibility (private
  is expected to work on the free plan, with low limits such as private ≈ 50/day). Quotas are per action and
  fetched dynamically from `GET /user/quotas/` and `X-Rate-Limit-*`; numbers are never hardcoded. Polling waits
  10 s then 2 s intervals, 404 incomplete / 410 deleted. The auth header name is strictly `API-Key`. The real
  free-plan private limit will be measured at the start of Phase 2.
- **Added features**: `quota` subcommand / `get_quota` tool to surface remaining quota (to avoid exhausting the
  low limits). `scan` gains `--country` / `--referer` / `--user-agent` (to reproduce geo-fenced / conditional
  phishing) and `--fail-on-malicious` (an opt-in exit code for SOC scripting).
- **Scaffold + real-API E2E (2026-07-17)**: skeleton built with whois-lookup as the canonical template and
  abuse-lookup as the API-key/rate-limit reference (`make build` / `go vet` / `gofmt` / `go test -race` all
  pass; 4-platform build). E2E with a real key: `quota` (fixed the mixed-`limits` parse) → `search` (public
  scans only; normalized OK) → `scan https://example.com` (private; submit → 25s poll → complete; verdict/IP/
  ASN/screenshot normalized OK) → `result` (cache hit) → `screenshot` (real PNG 1600×1200) → MCP `get_quota` /
  `get_result` (async path OK). The only real-data discrepancy was the quota `limits` mixed shape, fixed with a
  regression test that extracts only objects carrying a `day` window.
