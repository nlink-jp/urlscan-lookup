# Changelog

All notable changes to urlscan-lookup are documented here.

## [0.1.0] - 2026-07-17

Initial release.

### Added

- Project scaffold (Plan → Scaffold): Go module, single-binary CLI + MCP
  layout, build/release pipeline (Makefile, codesign/notarize/brew scripts),
  and docs. Design: [docs/ja/urlscan-lookup-rfp.ja.md](docs/ja/urlscan-lookup-rfp.ja.md).

- **Passive path (RFP Phase 1):** `search` (historical scan database),
  `result` (fetch by UUID), `quota` (per-action remaining quota), and
  `cache status|clear`. urlscan API v1 client with `API-Key` auth, in-house
  exponential backoff + jitter on 429/5xx (honoring `Retry-After` /
  `X-Rate-Limit-Reset`), and response normalization. Result/search TTL cache
  (default 24h). Pre-network validation gate (URL scheme/host/CRLF, RFC 4122
  UUID). Sectioned-TOML + `URLSCAN_LOOKUP_*` / `URLSCAN_API_KEY` config.

- **Active path + MCP (RFP Phase 2):** `scan` (submit → poll, default
  `private` visibility, `--no-wait`, `--country`, `--referer`, `--user-agent`,
  `--fail-on-malicious`) and `screenshot`. Zero-dep stdio JSON-RPC 2.0 MCP
  server with `scan_url` / `get_result` / `search` / `get_screenshot` /
  `get_quota` / `get_usage`, async job style (UUID returned immediately;
  `get_result` polls; "processing" is a normal response), structured tool
  errors, and file-mediated screenshots via `os.Root` containment.

### Verified

- Real-API E2E against the free plan (2026-07-17): `quota`, `search`, a
  `private` `scan` (submit → poll → result), `result` (cache hit),
  `screenshot`, and the MCP `get_quota` / `get_result` async path all work.
  Confirmed **private scans are available on the free plan at 50/day**
  (50/hour, 5/minute), so the default-`private` design needs no fallback.
  Fixed one real-data discrepancy: the `/user/quotas/` `limits` object mixes
  per-action quotas with plan metadata, so only objects with a `day` window
  are parsed as actions (regression test added).

### Pending

- Release (Phase 3): sign + notarize, submodule integration, catalog sync,
  Homebrew tap, `check-org.sh`.
