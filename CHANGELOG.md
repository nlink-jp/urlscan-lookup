# Changelog

All notable changes to urlscan-lookup are documented here.

## [Unreleased]

### Fixed

- **The Linux archives no longer carry macOS file metadata.** macOS `tar` wrote
  each bundled file's extended attributes (`com.apple.provenance`, and a Dropbox
  attribute where the tree is synced) into the `.tar.gz` twice: as AppleDouble
  `._` members, which GNU tar extracts as stray `._<name>` files beside the real
  ones, and as `LIBARCHIVE.xattr.*` / `SCHILY.xattr.*` pax headers, which it
  reports as unknown keywords. `make package` now archives with
  `COPYFILE_DISABLE=1 tar --no-xattrs`; each setting stops one of the two.
  Archives already published still carry them; the files themselves are
  unaffected.

### Internal

- `make verify-release` also judges each Linux archive: no AppleDouble or other
  macOS metadata members — listed with `--options 'tar:!mac-ext'`, because a
  plain macOS listing folds `._` members away — no extended attributes as pax
  headers, and exactly the canonical binary, `README.md` and `LICENSE`, compared
  in the C locale.
- The Linux-archive check in `make verify-release` reads each archive's pax
  headers with Python's `tarfile` instead of grepping the decompressed stream,
  which also matched file text that names the keywords (a bundled CHANGELOG,
  for one).

## [0.4.1] - 2026-09-21

### Fixed

- **`make verify-release` now fails closed.** Its last block chained unzip, the
  packaged binary's `--version` and `spctl` with `&&` and ended the whole chain
  in `|| true`, so a zip that did not unpack or a binary that did not run exited
  0 and the upload proceeded. Each step is now judged on its own, the packaged
  binary's `--version` must contain the tag being released, and only the
  informational `spctl` line may be ignored. Matches the org template
  (CONVENTIONS.md §Code Signing → Verifying a release).

- **The embedded manual said `get_screenshot` skips the strict argument check.**
  It does not, and has not since 0.4.0 — the error table kept a row from before
  the change, contradicting a paragraph in the same file. `get_usage` is what a
  model reads to decide whether to trust an error, so that row told it to retry
  a call that will keep failing and to distrust the message naming the typo.
  A test now compares the manual against the registry: every tool must be named
  in it, and no wording may carve a tool out of the check.
- **Stale project documents.** `CLAUDE.md` still listed the deleted
  `internal/workspace/` in the architecture and described the tool as awaiting
  release; the RFP still specified the withdrawn file-mediated
  `get_screenshot`. The RFP is kept as the record of what was planned, with a
  note that the ADR supersedes it (both languages).

## [0.4.0] - 2026-09-21

### Changed

- **Breaking: a screenshot comes back in the response, and this server no longer
  writes anything to disk.** `get_screenshot` used to write the PNG into a
  directory — yours via `workspace_root`, or the server's own by default, which
  in the common case was a path you could not read — and return that path. It
  now returns the image as MCP content when it fits the inline budget (4 MiB by
  default, `URLSCAN_LOOKUP_SCREENSHOT_MAX_BYTES`), and for a larger one returns
  its size, the budget that stopped it, and `screenshot_url` — urlscan.io's own
  address for the PNG — for you or your runtime to fetch. It is not truncated:
  half a PNG is not a smaller picture.

  `screenshot_file` is gone from the reply and `workspace_root` from the
  arguments. A configuration carrying `URLSCAN_LOOKUP_WORKSPACE` now fails to
  load, by name, rather than having a destination silently ignored.

  Deciding to put a large response on disk is the agent runtime's job, not a
  server's: a server cannot know your context window. The organisation retired
  the file-and-path shape fleet-wide on 2026-09-06; this server was the one that
  still had it. See `docs/en/adr/0001-screenshots-in-the-response.md`.

- `get_screenshot` now refuses an argument it does not declare, like every other
  tool. It was the one handler left lenient, because `workspace_root` looked
  like a rename waiting to happen; it was a withdrawal instead.

## [0.3.0] - 2026-09-21

### Changed

- **An MCP tool call carrying an argument the tool does not declare now fails
  instead of being quietly ignored.** This is a deliberate behaviour change,
  required by org ADR-021 §4, and on this server it is the visibility argument
  that makes it urgent: until now `visibilty` instead of `visibility` was
  dropped and the scan fell back to the configured default, so a caller who
  asked for a private scan and mistyped the argument got whatever the config
  said — and a caller who deliberately asked for `public` silently did not
  publish. `scan_url`, `get_result`, `search`, `get_quota` and `get_usage` now
  decode with `DisallowUnknownFields` and refuse the call, naming the offending
  field:
  `{"code":"invalid_input","message":"arguments: json: unknown field \"visibilty\""}`.

  A malformed argument object is refused for the same reason. The decode error
  used to be discarded along with the unknown field, so `{"url": 1}` ran as if
  no URL had been supplied and came back with "provide 'url'", an answer that
  contradicted the request. It now reports the type mismatch.

  Nothing runs before the arguments decode, so a rejected call submits no scan
  and spends no quota. Omitting `arguments`, or sending `{}` or `null`, still
  means "no arguments" and is not an error. There is no compatibility shim: an
  argument name this server does not declare has never meant anything, so the
  only fix is to correct it.

  **`get_screenshot` is the one exception and stays lenient for now**: its
  `workspace_root` argument is a spelling ADR-021 §1 retired in favour of
  `work_dir`, and that migration — which owns how a stale spelling is answered
  — is a separate job. An unknown argument to `get_screenshot` is still
  ignored. Everything else in the server refuses one.

### Fixed

- **Every MCP tool input schema is closed.** The six schemas omitted
  `additionalProperties: false`, so a mistyped argument read as a legitimate one
  to any client that validates against them — a misspelt `visibility` on
  `scan_url` being the one that matters, since dropping it falls back to the
  default rather than failing. Schemas are now built through a single `obj()`
  helper that sets the flag, and an arch test fails if a tool's schema omits it
  — org ADR-021 §10 requires the test as well as the flag, because a rule
  stated only in prose is re-decided by whoever adds the next tool.

## [0.2.0] - 2026-08-31

### Added

- **`get_screenshot` returns the PNG inline as MCP image content** when it is at
  or below 4 MiB, so a model can look at the screenshot directly instead of only
  receiving a path it may have no way to read. The file is still written to the
  workspace and the path and byte count are still returned as text; above the
  budget the result stays file-only, because base64 inflates by a third and an
  inline image is replayed with the conversation every round.
- `get_screenshot` takes `inline` (default true) for a client that cannot accept
  image content.

### Changed

- The `workspace_root` argument now says plainly that the caller should pass a
  root it can read back: every result is returned as a path under that root, so
  a workspace the caller cannot open leaves it holding a path to nothing. Text
  only — the behaviour is unchanged.


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
