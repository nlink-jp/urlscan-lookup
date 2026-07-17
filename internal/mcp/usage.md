# urlscan-lookup MCP server — operating manual

urlscan-lookup investigates a suspicious URL via the **urlscan.io API v1**. It
submits the URL to urlscan's sandbox browser to capture its real behaviour —
final URL, loaded resources, observed IPs/domains, threat verdicts, and a
screenshot (active scan) — and searches the historical public-scan database
(passive search). A free-plan API key is required (sent in the `API-Key`
header; never logged). Results are cached locally, so repeated `get_result` /
`search` calls do not re-spend the low free-plan quota.

## Safety: visibility

Active scans default to **private** — the scan is visible only to your account.
`unlisted` hides it from public search but exposes it to vetted researchers.
`public` publishes the scan (and the target URL, which may reveal the
attacker's assets or victim-identifying parameters) to the whole world,
including the attacker. **Pass `visibility: "public"` only when you deliberately
intend that.**

## Asynchronous model

Scans are not instant. `scan_url` submits and returns a `uuid` immediately —
it never blocks. Poll `get_result` with that uuid: while the scan runs it
returns `{status: "processing"}`, which is a **normal** state, not an error.
Allow ~10 seconds before the first poll, then poll every couple of seconds.

## Tools

### scan_url

Submit a new active scan. Arguments: `url` (required, http/https),
`visibility` (`private` default | `unlisted` | `public`), `country` (scanning
PoP, e.g. `jp`), `tags` (array), `referer`, `user_agent`. Returns
`{status: "submitted", uuid, visibility, result_url}`. Consumes the scan
quota for the chosen visibility.

### get_result

Fetch a scan result by `uuid` (optional `refresh` to bypass the cache).
Returns `{status: "processing"}` while running, else the normalized result:
`uuid`, `time`, `visibility`, `submitted_url`, `final_url`, `ip`, `asn`,
`asn_name`, `country`, `server`, `malicious`, `score`, `tags`, `brands`,
`categories`, `unique_ips`, `unique_domains`, `requests`,
`malicious_requests`, `related_ips`, `related_domains`, `screenshot_url`,
`report_url`, `raw`.

### search

Search the historical **public** scan database — passive, never touches the
target. Arguments: `query` (required; urlscan ElasticSearch syntax, e.g.
`domain:example.com`, `page.ip:1.2.3.4`, `hash:<sha256>`), `size` (default
100), `search_after` (pagination cursor), `refresh`. Returns `{total,
has_more, results:[{uuid, time, url, domain, ip, asn, country, report_url,
screenshot_url}]}`.

### get_screenshot

Save a scan's screenshot PNG into `workspace_root` (an agent-prepared writable
directory) and return the file path — never image bytes. Argument: `uuid`
(required), `workspace_root` (optional; defaults to the server workspace).

### get_quota

Report remaining quota per action (public/private/unlisted scan, search,
retrieve) across day/hour/minute windows. Free-plan quotas are low; check
before batch scanning.

### get_usage

Returns this manual. No arguments.

## Errors

Tool errors are structured JSON: `{"code": "...", "message": "..."}`.

| code | meaning | recovery |
|------|---------|----------|
| `invalid_input` | The URL/UUID/query failed the safety gate. Nothing was sent to the network. | Fix the argument (URL must be http/https; uuid must be the 36-char form). |
| `no_api_key` | No urlscan API key is configured. | Set `URLSCAN_API_KEY` (a free-plan key) and restart the server. |
| `rate_limited` | A per-action free-plan quota is exhausted (HTTP 429). | Wait for the window to reset; call get_quota to see remaining. Only 200s consume quota. |
| `not_ready` | The screenshot is not generated yet. | The scan may still be running or produced none; poll get_result first. |
| `gone` | The scan result was deleted (HTTP 410). | Nothing to fetch; submit a fresh scan if needed. |
| `timeout` | A polled scan did not finish within the budget. | The scan may still complete; fetch it later with get_result by uuid. |
| `network_error` | urlscan was unreachable or answered abnormally. | Retry later; avoid rapid retries — the cache exists for a reason. |
