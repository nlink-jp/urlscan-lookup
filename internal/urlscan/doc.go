// Package urlscan is the urlscan.io API v1 client and response normalizer.
//
// The API key authenticates to the user's own urlscan.io account. It is sent
// on every request via the "API-Key" header (strictly that name — urlscan
// rejects x-api-key) and is never placed in a URL, logged, or surfaced in an
// error. The client retries 429 and 5xx responses with exponential backoff +
// jitter (honoring Retry-After / X-Rate-Limit-Reset), implemented with the
// standard library only — no nlk, no third-party dependency. Response
// dialects are absorbed into normalized Result / SearchHit / Quota types here,
// so the engine, CLI, and MCP server never see raw urlscan JSON.
package urlscan
