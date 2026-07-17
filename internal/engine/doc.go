// Package engine ties validation, the urlscan client, and the result cache
// together behind one API shared by the CLI and the MCP server, so their
// behaviour cannot diverge. It is the only clock reader. Passive reads
// (result, search, quota) are cache-aware; active scans are never cached.
// Submit and Poll are separate so the MCP server can return a UUID
// immediately (async job style) while the CLI polls to completion.
package engine
