// Package mcp is a zero-dependency stdio JSON-RPC 2.0 MCP server exposing the
// urlscan engine. Scans are asynchronous: scan_url submits and returns the
// UUID immediately (never blocking the MCP request), and get_result polls —
// "still processing" is a normal response, not an error. Binary and large
// outputs (screenshots) are file-mediated through an agent-provided
// workspace_root. Diagnostics go to stderr only; stdout carries the protocol.
package mcp
