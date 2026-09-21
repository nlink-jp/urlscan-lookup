// Package mcp is a zero-dependency stdio JSON-RPC 2.0 MCP server exposing the
// urlscan engine. Scans are asynchronous: scan_url submits and returns the
// UUID immediately (never blocking the MCP request), and get_result polls —
// "still processing" is a normal response, not an error. A screenshot comes
// back as MCP image content when it fits the server's inline budget; one that
// does not is reported with its size and its urlscan.io URL, because a server
// does not choose a file for data (organization decision of 2026-09-06, this
// project's ADR-0001). Nothing is written to disk. Diagnostics go to stderr
// only; stdout carries the protocol.
package mcp
