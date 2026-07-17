package mcp

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nlink-jp/urlscan-lookup/internal/engine"
	"github.com/nlink-jp/urlscan-lookup/internal/urlscan"
	"github.com/nlink-jp/urlscan-lookup/internal/validate"
	"github.com/nlink-jp/urlscan-lookup/internal/workspace"
)

// usageMarkdown is the operating manual returned by the get_usage tool.
//
//go:embed usage.md
var usageMarkdown string

// Instructions is the initialize-time hint that makes get_usage discoverable
// and steers clients away from common errors.
const Instructions = "urlscan-lookup investigates a suspicious URL via the urlscan.io API. " +
	"Scans are asynchronous: scan_url submits and returns a uuid immediately (default visibility PRIVATE — " +
	"pass visibility \"public\" only to deliberately publish the scan to the world), then poll get_result " +
	"with that uuid (a \"processing\" status is normal, not an error). Use search for OpSec-safe historical " +
	"lookups that never touch the target. Tool errors are structured JSON ({code, message}). " +
	"Call get_usage for the full tool reference, quota notes, and error-recovery table."

// toolsList returns the advertised tool set with JSON Schema for each input.
func toolsList() any {
	return map[string]any{
		"tools": []map[string]any{
			{
				"name":        "get_usage",
				"description": "Return this server's operating manual (markdown): the tools, result schema, quota notes, and error-recovery table. Call it once before first use.",
				"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
			},
			{
				"name":        "scan_url",
				"description": "Submit a NEW active scan of a URL to urlscan.io and return its uuid immediately (the scan runs asynchronously — poll get_result with the uuid). Default visibility is PRIVATE (visible only to this account); pass visibility \"public\" ONLY to deliberately publish the scan to the world (including the attacker). Consumes the low free-plan scan quota.",
				"inputSchema": map[string]any{
					"type":     "object",
					"required": []string{"url"},
					"properties": map[string]any{
						"url":        map[string]any{"type": "string", "description": "The http(s) URL to scan."},
						"visibility": map[string]any{"type": "string", "enum": []string{"private", "unlisted", "public"}, "description": "Scan visibility (default private)."},
						"country":    map[string]any{"type": "string", "description": "Scanning PoP country code, e.g. jp, de (to defeat geo-fenced phishing)."},
						"tags":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Tags to attach."},
						"referer":    map[string]any{"type": "string", "description": "Referer header to send."},
						"user_agent": map[string]any{"type": "string", "description": "User-Agent to send."},
					},
				},
			},
			{
				"name":        "get_result",
				"description": "Fetch a scan result by uuid. While the scan is still running it returns {status:\"processing\"} — that is normal; poll again after a few seconds. Returns the normalized verdict, final URL, observed IPs/domains, and counts.",
				"inputSchema": map[string]any{
					"type":     "object",
					"required": []string{"uuid"},
					"properties": map[string]any{
						"uuid":    map[string]any{"type": "string", "description": "The scan uuid returned by scan_url."},
						"refresh": map[string]any{"type": "boolean", "description": "Bypass the local cache and re-fetch."},
					},
				},
			},
			{
				"name":        "search",
				"description": "Search the historical PUBLIC scan database (passive; never touches the target — OpSec-safe). Query uses urlscan's ElasticSearch syntax, e.g. 'domain:example.com' or 'page.ip:1.2.3.4'.",
				"inputSchema": map[string]any{
					"type":     "object",
					"required": []string{"query"},
					"properties": map[string]any{
						"query":        map[string]any{"type": "string", "description": "urlscan search query (ElasticSearch syntax)."},
						"size":         map[string]any{"type": "integer", "description": "Number of results (default 100)."},
						"search_after": map[string]any{"type": "string", "description": "Pagination cursor (sort value of the last row)."},
						"refresh":      map[string]any{"type": "boolean", "description": "Bypass the local cache and re-fetch."},
					},
				},
			},
			{
				"name":        "get_screenshot",
				"description": "Save a scan's screenshot PNG to a workspace directory and return the file path (never returns image bytes).",
				"inputSchema": map[string]any{
					"type":     "object",
					"required": []string{"uuid"},
					"properties": map[string]any{
						"uuid":           map[string]any{"type": "string", "description": "The scan uuid."},
						"workspace_root": map[string]any{"type": "string", "description": "Directory to write the PNG into (an agent-prepared writable dir). Defaults to the server workspace."},
					},
				},
			},
			{
				"name":        "get_quota",
				"description": "Report the account's remaining urlscan API quota per action (public/private/unlisted scan, search, retrieve) across the day/hour/minute windows. Free-plan quotas are low — check before batch scanning.",
				"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
			},
		},
	}
}

func (s *server) toolsCall(params json.RawMessage) (toolResult, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return toolResult{}, &rpcError{Code: -32602, Message: "invalid params: " + err.Error()}
	}
	ctx := context.Background()
	switch p.Name {
	case "get_usage":
		return textResult(false, usageMarkdown), nil
	case "scan_url":
		return s.toolScanURL(ctx, p.Arguments), nil
	case "get_result":
		return s.toolGetResult(ctx, p.Arguments), nil
	case "search":
		return s.toolSearch(ctx, p.Arguments), nil
	case "get_screenshot":
		return s.toolGetScreenshot(ctx, p.Arguments), nil
	case "get_quota":
		return s.toolGetQuota(ctx), nil
	default:
		return toolResult{}, &rpcError{Code: -32602, Message: "unknown tool: " + p.Name}
	}
}

func (s *server) toolScanURL(ctx context.Context, args json.RawMessage) toolResult {
	var a struct {
		URL        string   `json:"url"`
		Visibility string   `json:"visibility"`
		Country    string   `json:"country"`
		Tags       []string `json:"tags"`
		Referer    string   `json:"referer"`
		UserAgent  string   `json:"user_agent"`
	}
	_ = json.Unmarshal(args, &a)
	if a.URL == "" {
		return errorResult("invalid_input", "provide 'url' (an http(s) URL to scan)")
	}
	vis := a.Visibility
	if vis == "" {
		vis = s.cfg.Visibility
	}
	sub, err := s.e.Submit(ctx, a.URL, engine.ScanOptions{
		Visibility: vis,
		Country:    a.Country,
		Tags:       a.Tags,
		Referer:    a.Referer,
		UserAgent:  a.UserAgent,
	})
	if err != nil {
		return mapError(err)
	}
	return jsonResult(map[string]any{
		"status":     "submitted",
		"uuid":       sub.UUID,
		"visibility": sub.Visibility,
		"result_url": sub.Result,
		"message":    "scan submitted; poll get_result with this uuid (allow ~10s before the first poll)",
	})
}

func (s *server) toolGetResult(ctx context.Context, args json.RawMessage) toolResult {
	var a struct {
		UUID    string `json:"uuid"`
		Refresh bool   `json:"refresh"`
	}
	_ = json.Unmarshal(args, &a)
	if a.UUID == "" {
		return errorResult("invalid_input", "provide 'uuid'")
	}
	res, err := s.e.Result(ctx, a.UUID, a.Refresh)
	switch {
	case errors.Is(err, urlscan.ErrNotReady):
		return jsonResult(map[string]any{"status": "processing", "uuid": a.UUID,
			"message": "scan is still running; poll again in a few seconds"})
	case errors.Is(err, urlscan.ErrGone):
		return errorResult("gone", "scan result has been deleted")
	case err != nil:
		return mapError(err)
	}
	return jsonResult(res)
}

func (s *server) toolSearch(ctx context.Context, args json.RawMessage) toolResult {
	var a struct {
		Query       string `json:"query"`
		Size        int    `json:"size"`
		SearchAfter string `json:"search_after"`
		Refresh     bool   `json:"refresh"`
	}
	_ = json.Unmarshal(args, &a)
	if a.Query == "" {
		return errorResult("invalid_input", "provide 'query' (urlscan ElasticSearch syntax)")
	}
	res, err := s.e.Search(ctx, a.Query, a.Size, a.SearchAfter, a.Refresh)
	if err != nil {
		return mapError(err)
	}
	return jsonResult(res)
}

func (s *server) toolGetScreenshot(ctx context.Context, args json.RawMessage) toolResult {
	var a struct {
		UUID          string `json:"uuid"`
		WorkspaceRoot string `json:"workspace_root"`
	}
	_ = json.Unmarshal(args, &a)
	if a.UUID == "" {
		return errorResult("invalid_input", "provide 'uuid'")
	}
	clean, err := validate.UUID(a.UUID)
	if err != nil {
		return errorResult("invalid_input", err.Error())
	}
	dir := a.WorkspaceRoot
	if dir == "" {
		dir = s.cfg.WorkspaceDir
	}
	ws, err := workspace.Ensure(dir)
	if err != nil {
		return errorResult("invalid_input", err.Error())
	}
	png, err := s.e.Screenshot(ctx, clean)
	if errors.Is(err, urlscan.ErrNotReady) {
		return errorResult("not_ready", "screenshot not available (scan still processing or has none)")
	}
	if err != nil {
		return mapError(err)
	}
	path, err := ws.WriteFileAtomic(clean+".png", png)
	if err != nil {
		return errorResult("workspace_error", err.Error())
	}
	return jsonResult(map[string]any{"uuid": clean, "screenshot_file": path, "bytes": len(png)})
}

func (s *server) toolGetQuota(ctx context.Context) toolResult {
	q, err := s.e.Quota(ctx)
	if err != nil {
		return mapError(err)
	}
	return jsonResult(q)
}

// mapError translates engine/client errors into structured tool errors.
func mapError(err error) toolResult {
	switch {
	case errors.Is(err, validate.ErrInvalid):
		return errorResult("invalid_input", err.Error())
	case errors.Is(err, urlscan.ErrNoKey):
		return errorResult("no_api_key", "no urlscan API key configured (set URLSCAN_API_KEY)")
	case errors.Is(err, urlscan.ErrRateLimited):
		return errorResult("rate_limited", err.Error())
	case errors.Is(err, engine.ErrPollTimeout):
		return errorResult("timeout", err.Error())
	default:
		return errorResult("network_error", err.Error())
	}
}

// errorResult renders a structured tool error: {code, message}.
func errorResult(code, message string) toolResult {
	b, _ := json.Marshal(map[string]string{"code": code, "message": message})
	return textResult(true, string(b))
}

// jsonResult marshals v into a non-error text result.
func jsonResult(v any) toolResult {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errorResult("network_error", fmt.Sprintf("encode result: %v", err))
	}
	return textResult(false, string(b))
}
