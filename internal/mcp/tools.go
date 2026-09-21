package mcp

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nlink-jp/urlscan-lookup/internal/config"
	"github.com/nlink-jp/urlscan-lookup/internal/engine"
	"github.com/nlink-jp/urlscan-lookup/internal/urlscan"
	"github.com/nlink-jp/urlscan-lookup/internal/validate"
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

// obj builds a tool's input schema. Every schema goes through here so that
// org ADR-021 §10's `additionalProperties: false` is set once instead of being
// remembered per tool — the next tool added gets the closed schema for free.
func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

// decodeArgs decodes a tool's arguments strictly: an argument the tool does not
// declare is refused by name, and a malformed argument object is refused rather
// than read as an empty one.
//
// obj() above is only the declared half of org ADR-021 §4 — what a
// schema-checking client refuses before the call. This is the half that
// actually refuses, and it is needed because not every client checks the
// schema. The `_ = json.Unmarshal` this replaces discarded the decode error as
// well as the unknown field, so both defects were silent in the same way — and
// on this server the consequence is the sharpest in the fleet: a misspelt
// `visibility` fell back to the configured default, so a caller that asked for
// a private scan and typo'd the argument got whatever the config said, and a
// caller that deliberately asked for a public one silently did not publish.
//
// Every tool goes through this, `get_screenshot` included: its `workspace_root`
// argument went away with the file it named (ADR-0001), so there is no longer a
// retired spelling to answer for.
func decodeArgs(raw json.RawMessage, into any) error {
	raw = bytes.TrimSpace(raw)
	// Omitted or null arguments mean the empty object, not an error: a tool
	// whose arguments are all optional is legitimately called with none.
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return errors.New("arguments: " + err.Error())
	}
	return nil
}

// toolsList returns the advertised tool set with JSON Schema for each input.
func toolsList() any {
	return map[string]any{
		"tools": []map[string]any{
			{
				"name":        "get_usage",
				"description": "Return this server's operating manual (markdown): the tools, result schema, quota notes, and error-recovery table. Call it once before first use.",
				"inputSchema": obj(map[string]any{}),
			},
			{
				"name":        "scan_url",
				"description": "Submit a NEW active scan of a URL to urlscan.io and return its uuid immediately (the scan runs asynchronously — poll get_result with the uuid). Default visibility is PRIVATE (visible only to this account); pass visibility \"public\" ONLY to deliberately publish the scan to the world (including the attacker). Consumes the low free-plan scan quota.",
				"inputSchema": obj(map[string]any{
					"url":        map[string]any{"type": "string", "description": "The http(s) URL to scan."},
					"visibility": map[string]any{"type": "string", "enum": []string{"private", "unlisted", "public"}, "description": "Scan visibility (default private)."},
					"country":    map[string]any{"type": "string", "description": "Scanning PoP country code, e.g. jp, de (to defeat geo-fenced phishing)."},
					"tags":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Tags to attach."},
					"referer":    map[string]any{"type": "string", "description": "Referer header to send."},
					"user_agent": map[string]any{"type": "string", "description": "User-Agent to send."},
				}, "url"),
			},
			{
				"name":        "get_result",
				"description": "Fetch a scan result by uuid. While the scan is still running it returns {status:\"processing\"} — that is normal; poll again after a few seconds. Returns the normalized verdict, final URL, observed IPs/domains, and counts.",
				"inputSchema": obj(map[string]any{
					"uuid":    map[string]any{"type": "string", "description": "The scan uuid returned by scan_url."},
					"refresh": map[string]any{"type": "boolean", "description": "Bypass the local cache and re-fetch."},
				}, "uuid"),
			},
			{
				"name":        "search",
				"description": "Search the historical PUBLIC scan database (passive; never touches the target — OpSec-safe). Query uses urlscan's ElasticSearch syntax, e.g. 'domain:example.com' or 'page.ip:1.2.3.4'.",
				"inputSchema": obj(map[string]any{
					"query":        map[string]any{"type": "string", "description": "urlscan search query (ElasticSearch syntax)."},
					"size":         map[string]any{"type": "integer", "description": "Number of results (default 100)."},
					"search_after": map[string]any{"type": "string", "description": "Pagination cursor (sort value of the last row)."},
					"refresh":      map[string]any{"type": "boolean", "description": "Bypass the local cache and re-fetch."},
				}, "query"),
			},
			{
				"name":        "get_screenshot",
				"description": "Fetch a scan's screenshot PNG. It comes back inline as MCP image content when it fits the server's budget (4 MiB by default) so you can look at it directly. A larger one is not returned as bytes and is not written anywhere: the reply carries its size, the budget that stopped it, and the urlscan.io URL to fetch it from. Nothing is written to disk.",
				"inputSchema": obj(map[string]any{
					"uuid":   map[string]any{"type": "string", "description": "The scan uuid."},
					"inline": map[string]any{"type": "boolean", "description": "Return the image inline when it fits the budget (default true). Set false if your client cannot take image content; the reply then carries the size and the URL only."},
				}, "uuid"),
			},
			{
				"name":        "get_quota",
				"description": "Report the account's remaining urlscan API quota per action (public/private/unlisted scan, search, retrieve) across the day/hour/minute windows. Free-plan quotas are low — check before batch scanning.",
				"inputSchema": obj(map[string]any{}),
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
		// No arguments — which still means "none", not "any".
		if err := decodeArgs(p.Arguments, &struct{}{}); err != nil {
			return errorResult("invalid_input", err.Error()), nil
		}
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
		if err := decodeArgs(p.Arguments, &struct{}{}); err != nil {
			return errorResult("invalid_input", err.Error()), nil
		}
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
	if err := decodeArgs(args, &a); err != nil {
		return errorResult("invalid_input", err.Error())
	}
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
	if err := decodeArgs(args, &a); err != nil {
		return errorResult("invalid_input", err.Error())
	}
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
	if err := decodeArgs(args, &a); err != nil {
		return errorResult("invalid_input", err.Error())
	}
	if a.Query == "" {
		return errorResult("invalid_input", "provide 'query' (urlscan ElasticSearch syntax)")
	}
	res, err := s.e.Search(ctx, a.Query, a.Size, a.SearchAfter, a.Refresh)
	if err != nil {
		return mapError(err)
	}
	return jsonResult(res)
}

// inlineImageBudget caps the PNG returned inline as MCP image content. Base64
func (s *server) toolGetScreenshot(ctx context.Context, args json.RawMessage) toolResult {
	var a struct {
		UUID   string `json:"uuid"`
		Inline *bool  `json:"inline"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return errorResult("invalid_input", err.Error())
	}
	if a.UUID == "" {
		return errorResult("invalid_input", "provide 'uuid'")
	}
	clean, err := validate.UUID(a.UUID)
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

	budget := s.cfg.ScreenshotMaxBytes
	if budget <= 0 {
		budget = config.DefaultScreenshotMaxBytes
	}
	inline := (a.Inline == nil || *a.Inline) && len(png) <= budget
	out := map[string]any{
		"uuid":           clean,
		"bytes":          len(png),
		"inline":         inline,
		"screenshot_url": screenshotURL(s.cfg.BaseURL, clean),
	}
	// A screenshot is the one result here a model has to *see*, and MCP carries
	// image content natively. What this server does NOT do is turn the image
	// into a file of its own choosing above a threshold and hand back a path:
	// that shape was retired fleet-wide on 2026-09-06 — a server cannot know the
	// caller's context window, and putting a large response on disk is the
	// runtime's job. So an oversized screenshot is reported, not delivered, and
	// the URL is what anyone (runtime or person) fetches it from.
	if !inline {
		out["note"] = fmt.Sprintf("screenshot is %d bytes, above the %d-byte inline budget; "+
			"fetch it from screenshot_url", len(png), budget)
	}
	res := jsonResult(out)
	if inline {
		res.Content = append(res.Content, contentItem{
			Type:     "image",
			Data:     base64.StdEncoding.EncodeToString(png),
			MimeType: "image/png",
		})
	}
	return res
}

// screenshotURL is urlscan.io's own address for a scan's PNG — the same path
// the client fetches. Reported rather than guessed at by the caller, and the
// only thing this server hands back when the image is too large to inline.
func screenshotURL(baseURL, uuid string) string {
	return strings.TrimRight(baseURL, "/") + "/screenshots/" + uuid + ".png"
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
