package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/urlscan-lookup/internal/cache"
	"github.com/nlink-jp/urlscan-lookup/internal/config"
	"github.com/nlink-jp/urlscan-lookup/internal/engine"
	"github.com/nlink-jp/urlscan-lookup/internal/urlscan"
)

// fakeClient is a scripted engine.Client for driving the server.
type fakeClient struct {
	png       []byte // Screenshot payload; nil uses a tiny stub
	submit    *urlscan.SubmitResponse
	resultErr error
	result    *urlscan.Result
	quota     *urlscan.Quota
}

func (f *fakeClient) Submit(context.Context, urlscan.SubmitRequest) (*urlscan.SubmitResponse, *urlscan.RateLimit, error) {
	return f.submit, nil, nil
}
func (f *fakeClient) Result(context.Context, string) (*urlscan.Result, *urlscan.RateLimit, error) {
	return f.result, nil, f.resultErr
}
func (f *fakeClient) Search(context.Context, string, int, string) (*urlscan.SearchResult, *urlscan.RateLimit, error) {
	return &urlscan.SearchResult{Total: 0}, nil, nil
}
func (f *fakeClient) Quota(context.Context) (*urlscan.Quota, *urlscan.RateLimit, error) {
	return f.quota, nil, nil
}
func (f *fakeClient) Screenshot(context.Context, string) ([]byte, error) {
	if f.png != nil {
		return f.png, nil
	}
	return []byte("png"), nil
}

func testServer(t *testing.T, fc *fakeClient) (*engine.Engine, *config.Config) {
	t.Helper()
	cfg := &config.Config{Visibility: "private", CacheDir: t.TempDir(), CacheTTL: time.Hour, SearchSize: 100}
	e := &engine.Engine{
		Cfg:    cfg,
		Client: fc,
		Cache:  &cache.Store{Dir: cfg.CacheDir},
		Now:    func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	return e, cfg
}

// drive feeds newline-delimited JSON-RPC requests and returns the decoded
// responses.
func drive(t *testing.T, fc *fakeClient, requests ...string) []response {
	t.Helper()
	e, cfg := testServer(t, fc)
	in := strings.NewReader(strings.Join(requests, "\n") + "\n")
	var out strings.Builder
	if err := Serve(e, cfg, "test", in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resps []response
	dec := json.NewDecoder(strings.NewReader(out.String()))
	for dec.More() {
		var r response
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		resps = append(resps, r)
	}
	return resps
}

func toolText(t *testing.T, r response) (map[string]any, bool) {
	t.Helper()
	b, _ := json.Marshal(r.Result)
	var tr toolResult
	if err := json.Unmarshal(b, &tr); err != nil || len(tr.Content) == 0 {
		t.Fatalf("not a tool result: %s", b)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(tr.Content[0].Text), &m)
	return m, tr.IsError
}

func TestInitializeAndToolsList(t *testing.T) {
	resps := drive(t, &fakeClient{},
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	)
	if len(resps) != 2 {
		t.Fatalf("want 2 responses, got %d", len(resps))
	}
	b, _ := json.Marshal(resps[1].Result)
	for _, want := range []string{"scan_url", "get_result", "search", "get_screenshot", "get_quota", "get_usage"} {
		if !strings.Contains(string(b), `"`+want+`"`) {
			t.Fatalf("tools/list missing %q: %s", want, b)
		}
	}
}

func TestScanURLReturnsUUID(t *testing.T) {
	fc := &fakeClient{submit: &urlscan.SubmitResponse{UUID: "u1", Visibility: "private", Result: "https://urlscan.io/result/u1/"}}
	resps := drive(t, fc,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan_url","arguments":{"url":"https://evil.test/login"}}}`,
	)
	m, isErr := toolText(t, resps[0])
	if isErr {
		t.Fatalf("scan_url errored: %v", m)
	}
	if m["uuid"] != "u1" || m["status"] != "submitted" {
		t.Fatalf("scan_url result: %v", m)
	}
}

func TestScanURLRejectsBadURL(t *testing.T) {
	resps := drive(t, &fakeClient{},
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan_url","arguments":{"url":"ftp://x"}}}`,
	)
	m, isErr := toolText(t, resps[0])
	if !isErr || m["code"] != "invalid_input" {
		t.Fatalf("want invalid_input error, got %v", m)
	}
}

func TestGetResultProcessing(t *testing.T) {
	fc := &fakeClient{resultErr: urlscan.ErrNotReady}
	resps := drive(t, fc,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_result","arguments":{"uuid":"01234567-89ab-cdef-0123-456789abcdef"}}}`,
	)
	m, isErr := toolText(t, resps[0])
	if isErr {
		t.Fatalf("processing should be a normal response, not an error: %v", m)
	}
	if m["status"] != "processing" {
		t.Fatalf("want status processing, got %v", m)
	}
}

func TestNotificationGetsNoReply(t *testing.T) {
	resps := drive(t, &fakeClient{},
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":9,"method":"ping"}`,
	)
	if len(resps) != 1 {
		t.Fatalf("notification must not be answered; want 1 response, got %d", len(resps))
	}
}

func TestGetUsageNonEmpty(t *testing.T) {
	resps := drive(t, &fakeClient{},
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_usage"}}`,
	)
	b, _ := json.Marshal(resps[0].Result)
	if !strings.Contains(string(b), "operating manual") {
		t.Fatalf("get_usage should return the manual: %s", b)
	}
}

// toolContent returns the raw content blocks of a tool result.
func toolContent(t *testing.T, r response) []contentItem {
	t.Helper()
	b, _ := json.Marshal(r.Result)
	var tr toolResult
	if err := json.Unmarshal(b, &tr); err != nil {
		t.Fatalf("not a tool result: %s", b)
	}
	return tr.Content
}

func screenshotCall(t *testing.T, fc *fakeClient, extra string) []contentItem {
	t.Helper()
	ws := t.TempDir()
	req := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_screenshot","arguments":{"uuid":"c1b2a3d4-1111-2222-3333-444455556666","workspace_root":%q%s}}}`, ws, extra)
	return toolContent(t, drive(t, fc, req)[0])
}

// A screenshot is the one result a model has to *see*. MCP carries image
// content natively, so a small one rides inline alongside the path.
func TestGetScreenshotReturnsImageInline(t *testing.T) {
	content := screenshotCall(t, &fakeClient{}, "")
	if len(content) != 2 {
		t.Fatalf("want a text block and an image block, got %d: %+v", len(content), content)
	}
	if content[0].Type != "text" || !strings.Contains(content[0].Text, "screenshot_file") {
		t.Errorf("first block must stay the text metadata: %+v", content[0])
	}
	img := content[1]
	if img.Type != "image" || img.MimeType != "image/png" {
		t.Fatalf("second block is not PNG image content: %+v", img)
	}
	raw, err := base64.StdEncoding.DecodeString(img.Data)
	if err != nil || string(raw) != "png" {
		t.Errorf("image data does not decode to the PNG bytes: %v %q", err, raw)
	}
	if img.Text != "" {
		t.Error("an image block must not carry an empty text key — it reads as an empty answer")
	}
}

// Base64 inflates by a third and an inline image is replayed every round, so a
// large screenshot stays file-only.
func TestGetScreenshotOversizedStaysFileOnly(t *testing.T) {
	content := screenshotCall(t, &fakeClient{png: make([]byte, inlineImageBudget+1)}, "")
	if len(content) != 1 || content[0].Type != "text" {
		t.Fatalf("an oversized screenshot must not be inlined: %+v", content)
	}
	if !strings.Contains(content[0].Text, "screenshot_file") {
		t.Errorf("the path must still be returned: %s", content[0].Text)
	}
}

// A client that cannot take image content can say so.
func TestGetScreenshotInlineCanBeDeclined(t *testing.T) {
	content := screenshotCall(t, &fakeClient{}, `,"inline":false`)
	if len(content) != 1 || content[0].Type != "text" {
		t.Fatalf("inline:false must return text only: %+v", content)
	}
}

// TestEveryToolSchemaIsValidAndClosed keeps a mistyped argument from reading as
// a real one: org ADR-021 §10 requires every registered schema to set
// additionalProperties:false, and requires this assertion to exist, because a
// rule stated only in prose is re-decided by whoever adds the next tool.
//
// The flag is the declared half of the contract — what a schema-checking client
// refuses before the call. The enforcing half is decodeArgs
// (DisallowUnknownFields), which refuses an unknown argument that arrives
// anyway; TestUnknownArgumentIsRefusedByName covers it.
func TestEveryToolSchemaIsValidAndClosed(t *testing.T) {
	b, err := json.Marshal(toolsList())
	if err != nil {
		t.Fatalf("marshal tool list: %v", err)
	}
	var list struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Type                 string `json:"type"`
				AdditionalProperties *bool  `json:"additionalProperties"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("tool list is not valid JSON: %v", err)
	}
	// Without this the loop below passes by having nothing to check.
	if len(list.Tools) == 0 {
		t.Fatal("toolsList returned no tools")
	}
	for _, tool := range list.Tools {
		if tool.InputSchema.Type != "object" {
			t.Errorf("%s: schema type = %q, want object", tool.Name, tool.InputSchema.Type)
		}
		if tool.InputSchema.AdditionalProperties == nil || *tool.InputSchema.AdditionalProperties {
			t.Errorf("%s: schema should set additionalProperties:false so typos are caught", tool.Name)
		}
	}
}
