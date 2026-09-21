package mcp

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nlink-jp/urlscan-lookup/internal/urlscan"
)

// errText returns a tool error's code and message. toolText decodes the
// result body, which for an error is the {code, message} pair.
func errText(t *testing.T, r response) (string, string, bool) {
	t.Helper()
	m, isErr := toolText(t, r)
	code, _ := m["code"].(string)
	msg, _ := m["message"].(string)
	return code, msg, isErr
}

// TestUnknownArgumentIsRefusedByName is the enforcing half of org ADR-021 §4:
// additionalProperties:false only tells a client what is allowed, and a client
// that does not check the schema sends the typo anyway. Every tool must refuse
// it, and the message must name the offending field — a caller that is told
// only "invalid arguments" has to re-read the schema to find its own typo.
//
// `visibility` is the sharpest case in the fleet. Dropped, it falls back to
// the configured default, so a typo turns "scan this privately" into "scan it
// however the config says" and turns a deliberate `public` into a scan that
// was never published — and on this server the difference is whether the
// attacker can see that they are being investigated.
func TestUnknownArgumentIsRefusedByName(t *testing.T) {
	cases := []struct {
		tool  string
		args  string
		field string
	}{
		{"scan_url", `{"url":"https://example.com","visibilty":"public"}`, "visibilty"},
		{"scan_url", `{"url":"https://example.com","useragent":"x"}`, "useragent"},
		{"get_result", `{"uuid":"u1","refesh":true}`, "refesh"},
		{"search", `{"query":"domain:example.com","limit":10}`, "limit"},
		{"get_quota", `{"verbose":true}`, "verbose"},
		{"get_usage", `{"topic":"visibility"}`, "topic"},
	}
	for _, tc := range cases {
		t.Run(tc.tool+"/"+tc.field, func(t *testing.T) {
			fc := &fakeClient{
				submit: &urlscan.SubmitResponse{UUID: "u1", Visibility: "private"},
				result: &urlscan.Result{},
				quota:  &urlscan.Quota{},
			}
			req := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, tc.tool, tc.args)
			code, msg, isErr := errText(t, drive(t, fc, req)[0])
			if !isErr {
				t.Fatalf("%s accepted unknown argument %q: %s", tc.tool, tc.field, msg)
			}
			if code != "invalid_input" {
				t.Errorf("%s: error code = %q, want invalid_input", tc.tool, code)
			}
			// Matching the decoder's own phrasing, not just the field name: a
			// message like "provide 'uuid'" happens to contain "uuid", so a
			// bare substring test can pass for the wrong reason.
			want := `unknown field "` + tc.field + `"`
			if !strings.Contains(msg, want) {
				t.Errorf("%s: error does not name the offending argument: want %s, got %s", tc.tool, want, msg)
			}
		})
	}
}

// TestMalformedArgumentsAreRefused covers the other half of the discarded
// error: `_ = json.Unmarshal` left `a` at its zero value when the object did
// not decode, so a wrong-typed argument produced the same call as an absent
// one — and "provide 'url'" is a misleading answer to a request that did
// provide it.
func TestMalformedArgumentsAreRefused(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args string
	}{
		{"number for string", "scan_url", `{"url":1}`},
		{"string for array", "scan_url", `{"url":"https://example.com","tags":"phish"}`},
		{"array for object", "scan_url", `["https://example.com"]`},
		{"number for string", "get_result", `{"uuid":1}`},
		{"string for integer", "search", `{"query":"domain:example.com","size":"all"}`},
	}
	for _, tc := range cases {
		t.Run(tc.tool+"/"+tc.name, func(t *testing.T) {
			fc := &fakeClient{
				submit: &urlscan.SubmitResponse{UUID: "u1"},
				result: &urlscan.Result{},
			}
			req := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, tc.tool, tc.args)
			_, msg, isErr := errText(t, drive(t, fc, req)[0])
			if !isErr {
				t.Fatalf("%s accepted malformed arguments: %s", tc.tool, msg)
			}
			if strings.Contains(msg, "provide '") {
				t.Errorf("%s reported the argument as missing instead of malformed: %s", tc.tool, msg)
			}
			if !strings.Contains(msg, "arguments:") {
				t.Errorf("%s: error is not a decode error: %s", tc.tool, msg)
			}
		})
	}
}

// TestOmittedArgumentsStillMeanNone pins the boundary of the change: strict
// decoding must not turn a legitimately argument-less call into an error.
func TestOmittedArgumentsStillMeanNone(t *testing.T) {
	for _, args := range []string{``, `,"arguments":{}`, `,"arguments":null`} {
		fc := &fakeClient{quota: &urlscan.Quota{}}
		req := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_quota"%s}}`, args)
		_, msg, isErr := errText(t, drive(t, fc, req)[0])
		if isErr {
			t.Errorf("get_quota with arguments %q was refused: %s", args, msg)
		}
	}
}

// The handler that used to be outside the sweep. Its `workspace_root` went away
// with the file it named (ADR-0001), so there is no retired spelling left to
// answer for and no reason to be lenient here.
func TestGetScreenshotRefusesAnUnknownArgument(t *testing.T) {
	fc := &fakeClient{png: []byte("png")}
	req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_screenshot","arguments":{"uuid":"0199b3c4-0000-4000-8000-000000000000","workspace_root":"/tmp"}}}`
	_, msg, isErr := errText(t, drive(t, fc, req)[0])
	if !isErr || !strings.Contains(msg, "unknown field") || !strings.Contains(msg, "workspace_root") {
		t.Fatalf("an unknown argument must be refused by name: isError=%v msg=%q", isErr, msg)
	}
}
