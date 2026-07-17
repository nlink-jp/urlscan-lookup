package urlscan

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// fakeDoer returns a queued sequence of responses.
type fakeDoer struct {
	responses []*http.Response
	errs      []error
	calls     int
}

func (f *fakeDoer) Do(*http.Request) (*http.Response, error) {
	i := f.calls
	f.calls++
	if i < len(f.errs) && f.errs[i] != nil {
		return nil, f.errs[i]
	}
	return f.responses[i], nil
}

func resp(status int, body string, headers map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     h,
	}
}

func newTestClient(d Doer) *Client {
	c := NewClient("https://urlscan.io", "test-key", "ua", time.Second)
	c.HTTP = d
	c.BaseDelay = time.Millisecond
	// No real sleeping in tests.
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

func TestResultNotReadyAndGone(t *testing.T) {
	c := newTestClient(&fakeDoer{responses: []*http.Response{resp(404, "", nil)}})
	if _, _, err := c.Result(context.Background(), "01234567-89ab-cdef-0123-456789abcdef"); !errors.Is(err, ErrNotReady) {
		t.Fatalf("404: got %v, want ErrNotReady", err)
	}
	c = newTestClient(&fakeDoer{responses: []*http.Response{resp(410, "", nil)}})
	if _, _, err := c.Result(context.Background(), "01234567-89ab-cdef-0123-456789abcdef"); !errors.Is(err, ErrGone) {
		t.Fatalf("410: got %v, want ErrGone", err)
	}
}

func TestRetryThenRateLimited(t *testing.T) {
	// Three 429s exhaust the default 3 retries → ErrRateLimited. urlscan
	// sends the rate-limit headers on every 429.
	rlHdr := map[string]string{"X-Rate-Limit-Action": "private", "Retry-After": "0"}
	d := &fakeDoer{responses: []*http.Response{
		resp(429, `{"message":"quota"}`, rlHdr),
		resp(429, `{"message":"quota"}`, rlHdr),
		resp(429, `{"message":"quota"}`, rlHdr),
		resp(429, `{"message":"quota"}`, rlHdr),
	}}
	c := newTestClient(d)
	_, rl, err := c.Result(context.Background(), "01234567-89ab-cdef-0123-456789abcdef")
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("got %v, want ErrRateLimited", err)
	}
	if d.calls != 4 {
		t.Fatalf("calls = %d, want 4 (1 + 3 retries)", d.calls)
	}
	if rl == nil || rl.Action != "private" {
		t.Fatalf("rate limit not surfaced: %+v", rl)
	}
}

func TestRetryThenSuccess(t *testing.T) {
	d := &fakeDoer{responses: []*http.Response{
		resp(503, "", nil),
		resp(200, `{"task":{"uuid":"u1"},"page":{"ip":"1.2.3.4"},"verdicts":{"overall":{"malicious":true,"score":80}}}`, nil),
	}}
	c := newTestClient(d)
	res, _, err := c.Result(context.Background(), "01234567-89ab-cdef-0123-456789abcdef")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Malicious || res.Score != 80 || res.IP != "1.2.3.4" {
		t.Fatalf("normalize failed: %+v", res)
	}
}

func TestSubmitAndNoKey(t *testing.T) {
	d := &fakeDoer{responses: []*http.Response{resp(200, `{"uuid":"abc","visibility":"private","result":"https://urlscan.io/result/abc/"}`, nil)}}
	c := newTestClient(d)
	sub, _, err := c.Submit(context.Background(), SubmitRequest{URL: "https://x.test", Visibility: "private"})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if sub.UUID != "abc" || sub.Visibility != "private" {
		t.Fatalf("submit response: %+v", sub)
	}

	c.Key = ""
	if _, _, err := c.Submit(context.Background(), SubmitRequest{URL: "https://x.test"}); !errors.Is(err, ErrNoKey) {
		t.Fatalf("no key: got %v, want ErrNoKey", err)
	}
}

func TestParseRateLimit(t *testing.T) {
	h := http.Header{}
	h.Set("X-Rate-Limit-Scope", "user")
	h.Set("X-Rate-Limit-Action", "search")
	h.Set("X-Rate-Limit-Limit", "100")
	h.Set("X-Rate-Limit-Remaining", "42")
	h.Set("X-Rate-Limit-Reset", "2026-07-17T00:00:00Z")
	rl := parseRateLimit(h)
	if rl.Scope != "user" || rl.Action != "search" || rl.Limit != 100 || rl.Remaining != 42 {
		t.Fatalf("parseRateLimit: %+v", rl)
	}
	if rl.Reset != "2026-07-17T00:00:00Z" {
		t.Fatalf("reset = %q", rl.Reset)
	}
}

func TestNormalizeSearchAndQuota(t *testing.T) {
	sr, err := normalizeSearch([]byte(`{"total":2,"has_more":true,"results":[{"task":{"uuid":"a","time":"t","url":"https://a"},"page":{"ip":"1.1.1.1","domain":"a"}}]}`))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if sr.Total != 2 || !sr.HasMore || len(sr.Results) != 1 || sr.Results[0].IP != "1.1.1.1" {
		t.Fatalf("search normalize: %+v", sr)
	}
	q, err := normalizeQuota([]byte(`{"limits":{"private":{"day":{"limit":50,"used":3,"remaining":47}}}}`))
	if err != nil {
		t.Fatalf("quota: %v", err)
	}
	if q.Actions["private"].Day.Remaining != 47 {
		t.Fatalf("quota normalize: %+v", q.Actions)
	}
}

// TestNormalizeQuotaMixedLimits pins the fix for urlscan's real /user/quotas/
// shape, where the "limits" object mixes per-action window objects with plan
// metadata (scalars, arrays, and a nested files object). Only true action
// quotas must be extracted; metadata must not break the parse.
func TestNormalizeQuotaMixedLimits(t *testing.T) {
	body := []byte(`{
      "scope":"user",
      "limits":{
        "private":{"day":{"limit":50,"used":1,"remaining":49},"hour":{"limit":50},"minute":{"limit":5}},
        "search":{"day":{"limit":1000},"hour":{"limit":1000},"minute":{"limit":120}},
        "files":{"public":{"day":{"limit":100}},"private":{"day":{"limit":10}}},
        "features":[],
        "queryVisibility":["public"],
        "queryableFields":["asn","domain.*"],
        "maxSearchResults":1000,
        "maxRetentionPeriodDays":7
      }}`)
	q, err := normalizeQuota(body)
	if err != nil {
		t.Fatalf("mixed quota: %v", err)
	}
	if q.Scope != "user" {
		t.Fatalf("scope = %q", q.Scope)
	}
	if q.Actions["private"].Day.Remaining != 49 || q.Actions["search"].Minute.Limit != 120 {
		t.Fatalf("actions: %+v", q.Actions)
	}
	if _, ok := q.Actions["files"]; ok {
		t.Fatal("nested files object must not be treated as an action")
	}
	if _, ok := q.Actions["queryVisibility"]; ok {
		t.Fatal("metadata array must not be treated as an action")
	}
	if q.MaxSearchResults != 1000 || q.RetentionDays != 7 || len(q.QueryVisibility) != 1 || q.QueryVisibility[0] != "public" {
		t.Fatalf("metadata: %+v", q)
	}
}

func TestBrandNamesPolymorphic(t *testing.T) {
	if got := brandNames([]byte(`["PayPal","Apple"]`)); len(got) != 2 || got[0] != "PayPal" {
		t.Fatalf("string brands: %v", got)
	}
	if got := brandNames([]byte(`[{"name":"PayPal"},{"name":"Apple"}]`)); len(got) != 2 || got[1] != "Apple" {
		t.Fatalf("object brands: %v", got)
	}
	if got := brandNames(nil); got != nil {
		t.Fatalf("nil brands: %v", got)
	}
}
