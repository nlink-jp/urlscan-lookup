package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nlink-jp/urlscan-lookup/internal/cache"
	"github.com/nlink-jp/urlscan-lookup/internal/config"
	"github.com/nlink-jp/urlscan-lookup/internal/urlscan"
	"github.com/nlink-jp/urlscan-lookup/internal/validate"
)

// fakeClient is a scripted engine.Client.
type fakeClient struct {
	submit      *urlscan.SubmitResponse
	result      *urlscan.Result
	resultErrs  []error // consumed per Result call; nil ⇒ return result
	resultCalls int
	search      *urlscan.SearchResult
	searchCalls int
	quota       *urlscan.Quota
}

func (f *fakeClient) Submit(context.Context, urlscan.SubmitRequest) (*urlscan.SubmitResponse, *urlscan.RateLimit, error) {
	return f.submit, nil, nil
}
func (f *fakeClient) Result(context.Context, string) (*urlscan.Result, *urlscan.RateLimit, error) {
	i := f.resultCalls
	f.resultCalls++
	if i < len(f.resultErrs) && f.resultErrs[i] != nil {
		return nil, nil, f.resultErrs[i]
	}
	return f.result, nil, nil
}
func (f *fakeClient) Search(context.Context, string, int, string) (*urlscan.SearchResult, *urlscan.RateLimit, error) {
	f.searchCalls++
	return f.search, nil, nil
}
func (f *fakeClient) Quota(context.Context) (*urlscan.Quota, *urlscan.RateLimit, error) {
	return f.quota, nil, nil
}
func (f *fakeClient) Screenshot(context.Context, string) ([]byte, error) {
	return []byte("png"), nil
}

func testEngine(t *testing.T, fc *fakeClient) *Engine {
	t.Helper()
	cfg := &config.Config{
		BaseURL:          "https://urlscan.io",
		Visibility:       "private",
		CacheDir:         t.TempDir(),
		CacheTTL:         time.Hour,
		SearchSize:       100,
		PollInitialDelay: 0,
		PollInterval:     0,
		PollTimeout:      time.Minute,
	}
	return &Engine{
		Cfg:    cfg,
		Client: fc,
		Cache:  &cache.Store{Dir: cfg.CacheDir},
		Now:    func() time.Time { return time.Unix(1_700_000_000, 0) },
		sleep:  func(context.Context, time.Duration) error { return nil },
	}
}

const uuid = "01234567-89ab-cdef-0123-456789abcdef"

func TestSubmitValidatesURL(t *testing.T) {
	e := testEngine(t, &fakeClient{submit: &urlscan.SubmitResponse{UUID: "x"}})
	if _, err := e.Submit(context.Background(), "not-a-url", ScanOptions{}); !errors.Is(err, validate.ErrInvalid) {
		t.Fatalf("want ErrInvalid for bad URL, got %v", err)
	}
	sub, err := e.Submit(context.Background(), "https://evil.test/login", ScanOptions{Visibility: "public"})
	if err != nil || sub.UUID != "x" {
		t.Fatalf("submit: %v %+v", err, sub)
	}
}

func TestResultCaches(t *testing.T) {
	fc := &fakeClient{result: &urlscan.Result{UUID: "u", Malicious: true}}
	e := testEngine(t, fc)
	if _, err := e.Result(context.Background(), uuid, false); err != nil {
		t.Fatal(err)
	}
	res, err := e.Result(context.Background(), uuid, false)
	if err != nil {
		t.Fatal(err)
	}
	if fc.resultCalls != 1 {
		t.Fatalf("expected 1 network call (2nd cached), got %d", fc.resultCalls)
	}
	if !res.Cached {
		t.Fatal("second result should be marked cached")
	}
}

func TestResultInvalidUUID(t *testing.T) {
	e := testEngine(t, &fakeClient{})
	if _, err := e.Result(context.Background(), "bad", false); !errors.Is(err, validate.ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}

func TestPollRetriesUntilReady(t *testing.T) {
	fc := &fakeClient{
		result:     &urlscan.Result{UUID: "u"},
		resultErrs: []error{urlscan.ErrNotReady, urlscan.ErrNotReady, nil},
	}
	e := testEngine(t, fc)
	res, err := e.Poll(context.Background(), uuid)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if res.UUID != "u" || fc.resultCalls != 3 {
		t.Fatalf("expected 3 polls, got %d (res %+v)", fc.resultCalls, res)
	}
}

func TestPollTimeout(t *testing.T) {
	fc := &fakeClient{resultErrs: []error{urlscan.ErrNotReady}}
	e := testEngine(t, fc)
	e.Cfg.PollTimeout = 0 // deadline == now ⇒ time out after the first not-ready
	if _, err := e.Poll(context.Background(), uuid); !errors.Is(err, ErrPollTimeout) {
		t.Fatalf("want ErrPollTimeout, got %v", err)
	}
}

func TestSearchCaches(t *testing.T) {
	fc := &fakeClient{search: &urlscan.SearchResult{Total: 1}}
	e := testEngine(t, fc)
	if _, err := e.Search(context.Background(), "domain:x.test", 0, "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Search(context.Background(), "domain:x.test", 0, "", false); err != nil {
		t.Fatal(err)
	}
	if fc.searchCalls != 1 {
		t.Fatalf("expected 1 network call (2nd cached), got %d", fc.searchCalls)
	}
}
