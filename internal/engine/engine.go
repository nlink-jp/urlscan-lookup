package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nlink-jp/urlscan-lookup/internal/cache"
	"github.com/nlink-jp/urlscan-lookup/internal/config"
	"github.com/nlink-jp/urlscan-lookup/internal/urlscan"
	"github.com/nlink-jp/urlscan-lookup/internal/validate"
)

// ErrPollTimeout means a scan did not finish within the poll budget. The scan
// may still complete later; fetch it by UUID with the result command.
var ErrPollTimeout = errors.New("scan did not complete within the poll timeout")

// Client is the urlscan API surface the engine depends on. *urlscan.Client
// satisfies it; tests inject fakes.
type Client interface {
	Submit(ctx context.Context, req urlscan.SubmitRequest) (*urlscan.SubmitResponse, *urlscan.RateLimit, error)
	Result(ctx context.Context, uuid string) (*urlscan.Result, *urlscan.RateLimit, error)
	Search(ctx context.Context, query string, size int, searchAfter string) (*urlscan.SearchResult, *urlscan.RateLimit, error)
	Quota(ctx context.Context) (*urlscan.Quota, *urlscan.RateLimit, error)
	Screenshot(ctx context.Context, uuid string) ([]byte, error)
}

// ScanOptions modify a single scan submission.
type ScanOptions struct {
	Visibility string
	Country    string
	Tags       []string
	Referer    string
	UserAgent  string
}

// Engine is shared by the CLI and the MCP server.
type Engine struct {
	Cfg    *config.Config
	Client Client
	Cache  *cache.Store
	Now    func() time.Time
	// sleep paces polling; overridable in tests.
	sleep func(context.Context, time.Duration) error
}

// New wires a production engine from resolved configuration.
func New(cfg *config.Config, version string) *Engine {
	ua := "urlscan-lookup/" + version + " (+https://github.com/nlink-jp/urlscan-lookup)"
	return &Engine{
		Cfg:    cfg,
		Client: urlscan.NewClient(cfg.BaseURL, cfg.APIKey, ua, cfg.Timeout),
		Cache:  &cache.Store{Dir: cfg.CacheDir},
		Now:    time.Now,
	}
}

// Submit validates and submits a new scan, returning urlscan's immediate
// response (the UUID is the job handle). It never polls.
func (e *Engine) Submit(ctx context.Context, rawURL string, opts ScanOptions) (*urlscan.SubmitResponse, error) {
	cleanURL, err := validate.URL(rawURL)
	if err != nil {
		return nil, err
	}
	vis, err := validate.Visibility(opts.Visibility)
	if err != nil {
		return nil, err
	}
	req := urlscan.SubmitRequest{
		URL:        cleanURL,
		Visibility: vis,
		Tags:       opts.Tags,
		Country:    firstNonEmpty(opts.Country, e.Cfg.Country),
		Referer:    opts.Referer,
		UserAgent:  opts.UserAgent,
	}
	resp, _, err := e.Client.Submit(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Poll fetches a scan result, retrying while it is not ready, until it
// completes or the poll budget expires. It waits PollInitialDelay before the
// first fetch (urlscan's guidance: results are never instant).
func (e *Engine) Poll(ctx context.Context, uuid string) (*urlscan.Result, error) {
	clean, err := validate.UUID(uuid)
	if err != nil {
		return nil, err
	}
	deadline := e.Now().Add(e.Cfg.PollTimeout)
	if err := e.nap(ctx, e.Cfg.PollInitialDelay); err != nil {
		return nil, err
	}
	for {
		res, _, err := e.Client.Result(ctx, clean)
		switch {
		case err == nil:
			e.cachePut("result", clean, res)
			return res, nil
		case errors.Is(err, urlscan.ErrNotReady):
			if !e.Now().Before(deadline) {
				return nil, fmt.Errorf("%w (uuid %s)", ErrPollTimeout, clean)
			}
			if err := e.nap(ctx, e.Cfg.PollInterval); err != nil {
				return nil, err
			}
		default:
			return nil, err
		}
	}
}

// Result fetches a single scan result, consulting the cache unless refresh is
// set. urlscan.ErrNotReady / ErrGone pass through so callers can distinguish
// "still processing" from "deleted".
func (e *Engine) Result(ctx context.Context, uuid string, refresh bool) (*urlscan.Result, error) {
	clean, err := validate.UUID(uuid)
	if err != nil {
		return nil, err
	}
	key := cache.Key("result", clean)
	if !refresh {
		if raw, ok := e.Cache.Get(key, e.Now(), e.Cfg.CacheTTL); ok {
			var res urlscan.Result
			if json.Unmarshal(raw, &res) == nil {
				res.Cached = true
				return &res, nil
			}
		}
	}
	res, _, err := e.Client.Result(ctx, clean)
	if err != nil {
		return nil, err
	}
	e.cachePut("result", clean, res)
	return res, nil
}

// Search queries the historical scan database, consulting the cache unless
// refresh is set. The cache key includes size and pagination cursor.
func (e *Engine) Search(ctx context.Context, query string, size int, searchAfter string, refresh bool) (*urlscan.SearchResult, error) {
	if size <= 0 {
		size = e.Cfg.SearchSize
	}
	key := cache.Key("search", fmt.Sprintf("%s|%d|%s", query, size, searchAfter))
	if !refresh {
		if raw, ok := e.Cache.Get(key, e.Now(), e.Cfg.CacheTTL); ok {
			var res urlscan.SearchResult
			if json.Unmarshal(raw, &res) == nil {
				return &res, nil
			}
		}
	}
	res, _, err := e.Client.Search(ctx, query, size, searchAfter)
	if err != nil {
		return nil, err
	}
	if b, merr := json.Marshal(res); merr == nil {
		_ = e.Cache.Put(key, b, e.Now())
	}
	return res, nil
}

// Quota fetches the account's per-action quotas (never cached — the point is
// the live number).
func (e *Engine) Quota(ctx context.Context) (*urlscan.Quota, error) {
	q, _, err := e.Client.Quota(ctx)
	return q, err
}

// Screenshot fetches the PNG bytes for a scan.
func (e *Engine) Screenshot(ctx context.Context, uuid string) ([]byte, error) {
	clean, err := validate.UUID(uuid)
	if err != nil {
		return nil, err
	}
	return e.Client.Screenshot(ctx, clean)
}

// cachePut stores a marshalable result, best-effort (a cache-write failure
// must not fail a successful lookup).
func (e *Engine) cachePut(namespace, id string, v any) {
	if b, err := json.Marshal(v); err == nil {
		_ = e.Cache.Put(cache.Key(namespace, id), b, e.Now())
	}
}

// nap sleeps for d, honoring context cancellation.
func (e *Engine) nap(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	if e.sleep != nil {
		return e.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
