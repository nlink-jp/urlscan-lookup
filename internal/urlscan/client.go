package urlscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Sentinel errors let callers distinguish urlscan's normal async / quota
// states from real failures.
var (
	// ErrNotReady is returned by Result while a scan is still running
	// (HTTP 404). It is a normal transient state, not an error condition.
	ErrNotReady = errors.New("scan result not ready yet")
	// ErrGone means the result was deleted (HTTP 410).
	ErrGone = errors.New("scan result has been deleted")
	// ErrRateLimited wraps a 429 so a batch can stop early: the per-action
	// quota is exhausted until it resets.
	ErrRateLimited = errors.New("urlscan: rate limit exceeded")
	// ErrNoKey means no API key was configured.
	ErrNoKey = errors.New("urlscan: no API key configured")
)

// APIError is a non-2xx response with the urlscan-reported detail. The key is
// never included.
type APIError struct {
	StatusCode int
	Detail     string
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("urlscan: HTTP %d: %s", e.StatusCode, e.Detail)
	}
	return fmt.Sprintf("urlscan: HTTP %d", e.StatusCode)
}

// RateLimit captures the per-response X-Rate-Limit-* headers. Fields are -1
// when the corresponding header is absent or unparseable.
type RateLimit struct {
	Scope     string // X-Rate-Limit-Scope (user | ip-address)
	Action    string // X-Rate-Limit-Action
	Limit     int    // X-Rate-Limit-Limit
	Remaining int    // X-Rate-Limit-Remaining
	Reset     string // X-Rate-Limit-Reset (ISO-8601), or Retry-After seconds on 429
}

// Doer executes HTTP requests. *http.Client satisfies it; tests inject fakes.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client queries urlscan.io. It is safe for sequential use and honors ctx
// cancellation.
type Client struct {
	HTTP       Doer
	BaseURL    string // e.g. https://urlscan.io
	Key        string
	UserAgent  string
	MaxRetries int           // retry attempts for 429/5xx (default 3)
	BaseDelay  time.Duration // initial backoff (default 1s)
	// sleep is the backoff sleeper; overridable in tests to avoid real waits.
	sleep func(context.Context, time.Duration) error
	// rng seeds jitter; overridable in tests for determinism.
	rng *rand.Rand
}

// NewClient returns a Client with sane defaults.
func NewClient(baseURL, key, userAgent string, timeout time.Duration) *Client {
	return &Client{
		HTTP:       &http.Client{Timeout: timeout},
		BaseURL:    baseURL,
		Key:        key,
		UserAgent:  userAgent,
		MaxRetries: 3,
		BaseDelay:  time.Second,
	}
}

// Submit posts a new scan. The scan runs asynchronously; poll Result with the
// returned UUID.
func (c *Client) Submit(ctx context.Context, req SubmitRequest) (*SubmitResponse, *RateLimit, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}
	respBody, rl, err := c.do(ctx, http.MethodPost, "/api/v1/scan/", nil, body)
	if err != nil {
		return nil, rl, err
	}
	var out SubmitResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, rl, fmt.Errorf("urlscan: decode submit response: %w", err)
	}
	return &out, rl, nil
}

// Result fetches a scan result. A 404 becomes ErrNotReady (still running); a
// 410 becomes ErrGone (deleted).
func (c *Client) Result(ctx context.Context, uuid string) (*Result, *RateLimit, error) {
	body, rl, err := c.do(ctx, http.MethodGet, "/api/v1/result/"+url.PathEscape(uuid)+"/", nil, nil)
	if err != nil {
		return nil, rl, err
	}
	res, err := normalizeResult(body)
	if err != nil {
		return nil, rl, err
	}
	res.Raw = append(json.RawMessage(nil), body...)
	return res, rl, nil
}

// Search queries the historical scan database. searchAfter paginates (pass the
// sort value of the last row of the previous page; empty for the first page).
func (c *Client) Search(ctx context.Context, query string, size int, searchAfter string) (*SearchResult, *RateLimit, error) {
	q := url.Values{}
	q.Set("q", query)
	if size > 0 {
		q.Set("size", strconv.Itoa(size))
	}
	if searchAfter != "" {
		q.Set("search_after", searchAfter)
	}
	body, rl, err := c.do(ctx, http.MethodGet, "/api/v1/search/", q, nil)
	if err != nil {
		return nil, rl, err
	}
	res, err := normalizeSearch(body)
	if err != nil {
		return nil, rl, err
	}
	res.Raw = append(json.RawMessage(nil), body...)
	return res, rl, nil
}

// Quota fetches the account's per-action rate-limit quotas.
func (c *Client) Quota(ctx context.Context) (*Quota, *RateLimit, error) {
	body, rl, err := c.do(ctx, http.MethodGet, "/user/quotas/", nil, nil)
	if err != nil {
		return nil, rl, err
	}
	q, err := normalizeQuota(body)
	if err != nil {
		return nil, rl, err
	}
	q.Raw = append(json.RawMessage(nil), body...)
	return q, rl, nil
}

// Screenshot fetches the PNG bytes for a scan. A 404 becomes ErrNotReady (not
// generated yet).
func (c *Client) Screenshot(ctx context.Context, uuid string) ([]byte, error) {
	body, _, err := c.do(ctx, http.MethodGet, "/screenshots/"+url.PathEscape(uuid)+".png", nil, nil)
	return body, err
}

// do performs an authenticated request against BaseURL+path with retry on
// 429/5xx. The API key is sent via the API-Key header and never appears in the
// URL. A 404 on GET result/screenshot becomes ErrNotReady; 410 becomes ErrGone;
// 429 becomes ErrRateLimited after retries are exhausted.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, jsonBody []byte) ([]byte, *RateLimit, error) {
	if c.Key == "" {
		return nil, nil, ErrNoKey
	}
	endpoint := c.BaseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	var lastRL *RateLimit
	attempts := c.MaxRetries
	if attempts < 0 {
		attempts = 0
	}
	for attempt := 0; ; attempt++ {
		var reqBody io.Reader
		if jsonBody != nil {
			reqBody = bytes.NewReader(jsonBody)
		}
		req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("API-Key", c.Key)
		req.Header.Set("Accept", "application/json")
		if c.UserAgent != "" {
			req.Header.Set("User-Agent", c.UserAgent)
		}
		if jsonBody != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.client().Do(req)
		if err != nil {
			return nil, lastRL, fmt.Errorf("urlscan: request failed: %w", err)
		}
		rl := parseRateLimit(resp.Header)
		lastRL = rl
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()

		switch {
		case resp.StatusCode == http.StatusOK:
			return body, rl, nil
		case resp.StatusCode == http.StatusNotFound:
			return nil, rl, ErrNotReady
		case resp.StatusCode == http.StatusGone:
			return nil, rl, ErrGone
		case resp.StatusCode == http.StatusTooManyRequests:
			if attempt < attempts {
				if werr := c.backoff(ctx, attempt, rl); werr != nil {
					return nil, rl, werr
				}
				continue
			}
			return nil, rl, fmt.Errorf("%w: %s", ErrRateLimited, firstErrorDetail(body))
		case resp.StatusCode >= 500:
			if attempt < attempts {
				if werr := c.backoff(ctx, attempt, rl); werr != nil {
					return nil, rl, werr
				}
				continue
			}
			return nil, rl, &APIError{StatusCode: resp.StatusCode, Detail: firstErrorDetail(body)}
		default:
			return nil, rl, &APIError{StatusCode: resp.StatusCode, Detail: firstErrorDetail(body)}
		}
	}
}

func (c *Client) client() Doer {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// backoff waits before a retry: honors Retry-After (seconds) when present,
// else exponential base*2^attempt with full jitter.
func (c *Client) backoff(ctx context.Context, attempt int, rl *RateLimit) error {
	base := c.BaseDelay
	if base <= 0 {
		base = time.Second
	}
	delay := base << attempt
	if rl != nil && rl.Reset != "" {
		if secs, err := strconv.Atoi(rl.Reset); err == nil && secs > 0 {
			delay = time.Duration(secs) * time.Second
		}
	}
	// Full jitter: sleep a random duration in [0, delay].
	jittered := time.Duration(c.jitter(int64(delay)))
	return c.sleeper()(ctx, jittered)
}

func (c *Client) jitter(max int64) int64 {
	if max <= 0 {
		return 0
	}
	if c.rng != nil {
		return c.rng.Int63n(max + 1)
	}
	return rand.Int63n(max + 1)
}

func (c *Client) sleeper() func(context.Context, time.Duration) error {
	if c.sleep != nil {
		return c.sleep
	}
	return func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
}

// parseRateLimit extracts the X-Rate-Limit-* headers; missing numeric values
// become -1.
func parseRateLimit(h http.Header) *RateLimit {
	rl := &RateLimit{Limit: -1, Remaining: -1}
	rl.Scope = h.Get("X-Rate-Limit-Scope")
	rl.Action = h.Get("X-Rate-Limit-Action")
	if v := h.Get("X-Rate-Limit-Limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			rl.Limit = n
		}
	}
	if v := h.Get("X-Rate-Limit-Remaining"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			rl.Remaining = n
		}
	}
	if v := h.Get("X-Rate-Limit-Reset"); v != "" {
		rl.Reset = v
	} else if v := h.Get("Retry-After"); v != "" {
		rl.Reset = v
	}
	return rl
}

// firstErrorDetail pulls a human message from a urlscan error body
// ({"message": ...} or {"description": ...}), falling back to a trimmed raw
// body.
func firstErrorDetail(body []byte) string {
	var e struct {
		Message     string `json:"message"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(body, &e); err == nil {
		if e.Message != "" {
			return e.Message
		}
		if e.Description != "" {
			return e.Description
		}
	}
	s := string(bytes.TrimSpace(body))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
