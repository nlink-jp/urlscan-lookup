package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/nlink-jp/mcp/client"
	"github.com/nlink-jp/urlscan-lookup/internal/urlscan"
)

// waitingClient's Submit waits for its ctx and reports how it ended.
type waitingClient struct {
	fakeClient
	cancelled chan error
}

func (w *waitingClient) Submit(ctx context.Context, _ urlscan.SubmitRequest) (*urlscan.SubmitResponse, *urlscan.RateLimit, error) {
	select {
	case <-ctx.Done():
		w.cancelled <- ctx.Err()
		return nil, nil, ctx.Err()
	case <-time.After(5 * time.Second):
		w.cancelled <- nil
		return &urlscan.SubmitResponse{UUID: "u1"}, nil, nil
	}
}

// notifications/cancelled reaches the urlscan request: toolsCall passes the
// handler's ctx on. A fixed context.Background() let the request run to its
// end after the caller had gone.
func TestACancelledCallCancelsTheEngine(t *testing.T) {
	e, cfg := testServer(t, nil)
	wc := &waitingClient{cancelled: make(chan error, 1)}
	e.Client = wc
	cl := openWith(t, func(ctx context.Context, in io.Reader, w io.Writer) error {
		return Serve(ctx, e, cfg, "test", in, w)
	}, client.Options{CancelNotice: true})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := cl.CallTool(ctx, "scan_url", json.RawMessage(`{"url":"https://example.com"}`), nil); err == nil {
		t.Fatal("the cancelled call returned a result")
	}
	select {
	case err := <-wc.cancelled:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("the urlscan request's ctx ended with %v, want context.Canceled", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("the urlscan request never returned")
	}
}
