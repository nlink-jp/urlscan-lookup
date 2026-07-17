package cache

import (
	"encoding/json"
	"testing"
	"time"
)

func TestStoreRoundTrip(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	now := time.Unix(1_700_000_000, 0)
	key := Key("result", "01234567-89ab-cdef-0123-456789abcdef")

	if _, ok := s.Get(key, now, time.Hour); ok {
		t.Fatal("expected miss on empty store")
	}
	want := json.RawMessage(`{"uuid":"x","malicious":true}`)
	if err := s.Put(key, want, now); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := s.Get(key, now.Add(30*time.Minute), time.Hour)
	if !ok {
		t.Fatal("expected hit within TTL")
	}
	if string(got) != string(want) {
		t.Fatalf("Get = %s, want %s", got, want)
	}
	if _, ok := s.Get(key, now.Add(2*time.Hour), time.Hour); ok {
		t.Fatal("expected miss past TTL")
	}
}

func TestStoreClearAndCount(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	now := time.Unix(1_700_000_000, 0)
	for _, id := range []string{"a", "b", "c"} {
		if err := s.Put(Key("search", id), json.RawMessage(`{}`), now); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	if n := s.Count(); n != 3 {
		t.Fatalf("Count = %d, want 3", n)
	}
	n, err := s.Clear()
	if err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if n != 3 {
		t.Fatalf("Clear removed %d, want 3", n)
	}
	if n := s.Count(); n != 0 {
		t.Fatalf("Count after clear = %d, want 0", n)
	}
}

func TestKeyDistinctNamespaces(t *testing.T) {
	if Key("result", "x") == Key("search", "x") {
		t.Fatal("namespaces must not alias")
	}
}
