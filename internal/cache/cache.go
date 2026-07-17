package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// record is the on-disk envelope. Freshness lives in the record, not the file
// mtime, so it survives copies and backups.
type record struct {
	FetchedAtUnix int64           `json:"fetched_at_unix"`
	Result        json.RawMessage `json:"result"`
}

// Store is a namespaced result cache rooted at a directory. The clock is
// supplied by callers (the engine is the only clock reader), keeping the
// store deterministic and testable.
type Store struct {
	Dir string
}

// Key builds a cache filename for a namespace (e.g. "result", "search") and a
// free-form identifier. The identifier is hashed so arbitrary search queries
// and UUIDs map to a filesystem-safe, fixed-length name.
func Key(namespace, id string) string {
	sum := sha256.Sum256([]byte(id))
	return namespace + "_" + hex.EncodeToString(sum[:16]) + ".json"
}

// Get returns the cached raw result for key when it is younger than ttl.
func (s *Store) Get(key string, now time.Time, ttl time.Duration) (json.RawMessage, bool) {
	b, err := os.ReadFile(filepath.Join(s.Dir, key))
	if err != nil {
		return nil, false
	}
	var rec record
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, false // corrupt entries read as misses; Put overwrites them
	}
	if now.Sub(time.Unix(rec.FetchedAtUnix, 0)) > ttl {
		return nil, false
	}
	return rec.Result, true
}

// Put stores a raw result under key, stamped with now. The write is atomic
// (temp file + rename) so a crash never leaves a truncated entry.
func (s *Store) Put(key string, result json.RawMessage, now time.Time) error {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	b, err := json.Marshal(record{FetchedAtUnix: now.Unix(), Result: result})
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Dir, key), b)
}

// Count returns the number of cached entries.
func (s *Store) Count() int {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	return n
}

// Clear removes every cached entry (top-level *.json files). It returns the
// number of entries removed.
func (s *Store) Clear() (int, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if err := os.Remove(filepath.Join(s.Dir, e.Name())); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// writeAtomic writes b to path via a temp file + rename in the same directory.
func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
