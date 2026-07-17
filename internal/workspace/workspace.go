package workspace

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Workspace is a materialized output directory.
type Workspace struct {
	BaseDir string
}

// Ensure creates the base directory if needed and returns the Workspace. An
// empty dir is an error — the caller must resolve a default first.
func Ensure(dir string) (*Workspace, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("workspace: no output directory (pass workspace_root)")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("workspace: create %s: %w", dir, err)
	}
	return &Workspace{BaseDir: dir}, nil
}

// Path joins parts under the base directory (for display / returning to the
// caller).
func (w *Workspace) Path(parts ...string) string {
	return filepath.Join(append([]string{w.BaseDir}, parts...)...)
}

// WriteFileAtomic writes a workspace-relative file (temp + rename) with symlink
// containment via os.Root, and returns the absolute path written.
func (w *Workspace) WriteFileAtomic(rel string, data []byte) (string, error) {
	clean, err := resolveInside(rel)
	if err != nil {
		return "", err
	}
	root, err := os.OpenRoot(w.BaseDir)
	if err != nil {
		return "", fmt.Errorf("workspace: open root: %w", err)
	}
	defer root.Close()

	tmp := clean + ".tmp"
	f, err := root.Create(tmp)
	if err != nil {
		return "", fmt.Errorf("workspace: create: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = root.Remove(tmp)
		return "", fmt.Errorf("workspace: write: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(tmp)
		return "", fmt.Errorf("workspace: close: %w", err)
	}
	if err := root.Rename(tmp, clean); err != nil {
		_ = root.Remove(tmp)
		return "", fmt.Errorf("workspace: rename: %w", err)
	}
	return w.Path(clean), nil
}

// resolveInside rejects a relative path that escapes the workspace (absolute,
// or containing a ".." component). os.Root enforces this at the kernel level
// too; this lexical check yields a friendlier error first.
func resolveInside(rel string) (string, error) {
	if rel == "" {
		return "", errors.New("workspace: empty filename")
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("workspace: absolute path not allowed: %s", rel)
	}
	clean := filepath.Clean(rel)
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		if part == ".." {
			return "", fmt.Errorf("workspace: path escapes workspace: %s", rel)
		}
	}
	return clean, nil
}
