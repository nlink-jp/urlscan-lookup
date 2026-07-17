package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicRoundTrip(t *testing.T) {
	ws, err := Ensure(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path, err := ws.WriteFileAtomic("shot.png", []byte("PNGDATA"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(b) != "PNGDATA" {
		t.Fatalf("content = %q", b)
	}
	if filepath.Dir(path) != ws.BaseDir {
		t.Fatalf("path %q not under base %q", path, ws.BaseDir)
	}
}

func TestWriteRejectsEscape(t *testing.T) {
	ws, err := Ensure(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"../evil.png", "a/../../evil.png", "/etc/passwd", ""} {
		if _, err := ws.WriteFileAtomic(rel, []byte("x")); err == nil {
			t.Fatalf("WriteFileAtomic(%q) should have been rejected", rel)
		}
	}
}

func TestEnsureEmptyDir(t *testing.T) {
	if _, err := Ensure(""); err == nil {
		t.Fatal("Ensure(\"\") should error")
	}
}
