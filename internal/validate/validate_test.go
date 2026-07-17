package validate

import (
	"errors"
	"testing"
)

func TestURL(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"https ok", "https://example.com/path?q=1", "https://example.com/path?q=1", false},
		{"http ok", "http://例え.jp/", "http://%E4%BE%8B%E3%81%88.jp/", false},
		{"trims space", "  https://a.test/  ", "https://a.test/", false},
		{"empty", "", "", true},
		{"no scheme", "example.com", "", true},
		{"ftp scheme", "ftp://example.com", "", true},
		{"file scheme", "file:///etc/passwd", "", true},
		{"no host", "https://", "", true},
		{"crlf injection", "https://example.com/\r\nHost: evil", "", true},
		{"control char", "https://exa\x01mple.com", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := URL(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("URL(%q) = %q, want error", tt.in, got)
				}
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("URL(%q) error = %v, want ErrInvalid", tt.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("URL(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("URL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestUUID(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"lowercase", "01234567-89ab-cdef-0123-456789abcdef", "01234567-89ab-cdef-0123-456789abcdef", false},
		{"uppercase normalized", "ABCDEF01-2345-6789-ABCD-EF0123456789", "abcdef01-2345-6789-abcd-ef0123456789", false},
		{"trims", "  01234567-89ab-cdef-0123-456789abcdef  ", "01234567-89ab-cdef-0123-456789abcdef", false},
		{"too short", "01234567-89ab-cdef-0123-456789abcde", "", true},
		{"non hex", "0123456g-89ab-cdef-0123-456789abcdef", "", true},
		{"missing dash", "0123456789ab-cdef-0123-456789abcdef00", "", true},
		{"empty", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UUID(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("UUID(%q) = %q, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("UUID(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("UUID(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestVisibility(t *testing.T) {
	for _, tt := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "private", false},
		{"private", "private", false},
		{"PUBLIC", "public", false},
		{"unlisted", "unlisted", false},
		{"secret", "", true},
	} {
		got, err := Visibility(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("Visibility(%q) = %q, want error", tt.in, got)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Fatalf("Visibility(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}
