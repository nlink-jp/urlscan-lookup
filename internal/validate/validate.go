package validate

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrInvalid marks input that fails the safety gate. Callers must not send
// such input anywhere near the network.
var ErrInvalid = errors.New("invalid input")

// URL validates a scan target and returns its canonical string form. Only
// http and https schemes are accepted; a host is required; control
// characters and CRLF (header/log injection vectors) are rejected. The input
// is parsed with net/url so a bare "example.com" without a scheme is
// rejected rather than silently mis-scanned.
func URL(raw string) (string, error) {
	in := strings.TrimSpace(raw)
	if in == "" {
		return "", fmt.Errorf("%w: empty URL", ErrInvalid)
	}
	for _, r := range in {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: control character in URL", ErrInvalid)
		}
	}
	u, err := url.Parse(in)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("%w: URL must start with http:// or https://", ErrInvalid)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%w: URL has no host", ErrInvalid)
	}
	return u.String(), nil
}

// UUID validates the canonical RFC 4122 form (8-4-4-4-12 lowercase hex, as
// urlscan returns) before it is interpolated into a result/screenshot path.
func UUID(raw string) (string, error) {
	in := strings.TrimSpace(raw)
	const dashes = "________-____-____-____-____________" // 36 chars, dashes at 8,13,18,23
	if len(in) != 36 {
		return "", fmt.Errorf("%w: UUID must be 36 characters", ErrInvalid)
	}
	for i := 0; i < 36; i++ {
		c := in[i]
		if dashes[i] == '-' {
			if c != '-' {
				return "", fmt.Errorf("%w: malformed UUID", ErrInvalid)
			}
			continue
		}
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return "", fmt.Errorf("%w: UUID contains a non-hex character", ErrInvalid)
		}
	}
	return strings.ToLower(in), nil
}

// Visibility validates the scan visibility, defaulting empty input to
// "private" (the safe default: a scan is visible only to the submitter unless
// public is requested explicitly).
func Visibility(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "private":
		return "private", nil
	case "unlisted":
		return "unlisted", nil
	case "public":
		return "public", nil
	default:
		return "", fmt.Errorf("%w: visibility must be private, unlisted, or public", ErrInvalid)
	}
}
