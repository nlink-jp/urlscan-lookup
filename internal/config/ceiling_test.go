package config

import (
	"testing"

	"github.com/nlink-jp/urlscan-lookup/internal/urlscan"
)

// Every inline budget the setting allows must be reachable: the client reads
// at most urlscan.MaxResponseBytes, so a budget above it could never be met.
func TestTheScreenshotBudgetCeilingIsWithinTheReadLimit(t *testing.T) {
	if maxScreenshotMaxBytes > urlscan.MaxResponseBytes {
		t.Fatalf("screenshot_max_bytes may be %d, but the client reads at most %d", maxScreenshotMaxBytes, urlscan.MaxResponseBytes)
	}
}
