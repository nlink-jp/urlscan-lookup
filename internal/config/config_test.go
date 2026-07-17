package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("URLSCAN_API_KEY", "")
	t.Setenv("URLSCAN_LOOKUP_API_KEY", "")
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.toml"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BaseURL != DefaultBaseURL || cfg.Visibility != "private" || !cfg.Wait {
		t.Fatalf("defaults: %+v", cfg)
	}
	if cfg.PollInitialDelay != DefaultPollInitialDelay || cfg.SearchSize != DefaultSearchSize {
		t.Fatalf("poll/search defaults: %+v", cfg)
	}
}

func TestLoadConfigFile(t *testing.T) {
	t.Setenv("URLSCAN_API_KEY", "")
	t.Setenv("URLSCAN_LOOKUP_API_KEY", "")
	p := writeConfig(t, `
[auth]
api_key = "from-file"

[scan]
default_visibility = "unlisted"
poll_timeout_seconds = 45
country = "jp"

[search]
size = 25

[cache]
ttl_hours = 6

[network]
timeout_seconds = 12
`)
	cfg, err := Load(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey != "from-file" {
		t.Fatalf("api_key = %q", cfg.APIKey)
	}
	if cfg.Visibility != "unlisted" || cfg.Country != "jp" {
		t.Fatalf("scan: %+v", cfg)
	}
	if cfg.PollTimeout != 45*time.Second {
		t.Fatalf("poll timeout = %v", cfg.PollTimeout)
	}
	if cfg.SearchSize != 25 || cfg.CacheTTL != 6*time.Hour || cfg.Timeout != 12*time.Second {
		t.Fatalf("misc: %+v", cfg)
	}
}

func TestEnvOverridesFileAndFlagWins(t *testing.T) {
	p := writeConfig(t, "[auth]\napi_key = \"from-file\"\n[network]\ntimeout_seconds = 12\n")
	t.Setenv("URLSCAN_API_KEY", "from-env")
	t.Setenv("URLSCAN_LOOKUP_VISIBILITY", "public")
	cfg, err := Load(p, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey != "from-env" {
		t.Fatalf("env should override file: %q", cfg.APIKey)
	}
	if cfg.Visibility != "public" {
		t.Fatalf("env visibility: %q", cfg.Visibility)
	}
	if cfg.Timeout != 5*time.Second {
		t.Fatalf("flag timeout override should win: %v", cfg.Timeout)
	}
}

func TestBaseURLTrimsTrailingSlash(t *testing.T) {
	t.Setenv("URLSCAN_LOOKUP_BASE_URL", "https://example.test/")
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.toml"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BaseURL != "https://example.test" {
		t.Fatalf("base url = %q", cfg.BaseURL)
	}
}
