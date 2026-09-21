package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// clearEnv empties every variable Load reads, so a test sees the defaults and
// not the machine it runs on.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"URLSCAN_API_KEY", "URLSCAN_LOOKUP_API_KEY", "URLSCAN_LOOKUP_BASE_URL",
		"URLSCAN_LOOKUP_VISIBILITY", "URLSCAN_LOOKUP_COUNTRY", "URLSCAN_LOOKUP_CACHE_DIR",
		"URLSCAN_LOOKUP_WORKSPACE", "URLSCAN_LOOKUP_SCREENSHOT_MAX_BYTES",
		"URLSCAN_LOOKUP_CACHE_TTL_HOURS", "URLSCAN_LOOKUP_TIMEOUT_SECONDS",
		"XDG_CONFIG_HOME",
	} {
		t.Setenv(k, "")
	}
	// A config file in the default location would answer instead of the
	// defaults; point HOME at an empty directory.
	t.Setenv("HOME", t.TempDir())
}

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

// The organization retired file-mediated results on 2026-09-06: a server does
// not choose a file for data. The setting that named that file is gone, and a
// configuration still carrying it fails by name — ignoring it would delete a
// destination the operator believes is in force (the same rule pcap-analyzer's
// ADR-0009 §5 states for its removed output keys).
func TestRetiredWorkspaceEnvFailsByName(t *testing.T) {
	clearEnv(t)
	t.Setenv("URLSCAN_LOOKUP_WORKSPACE", t.TempDir())
	_, err := Load("", 0)
	if err == nil {
		t.Fatal("a retired setting must not be ignored")
	}
	for _, want := range []string{"URLSCAN_LOOKUP_WORKSPACE", "retired"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say %q: %v", want, err)
		}
	}
}

// The inline budget is the operator's, and it is stated from the inside: NaN
// fails every comparison, so "reject what is out of range" would let it in.
func TestScreenshotBudgetIsBounded(t *testing.T) {
	cases := map[string]struct {
		value string
		want  int // 0 = the load must fail
	}{
		"default when unset": {"", DefaultScreenshotMaxBytes},
		"a plain count":      {"1048576", 1 << 20},
		"the ceiling":        {"67108864", 64 << 20},
		"above the ceiling":  {"67108865", 0},
		"zero":               {"0", 0},
		"negative":           {"-1", 0},
		"NaN":                {"NaN", 0},
		"infinity":           {"Inf", 0},
		"not a number":       {"large", 0},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			clearEnv(t)
			if c.value != "" {
				t.Setenv("URLSCAN_LOOKUP_SCREENSHOT_MAX_BYTES", c.value)
			}
			cfg, err := Load("", 0)
			if c.want == 0 {
				if err == nil {
					t.Fatalf("%q was accepted as a byte budget", c.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.ScreenshotMaxBytes != c.want {
				t.Errorf("budget = %d, want %d", cfg.ScreenshotMaxBytes, c.want)
			}
		})
	}
}
