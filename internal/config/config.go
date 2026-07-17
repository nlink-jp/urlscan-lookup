package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the urlscan.io API host. All endpoints (scan, result,
	// search, quotas, screenshots) live under it.
	DefaultBaseURL = "https://urlscan.io"

	// DefaultVisibility is the safe scan default: a scan is visible only to
	// the submitter unless "public" is requested explicitly.
	DefaultVisibility = "private"

	// DefaultCacheTTL is how long a result/search response stays fresh. urlscan
	// results are immutable once complete, so this can be high.
	DefaultCacheTTL = 24 * time.Hour
	// DefaultTimeout bounds each HTTP exchange.
	DefaultTimeout = 30 * time.Second

	// Poll defaults follow urlscan's guidance: wait 10s after submit, then
	// poll every 2s.
	DefaultPollInitialDelay = 10 * time.Second
	DefaultPollInterval     = 2 * time.Second
	DefaultPollTimeout      = 120 * time.Second

	// DefaultSearchSize is the default number of search hits.
	DefaultSearchSize = 100
)

// Config holds resolved runtime settings.
type Config struct {
	BaseURL          string        // urlscan API host
	APIKey           string        // urlscan API key (secret; never logged)
	Visibility       string        // default scan visibility
	Country          string        // default scanning PoP country
	Wait             bool          // CLI: poll a scan to completion after submit
	PollInitialDelay time.Duration // delay before the first result poll
	PollInterval     time.Duration // interval between result polls
	PollTimeout      time.Duration // overall poll budget
	SearchSize       int           // default search result count
	CacheDir         string        // result/search cache directory
	CacheTTL         time.Duration // result/search freshness
	Timeout          time.Duration // network timeout per HTTP exchange
	WorkspaceDir     string        // default MCP file-mediated output root
}

// Load resolves configuration. If configPath is empty the default location
// (~/.config/urlscan-lookup/config.toml) is used when present. Environment
// variables override file values; a non-zero timeoutOverride wins over both.
func Load(configPath string, timeoutOverride time.Duration) (*Config, error) {
	cfg := &Config{
		BaseURL:          DefaultBaseURL,
		Visibility:       DefaultVisibility,
		Wait:             true,
		PollInitialDelay: DefaultPollInitialDelay,
		PollInterval:     DefaultPollInterval,
		PollTimeout:      DefaultPollTimeout,
		SearchSize:       DefaultSearchSize,
		CacheDir:         DefaultCacheDir(),
		CacheTTL:         DefaultCacheTTL,
		Timeout:          DefaultTimeout,
	}

	if configPath == "" {
		configPath = DefaultConfigPath()
	}
	if configPath != "" {
		if f, err := os.Open(configPath); err == nil {
			defer f.Close()
			sections, perr := parseTOML(f)
			if perr != nil {
				return nil, fmt.Errorf("parse config %s: %w", configPath, perr)
			}
			if aerr := applySections(cfg, sections); aerr != nil {
				return nil, fmt.Errorf("config %s: %w", configPath, aerr)
			}
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("open config %s: %w", configPath, err)
		}
	}

	// Environment overrides. The key is canonically URLSCAN_API_KEY.
	if v := firstEnv("URLSCAN_API_KEY", "URLSCAN_LOOKUP_API_KEY"); v != "" {
		cfg.APIKey = v
	}
	if v := os.Getenv("URLSCAN_LOOKUP_BASE_URL"); v != "" {
		cfg.BaseURL = v
	}
	if v := os.Getenv("URLSCAN_LOOKUP_VISIBILITY"); v != "" {
		cfg.Visibility = strings.ToLower(v)
	}
	if v := os.Getenv("URLSCAN_LOOKUP_COUNTRY"); v != "" {
		cfg.Country = v
	}
	if v := os.Getenv("URLSCAN_LOOKUP_CACHE_DIR"); v != "" {
		cfg.CacheDir = expandHome(v)
	}
	if v := os.Getenv("URLSCAN_LOOKUP_WORKSPACE"); v != "" {
		cfg.WorkspaceDir = expandHome(v)
	}
	if v := os.Getenv("URLSCAN_LOOKUP_CACHE_TTL_HOURS"); v != "" {
		d, err := parseHours(v)
		if err != nil {
			return nil, fmt.Errorf("URLSCAN_LOOKUP_CACHE_TTL_HOURS: %w", err)
		}
		cfg.CacheTTL = d
	}
	if v := os.Getenv("URLSCAN_LOOKUP_TIMEOUT_SECONDS"); v != "" {
		s, err := parseSeconds(v)
		if err != nil {
			return nil, fmt.Errorf("URLSCAN_LOOKUP_TIMEOUT_SECONDS: %w", err)
		}
		cfg.Timeout = s
	}

	// Explicit flag override wins.
	if timeoutOverride > 0 {
		cfg.Timeout = timeoutOverride
	}

	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return cfg, nil
}

func applySections(cfg *Config, sections map[string]map[string]string) error {
	if a := sections["auth"]; a != nil {
		if v := a["api_key"]; v != "" {
			cfg.APIKey = v
		}
	}
	if s := sections["scan"]; s != nil {
		if v := s["default_visibility"]; v != "" {
			cfg.Visibility = strings.ToLower(v)
		}
		if v := s["country"]; v != "" {
			cfg.Country = v
		}
		if v, ok := s["wait"]; ok {
			cfg.Wait = v == "true"
		}
		if v := s["poll_initial_delay_seconds"]; v != "" {
			d, err := parseSeconds(v)
			if err != nil {
				return fmt.Errorf("[scan] poll_initial_delay_seconds: %w", err)
			}
			cfg.PollInitialDelay = d
		}
		if v := s["poll_interval_seconds"]; v != "" {
			d, err := parseSeconds(v)
			if err != nil {
				return fmt.Errorf("[scan] poll_interval_seconds: %w", err)
			}
			cfg.PollInterval = d
		}
		if v := s["poll_timeout_seconds"]; v != "" {
			d, err := parseSeconds(v)
			if err != nil {
				return fmt.Errorf("[scan] poll_timeout_seconds: %w", err)
			}
			cfg.PollTimeout = d
		}
	}
	if s := sections["search"]; s != nil {
		if v := s["size"]; v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return fmt.Errorf("[search] size: %q is not a positive integer", v)
			}
			cfg.SearchSize = n
		}
	}
	if c := sections["cache"]; c != nil {
		if v := c["ttl_hours"]; v != "" {
			d, err := parseHours(v)
			if err != nil {
				return fmt.Errorf("[cache] ttl_hours: %w", err)
			}
			cfg.CacheTTL = d
		}
		if v := c["dir"]; v != "" {
			cfg.CacheDir = expandHome(v)
		}
	}
	if n := sections["network"]; n != nil {
		if v := n["timeout_seconds"]; v != "" {
			d, err := parseSeconds(v)
			if err != nil {
				return fmt.Errorf("[network] timeout_seconds: %w", err)
			}
			cfg.Timeout = d
		}
	}
	if n := sections["base"]; n != nil {
		if v := n["url"]; v != "" {
			cfg.BaseURL = v
		}
	}
	return nil
}

func parseHours(v string) (time.Duration, error) {
	h, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", v)
	}
	if h < 0 {
		return 0, fmt.Errorf("must not be negative")
	}
	return time.Duration(h * float64(time.Hour)), nil
}

func parseSeconds(v string) (time.Duration, error) {
	s, err := strconv.ParseFloat(v, 64)
	if err != nil || s <= 0 {
		return 0, fmt.Errorf("%q is not a positive number", v)
	}
	return time.Duration(s * float64(time.Second)), nil
}

func firstEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

// DefaultConfigPath returns the default config file location, honoring
// XDG_CONFIG_HOME.
func DefaultConfigPath() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "urlscan-lookup", "config.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "urlscan-lookup", "config.toml")
}

// DefaultCacheDir returns the default cache directory, honoring
// XDG_CACHE_HOME.
func DefaultCacheDir() string {
	if x := os.Getenv("XDG_CACHE_HOME"); x != "" {
		return filepath.Join(x, "urlscan-lookup")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "urlscan-lookup-cache"
	}
	return filepath.Join(home, ".cache", "urlscan-lookup")
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// parseTOML parses the minimal subset urlscan-lookup needs: [section] headers
// and key = value lines, where value is an optionally quoted string. Comments
// start with '#'. Arrays, nested tables, and typed values are intentionally
// unsupported.
func parseTOML(r io.Reader) (map[string]map[string]string, error) {
	sections := map[string]map[string]string{}
	current := ""
	sections[current] = map[string]string{}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if strings.HasPrefix(raw, "[") {
			end := strings.IndexByte(raw, ']')
			if end < 0 {
				return nil, fmt.Errorf("line %d: unterminated section header", line)
			}
			current = strings.TrimSpace(raw[1:end])
			if _, ok := sections[current]; !ok {
				sections[current] = map[string]string{}
			}
			continue
		}
		eq := strings.IndexByte(raw, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: expected key = value", line)
		}
		key := strings.TrimSpace(raw[:eq])
		val := parseValue(strings.TrimSpace(raw[eq+1:]))
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", line)
		}
		sections[current][key] = val
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return sections, nil
}

// parseValue strips surrounding quotes, or trims a trailing inline comment
// from a bare value.
func parseValue(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
		q := v[0]
		if end := strings.IndexByte(v[1:], q); end >= 0 {
			return v[1 : 1+end]
		}
	}
	if hash := strings.IndexByte(v, '#'); hash >= 0 {
		v = strings.TrimSpace(v[:hash])
	}
	return v
}
