package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nlink-jp/urlscan-lookup/internal/config"
	"github.com/nlink-jp/urlscan-lookup/internal/engine"
	"github.com/nlink-jp/urlscan-lookup/internal/urlscan"
)

// runScan implements the scan command: submit, then (unless --no-wait) poll to
// completion.
func runScan(args []string, version string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		visibility = fs.String("visibility", "", "scan visibility: private (default), unlisted, or public")
		noWait     = fs.Bool("no-wait", false, "submit only; print the UUID and do not poll")
		country    = fs.String("country", "", "scanning PoP country (e.g. jp)")
		tags       = fs.String("tags", "", "comma-separated tags")
		referer    = fs.String("referer", "", "Referer header to send")
		userAgent  = fs.String("user-agent", "", "User-Agent to send")
		failMal    = fs.Bool("fail-on-malicious", false, "exit 1 if the scan is flagged malicious")
		jsonOut    = fs.Bool("json", false, "JSON output")
		cfgPath    = fs.String("config", "", "config file path")
	)
	fs.BoolVar(jsonOut, "j", false, "JSON output (shorthand)")
	fs.StringVar(cfgPath, "c", "", "config file path (shorthand)")

	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError
	}
	if len(positionals) != 1 {
		fmt.Fprintln(stderr, "scan: exactly one URL is required")
		return exitError
	}
	cfg, err := config.Load(*cfgPath, 0)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	e := engine.New(cfg, version)
	ctx := context.Background()

	vis := *visibility
	if vis == "" {
		vis = cfg.Visibility
	}
	sub, err := e.Submit(ctx, positionals[0], engine.ScanOptions{
		Visibility: vis,
		Country:    *country,
		Tags:       splitCSV(*tags),
		Referer:    *referer,
		UserAgent:  *userAgent,
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}

	if *noWait {
		if *jsonOut {
			writeJSON(stdout, sub)
		} else {
			fmt.Fprintf(stdout, "uuid:       %s\n", sub.UUID)
			fmt.Fprintf(stdout, "visibility: %s\n", sub.Visibility)
			fmt.Fprintf(stdout, "result:     %s\n", sub.Result)
			fmt.Fprintln(stdout, "(submitted; fetch later with: urlscan-lookup result "+sub.UUID+")")
		}
		return exitOK
	}

	res, err := e.Poll(ctx, sub.UUID)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	if *jsonOut {
		writeJSON(stdout, res)
	} else {
		printResult(stdout, res)
	}
	if *failMal && res.Malicious {
		return exitMalicious
	}
	return exitOK
}

// runSearch implements the search command (passive; OpSec-safe).
func runSearch(args []string, version string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		size        = fs.Int("size", 0, "number of results (default 100)")
		searchAfter = fs.String("search-after", "", "pagination cursor")
		refresh     = fs.Bool("refresh", false, "bypass the cache and re-fetch")
		jsonOut     = fs.Bool("json", false, "JSONL output")
		cfgPath     = fs.String("config", "", "config file path")
	)
	fs.BoolVar(jsonOut, "j", false, "JSONL output (shorthand)")
	fs.StringVar(cfgPath, "c", "", "config file path (shorthand)")

	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError
	}
	if len(positionals) != 1 {
		fmt.Fprintln(stderr, "search: exactly one query is required (e.g. 'domain:example.com')")
		return exitError
	}
	cfg, err := config.Load(*cfgPath, 0)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	e := engine.New(cfg, version)
	res, err := e.Search(context.Background(), positionals[0], *size, *searchAfter, *refresh)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		for _, h := range res.Results {
			_ = enc.Encode(h)
		}
		return exitOK
	}
	printSearch(stdout, res)
	return exitOK
}

// runResult implements the result command.
func runResult(args []string, version string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("result", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		refresh = fs.Bool("refresh", false, "bypass the cache and re-fetch")
		jsonOut = fs.Bool("json", false, "JSON output")
		cfgPath = fs.String("config", "", "config file path")
	)
	fs.BoolVar(jsonOut, "j", false, "JSON output (shorthand)")
	fs.StringVar(cfgPath, "c", "", "config file path (shorthand)")

	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError
	}
	if len(positionals) != 1 {
		fmt.Fprintln(stderr, "result: exactly one scan UUID is required")
		return exitError
	}
	cfg, err := config.Load(*cfgPath, 0)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	e := engine.New(cfg, version)
	res, err := e.Result(context.Background(), positionals[0], *refresh)
	switch {
	case errors.Is(err, urlscan.ErrNotReady):
		fmt.Fprintln(stderr, "scan is still processing; try again shortly")
		return exitError
	case errors.Is(err, urlscan.ErrGone):
		fmt.Fprintln(stderr, "scan result has been deleted")
		return exitError
	case err != nil:
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	if *jsonOut {
		writeJSON(stdout, res)
	} else {
		printResult(stdout, res)
	}
	return exitOK
}

// runScreenshot implements the screenshot command.
func runScreenshot(args []string, version string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("screenshot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		output  = fs.String("output", "", "output PNG path (default <uuid>.png)")
		cfgPath = fs.String("config", "", "config file path")
	)
	fs.StringVar(output, "o", "", "output PNG path (shorthand)")
	fs.StringVar(cfgPath, "c", "", "config file path (shorthand)")

	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError
	}
	if len(positionals) != 1 {
		fmt.Fprintln(stderr, "screenshot: exactly one scan UUID is required")
		return exitError
	}
	cfg, err := config.Load(*cfgPath, 0)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	e := engine.New(cfg, version)
	png, err := e.Screenshot(context.Background(), positionals[0])
	switch {
	case errors.Is(err, urlscan.ErrNotReady):
		fmt.Fprintln(stderr, "screenshot is not available (scan still processing or has none)")
		return exitError
	case err != nil:
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	out := *output
	if out == "" {
		out = strings.ToLower(strings.TrimSpace(positionals[0])) + ".png"
	}
	if err := os.WriteFile(out, png, 0o644); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	fmt.Fprintf(stdout, "wrote %s (%d bytes)\n", out, len(png))
	return exitOK
}

// runQuota implements the quota command.
func runQuota(args []string, version string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("quota", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		jsonOut = fs.Bool("json", false, "JSON output")
		cfgPath = fs.String("config", "", "config file path")
	)
	fs.BoolVar(jsonOut, "j", false, "JSON output (shorthand)")
	fs.StringVar(cfgPath, "c", "", "config file path (shorthand)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return exitError
	}
	cfg, err := config.Load(*cfgPath, 0)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	e := engine.New(cfg, version)
	q, err := e.Quota(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	if *jsonOut {
		writeJSON(stdout, q)
	} else {
		printQuota(stdout, q)
	}
	return exitOK
}

// parseInterspersed parses fs while tolerating flags that appear after
// positional arguments (Go's flag package otherwise stops at the first
// non-flag).
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positionals = append(positionals, args[0])
		args = args[1:]
	}
	return positionals, nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// printResult renders a normalized scan Result as aligned key: value lines,
// skipping empty fields.
func printResult(w io.Writer, res *urlscan.Result) {
	line := func(k, v string) {
		if v != "" {
			fmt.Fprintf(w, "%-16s %s\n", k+":", v)
		}
	}
	line("uuid", res.UUID)
	line("time", res.Time)
	line("visibility", res.Visibility)
	if res.Cached {
		line("cached", "true")
	}
	line("submitted_url", res.SubmittedURL)
	line("final_url", res.FinalURL)
	verdict := "clean"
	if res.Malicious {
		verdict = "MALICIOUS"
	}
	fmt.Fprintf(w, "%-16s %s (score %d)\n", "verdict:", verdict, res.Score)
	if len(res.Brands) > 0 {
		line("brands", strings.Join(res.Brands, ", "))
	}
	if len(res.Tags) > 0 {
		line("tags", strings.Join(res.Tags, ", "))
	}
	if len(res.Categories) > 0 {
		line("categories", strings.Join(res.Categories, ", "))
	}
	line("ip", res.IP)
	if res.ASN != "" {
		line("asn", strings.TrimSpace(res.ASN+" "+res.ASNName))
	}
	line("country", res.Country)
	line("server", res.Server)
	fmt.Fprintf(w, "%-16s %d IPs / %d domains / %d requests (%d malicious)\n",
		"observed:", res.UniqueIPs, res.UniqueDomains, res.Requests, res.MaliciousReqs)
	if len(res.RelatedDomns) > 0 {
		line("domains", strings.Join(res.RelatedDomns, ", "))
	}
	line("screenshot", res.ScreenshotURL)
	line("report", res.ReportURL)
}

// printSearch renders search hits as a compact table plus a summary line.
func printSearch(w io.Writer, res *urlscan.SearchResult) {
	for _, h := range res.Results {
		verdict := ""
		fmt.Fprintf(w, "%s  %-22s  %-15s  %s%s\n",
			h.UUID, truncate(h.Time, 20), truncate(h.IP, 15), truncate(h.URL, 60), verdict)
	}
	more := ""
	if res.HasMore {
		more = " (more available; paginate with --search-after)"
	}
	fmt.Fprintf(w, "\n%d shown, %d total%s\n", len(res.Results), res.Total, more)
}

// printQuota renders per-action remaining/limit quota (day/hour/minute) plus
// the plan metadata that bounds searches.
func printQuota(w io.Writer, q *urlscan.Quota) {
	if len(q.Actions) == 0 {
		fmt.Fprintln(w, "no quota information returned")
		return
	}
	fmt.Fprintf(w, "%-12s %14s %14s %14s\n", "action", "day", "hour", "minute")
	for _, name := range []string{"public", "unlisted", "private", "search", "retrieve", "livescan", "malicious"} {
		a, ok := q.Actions[name]
		if !ok {
			continue
		}
		fmt.Fprintf(w, "%-12s %14s %14s %14s\n", name,
			win(a.Day), win(a.Hour), win(a.Minute))
	}
	fmt.Fprintf(w, "\n(remaining/limit; search sees %v, retention %dd, max %d results)\n",
		q.QueryVisibility, q.RetentionDays, q.MaxSearchResults)
}

func win(w urlscan.Window) string {
	if w.Limit == 0 && w.Remaining == 0 && w.Used == 0 {
		return "-"
	}
	return fmt.Sprintf("%d/%d", w.Remaining, w.Limit)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
