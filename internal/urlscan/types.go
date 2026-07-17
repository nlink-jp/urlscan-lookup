package urlscan

import (
	"encoding/json"
	"fmt"
)

// SubmitRequest is the body of POST /api/v1/scan/.
type SubmitRequest struct {
	URL        string   `json:"url"`
	Visibility string   `json:"visibility,omitempty"` // private | unlisted | public
	Tags       []string `json:"tags,omitempty"`
	Country    string   `json:"country,omitempty"`     // scanning PoP, e.g. "jp"
	Referer    string   `json:"referer,omitempty"`     // sent Referer header
	UserAgent  string   `json:"customagent,omitempty"` // sent User-Agent (urlscan calls it customagent)
}

// SubmitResponse is the 200 body of a scan submission. The scan runs
// asynchronously; poll Result with UUID until it is ready.
type SubmitResponse struct {
	Message    string `json:"message"`
	UUID       string `json:"uuid"`
	Result     string `json:"result"` // human result page URL
	API        string `json:"api"`    // result API URL
	Visibility string `json:"visibility"`
	URL        string `json:"url"`
	Country    string `json:"country,omitempty"`
}

// Result is the normalized scan result shared by the CLI and the MCP server.
// urlscan's large, nested result JSON is distilled to the fields an analyst
// acts on; the full body is available via Raw.
type Result struct {
	UUID          string          `json:"uuid"`
	Time          string          `json:"time,omitempty"`
	Visibility    string          `json:"visibility,omitempty"`
	SubmittedURL  string          `json:"submitted_url,omitempty"`
	FinalURL      string          `json:"final_url,omitempty"`
	IP            string          `json:"ip,omitempty"`
	ASN           string          `json:"asn,omitempty"`
	ASNName       string          `json:"asn_name,omitempty"`
	Country       string          `json:"country,omitempty"`
	Server        string          `json:"server,omitempty"`
	Malicious     bool            `json:"malicious"`
	Score         int             `json:"score"`
	Tags          []string        `json:"tags,omitempty"`
	Brands        []string        `json:"brands,omitempty"`
	Categories    []string        `json:"categories,omitempty"`
	UniqueIPs     int             `json:"unique_ips,omitempty"`
	UniqueDomains int             `json:"unique_domains,omitempty"`
	Requests      int             `json:"requests,omitempty"`
	MaliciousReqs int             `json:"malicious_requests,omitempty"`
	RelatedIPs    []string        `json:"related_ips,omitempty"`
	RelatedDomns  []string        `json:"related_domains,omitempty"`
	ScreenshotURL string          `json:"screenshot_url,omitempty"`
	ReportURL     string          `json:"report_url,omitempty"`
	Cached        bool            `json:"cached,omitempty"`
	Raw           json.RawMessage `json:"raw,omitempty"`
}

// SearchHit is one normalized row of a /search response.
type SearchHit struct {
	UUID          string `json:"uuid"`
	Time          string `json:"time,omitempty"`
	URL           string `json:"url,omitempty"`
	Domain        string `json:"domain,omitempty"`
	IP            string `json:"ip,omitempty"`
	ASN           string `json:"asn,omitempty"`
	Country       string `json:"country,omitempty"`
	ReportURL     string `json:"report_url,omitempty"`
	ScreenshotURL string `json:"screenshot_url,omitempty"`
}

// SearchResult is the normalized /search response.
type SearchResult struct {
	Total   int             `json:"total"`
	Took    int             `json:"took,omitempty"`
	HasMore bool            `json:"has_more"`
	Results []SearchHit     `json:"results"`
	Raw     json.RawMessage `json:"raw,omitempty"`
}

// Window is one rate-limit window (day/hour/minute) of a quota action.
type Window struct {
	Limit     int `json:"limit"`
	Used      int `json:"used"`
	Remaining int `json:"remaining"`
}

// ActionQuota holds the per-window quota for one action.
type ActionQuota struct {
	Day    Window `json:"day"`
	Hour   Window `json:"hour"`
	Minute Window `json:"minute"`
}

// Quota is the normalized /user/quotas/ response. Actions is keyed by action
// name (public, private, unlisted, search, retrieve, livescan, malicious).
// The account's plan metadata carried alongside the per-action quotas is
// surfaced too.
type Quota struct {
	Scope            string                 `json:"scope,omitempty"`
	Actions          map[string]ActionQuota `json:"actions"`
	MaxSearchResults int                    `json:"max_search_results,omitempty"`
	RetentionDays    int                    `json:"retention_days,omitempty"`
	QueryVisibility  []string               `json:"query_visibility,omitempty"`
	Raw              json.RawMessage        `json:"raw,omitempty"`
}

// --- wire types (lenient: fields vary across urlscan versions) ---

type resultWire struct {
	Task struct {
		UUID          string `json:"uuid"`
		Time          string `json:"time"`
		URL           string `json:"url"`
		Visibility    string `json:"visibility"`
		ReportURL     string `json:"reportURL"`
		ScreenshotURL string `json:"screenshotURL"`
	} `json:"task"`
	Page struct {
		URL     string `json:"url"`
		Domain  string `json:"domain"`
		IP      string `json:"ip"`
		ASN     string `json:"asn"`
		ASNName string `json:"asnname"`
		Country string `json:"country"`
		Server  string `json:"server"`
	} `json:"page"`
	Lists struct {
		IPs     []string `json:"ips"`
		Domains []string `json:"domains"`
		URLs    []string `json:"urls"`
	} `json:"lists"`
	Verdicts struct {
		Overall struct {
			Score      int             `json:"score"`
			Malicious  bool            `json:"malicious"`
			Tags       []string        `json:"tags"`
			Categories []string        `json:"categories"`
			Brands     json.RawMessage `json:"brands"`
		} `json:"overall"`
	} `json:"verdicts"`
	Stats struct {
		UniqIPs       int `json:"uniqIPs"`
		UniqCountries int `json:"uniqCountries"`
		Malicious     int `json:"malicious"`
	} `json:"stats"`
	Data struct {
		Requests []json.RawMessage `json:"requests"`
	} `json:"data"`
}

// normalizeResult distills the raw result body into Result, tolerating
// missing fields.
func normalizeResult(body []byte) (*Result, error) {
	var w resultWire
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("not valid urlscan result JSON: %w", err)
	}
	res := &Result{
		UUID:          w.Task.UUID,
		Time:          w.Task.Time,
		Visibility:    w.Task.Visibility,
		SubmittedURL:  w.Task.URL,
		FinalURL:      w.Page.URL,
		IP:            w.Page.IP,
		ASN:           w.Page.ASN,
		ASNName:       w.Page.ASNName,
		Country:       w.Page.Country,
		Server:        w.Page.Server,
		Malicious:     w.Verdicts.Overall.Malicious,
		Score:         w.Verdicts.Overall.Score,
		Tags:          w.Verdicts.Overall.Tags,
		Categories:    w.Verdicts.Overall.Categories,
		Brands:        brandNames(w.Verdicts.Overall.Brands),
		UniqueIPs:     firstPositive(w.Stats.UniqIPs, len(w.Lists.IPs)),
		UniqueDomains: len(w.Lists.Domains),
		Requests:      len(w.Data.Requests),
		MaliciousReqs: w.Stats.Malicious,
		RelatedIPs:    head(w.Lists.IPs, 10),
		RelatedDomns:  head(w.Lists.Domains, 10),
		ScreenshotURL: w.Task.ScreenshotURL,
		ReportURL:     w.Task.ReportURL,
	}
	return res, nil
}

// brandNames extracts brand names from the polymorphic verdicts brands field,
// which may be a list of strings or of {name: ...} objects.
func brandNames(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var strs []string
	if json.Unmarshal(raw, &strs) == nil && len(strs) > 0 {
		return strs
	}
	var objs []struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(raw, &objs) == nil {
		out := make([]string, 0, len(objs))
		for _, o := range objs {
			if o.Name != "" {
				out = append(out, o.Name)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

type searchWire struct {
	Total   int  `json:"total"`
	Took    int  `json:"took"`
	HasMore bool `json:"has_more"`
	Results []struct {
		Task struct {
			UUID string `json:"uuid"`
			Time string `json:"time"`
			URL  string `json:"url"`
		} `json:"task"`
		Page struct {
			Domain  string `json:"domain"`
			IP      string `json:"ip"`
			ASN     string `json:"asn"`
			Country string `json:"country"`
			URL     string `json:"url"`
		} `json:"page"`
		Result     string `json:"result"`
		Screenshot string `json:"screenshot"`
	} `json:"results"`
}

func normalizeSearch(body []byte) (*SearchResult, error) {
	var w searchWire
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("not valid urlscan search JSON: %w", err)
	}
	out := &SearchResult{Total: w.Total, Took: w.Took, HasMore: w.HasMore}
	for _, r := range w.Results {
		url := r.Task.URL
		if url == "" {
			url = r.Page.URL
		}
		out.Results = append(out.Results, SearchHit{
			UUID:          r.Task.UUID,
			Time:          r.Task.Time,
			URL:           url,
			Domain:        r.Page.Domain,
			IP:            r.Page.IP,
			ASN:           r.Page.ASN,
			Country:       r.Page.Country,
			ReportURL:     r.Result,
			ScreenshotURL: r.Screenshot,
		})
	}
	return out, nil
}

// normalizeQuota parses the /user/quotas/ body. urlscan nests per-action
// quotas under a "limits" object, but that object also carries plan metadata
// (features, queryableFields, maxSearchResults, a nested files object, ...),
// so the actions are extracted by shape: only entries that are objects with a
// "day" window are treated as action quotas.
func normalizeQuota(body []byte) (*Quota, error) {
	var w struct {
		Scope  string                     `json:"scope"`
		Limits map[string]json.RawMessage `json:"limits"`
	}
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("not valid urlscan quota JSON: %w", err)
	}
	q := &Quota{Scope: w.Scope, Actions: map[string]ActionQuota{}}
	for name, raw := range w.Limits {
		switch name {
		case "maxSearchResults":
			_ = json.Unmarshal(raw, &q.MaxSearchResults)
			continue
		case "maxRetentionPeriodDays":
			_ = json.Unmarshal(raw, &q.RetentionDays)
			continue
		case "queryVisibility":
			_ = json.Unmarshal(raw, &q.QueryVisibility)
			continue
		}
		// An action quota is an object with day/hour/minute windows; skip
		// lists, scalars, and the nested files object (keyed by visibility).
		var probe map[string]json.RawMessage
		if json.Unmarshal(raw, &probe) != nil {
			continue
		}
		if _, ok := probe["day"]; !ok {
			continue
		}
		var aq ActionQuota
		if json.Unmarshal(raw, &aq) == nil {
			q.Actions[name] = aq
		}
	}
	return q, nil
}

func firstPositive(vals ...int) int {
	for _, v := range vals {
		if v > 0 {
			return v
		}
	}
	return 0
}

func head(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
