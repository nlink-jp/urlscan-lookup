package mcp

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// manualToolNames returns the advertised tool names, so the manual is checked
// against the registry rather than against a second list that would drift.
func manualToolNames(t *testing.T) []string {
	t.Helper()
	b, err := json.Marshal(toolsList())
	if err != nil {
		t.Fatalf("marshal tool list: %v", err)
	}
	var list struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("tool list is not valid JSON: %v", err)
	}
	names := make([]string, 0, len(list.Tools))
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
	}
	// Without this the callers below pass by having nothing to check.
	if len(names) == 0 {
		t.Fatal("toolsList returned no tools")
	}
	return names
}

func TestManualNamesEveryTool(t *testing.T) {
	for _, name := range manualToolNames(t) {
		if !strings.Contains(usageMarkdown, name) {
			t.Errorf("usage.md never mentions the %s tool; a manual that omits a tool is why get_usage exists", name)
		}
	}
}

// TestManualClaimsNoExemptionFromStrictArguments compares the manual against
// the behaviour it describes, in the one direction that has already gone
// wrong: the error table kept a row saying `get_screenshot` "does not yet
// check" unknown arguments after that exemption was removed, contradicting a
// paragraph two screens above it in the same file.
//
// The manual is not decoration. It is embedded in the binary, returned by
// get_usage, and read by the model deciding whether to trust an error — so a
// stale exemption tells it to retry a call that will keep failing, and to
// distrust the one error message that names the mistake. Nothing compared the
// two halves, so the contradiction shipped in a release.
//
// The phrasing is banned as a class, not as a sentence: every tool is checked
// (TestUnknownArgumentIsRefusedByName and
// TestGetScreenshotRefusesAnUnknownArgument), so any wording that carves one
// out is false by construction. Describing the withdrawn exemption in the past
// tense stays allowed — that is history, and the file does it deliberately.
func TestManualClaimsNoExemptionFromStrictArguments(t *testing.T) {
	exemption := regexp.MustCompile(`(?i)(does|do) not (yet )?(check|refuse|validate)|is (currently )?the one exception|except (for )?get_`)
	if m := exemption.FindString(usageMarkdown); m != "" {
		t.Errorf("usage.md claims a tool is exempt from the strict argument check (%q), but every tool refuses an undeclared argument", m)
	}
	// Positive control: the pattern has to match the sentence that shipped,
	// or this test is watching for nothing.
	shipped := "Note `get_screenshot` does not yet check this."
	if !exemption.MatchString(shipped) {
		t.Errorf("the pattern no longer matches the wording it exists for: %q", shipped)
	}
}
