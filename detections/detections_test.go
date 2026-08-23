package detections_test

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kamilxgriefer/griefer-security-platform/detections"
)

// sigmaRule is the subset of the Sigma specification GRIEFER validates.
//
// GRIEFER v0.1 does not evaluate Sigma rules; it publishes them for export to
// external SIEM and EDR platforms. Shipping detection content that has never
// been parsed would be shipping a text file with a .yaml extension, so CI
// checks every rule for the fields a consumer actually needs.
type sigmaRule struct {
	Title          string         `yaml:"title"`
	ID             string         `yaml:"id"`
	Status         string         `yaml:"status"`
	Description    string         `yaml:"description"`
	References     []string       `yaml:"references"`
	Author         string         `yaml:"author"`
	Date           string         `yaml:"date"`
	Tags           []string       `yaml:"tags"`
	LogSource      map[string]any `yaml:"logsource"`
	Detection      map[string]any `yaml:"detection"`
	FalsePositives []string       `yaml:"falsepositives"`
	Level          string         `yaml:"level"`
}

var (
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	validLevels = map[string]bool{"informational": true, "low": true, "medium": true, "high": true, "critical": true}
	validStatus = map[string]bool{"stable": true, "test": true, "experimental": true, "deprecated": true, "unsupported": true}
)

func TestSigmaRulesAreWellFormed(t *testing.T) {
	entries, err := fs.ReadDir(detections.SigmaFS, detections.SigmaDir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no Sigma rules are shipped")
	}

	seenIDs := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			raw, err := fs.ReadFile(detections.SigmaFS, detections.SigmaDir+"/"+entry.Name())
			if err != nil {
				t.Fatalf("ReadFile() error = %v", err)
			}
			var rule sigmaRule
			if err := yaml.Unmarshal(raw, &rule); err != nil {
				t.Fatalf("rule is not valid YAML: %v", err)
			}

			if rule.Title == "" {
				t.Error("title is required")
			}
			if !uuidPattern.MatchString(rule.ID) {
				t.Errorf("id = %q, want a UUID", rule.ID)
			}
			if prev, dup := seenIDs[rule.ID]; dup {
				t.Errorf("id %s is also used by %s", rule.ID, prev)
			}
			seenIDs[rule.ID] = entry.Name()

			if !validStatus[rule.Status] {
				t.Errorf("status = %q, want a Sigma status value", rule.Status)
			}
			if !validLevels[rule.Level] {
				t.Errorf("level = %q, want a Sigma level value", rule.Level)
			}
			if strings.TrimSpace(rule.Description) == "" {
				t.Error("description is required")
			}
			if len(rule.LogSource) == 0 {
				t.Error("logsource is required")
			}
			if len(rule.Detection) == 0 {
				t.Error("detection is required")
			}
			if _, ok := rule.Detection["condition"]; !ok {
				t.Error("detection has no condition")
			}
			// A detection with no documented false positives has not been
			// thought about; every rule here fires on activity that is
			// sometimes legitimate.
			if len(rule.FalsePositives) == 0 {
				t.Error("falsepositives is required")
			}
			if len(rule.Tags) == 0 {
				t.Error("tags are required so the rule maps to ATT&CK")
			}
			hasAttack := false
			for _, tag := range rule.Tags {
				if strings.HasPrefix(tag, "attack.t") {
					hasAttack = true
				}
			}
			if !hasAttack {
				t.Errorf("tags = %v, want at least one attack.tNNNN technique tag", rule.Tags)
			}
		})
	}
}

func TestEmbeddedDetectionContentIsPresent(t *testing.T) {
	for _, dir := range []struct {
		name string
		fsys fs.FS
		root string
	}{
		{"correlation", detections.CorrelationFS, detections.CorrelationDir},
		{"sigma", detections.SigmaFS, detections.SigmaDir},
	} {
		entries, err := fs.ReadDir(dir.fsys, dir.root)
		if err != nil {
			t.Fatalf("%s: ReadDir() error = %v", dir.name, err)
		}
		count := 0
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".yaml") {
				count++
			}
		}
		if count == 0 {
			t.Errorf("%s: no rule files are embedded in the binary", dir.name)
		}
	}
}
