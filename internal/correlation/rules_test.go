package correlation_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/kamilxgriefer/griefer-security-platform/internal/correlation"
	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
)

func TestDefaultRulesLoadAndCoverTheDemoChain(t *testing.T) {
	rules, err := correlation.DefaultRules()
	if err != nil {
		t.Fatalf("DefaultRules() error = %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("no rules were loaded; a silently ruleless engine looks healthy and detects nothing")
	}

	byID := map[string]correlation.Rule{}
	categories := map[events.Category]bool{}
	for _, r := range rules {
		byID[r.ID] = r
		categories[r.Category] = true
	}
	for _, want := range []string{
		"GRF-CORR-0001", "GRF-CORR-0002", "GRF-CORR-0003", "GRF-CORR-0004", "GRF-CORR-0005",
	} {
		rule, ok := byID[want]
		if !ok {
			t.Errorf("rule %s is missing; the demo scenario depends on it", want)
			continue
		}
		if rule.Description == "" {
			t.Errorf("rule %s has no description; an analyst cannot triage an unexplained finding", want)
		}
		if len(rule.Techniques) == 0 {
			t.Errorf("rule %s carries no ATT&CK technique", want)
		}
	}
	// The chain must span independent categories, or the Policy Kernel's
	// corroboration requirement can never be satisfied by it.
	if len(categories) < 4 {
		t.Errorf("rules span %d evidence categories, want at least 4", len(categories))
	}
}

func TestLoadRulesRejectsUnsafeRuleContent(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "field outside the allowlist",
			yaml: `version: "0.1"
rules:
  - id: R1
    title: t
    category: authentication
    severity: medium
    confidence: 0.5
    match:
      conditions:
        - field: actor.password_hash
          equals: x
`,
			wantErr: "not in the allowlist",
		},
		{
			name: "unconstrained rule would match all telemetry",
			yaml: `version: "0.1"
rules:
  - id: R1
    title: t
    category: authentication
    severity: medium
    confidence: 0.5
    match: {}
`,
			wantErr: "must constrain at least one field",
		},
		{
			name: "condition with two operators is ambiguous",
			yaml: `version: "0.1"
rules:
  - id: R1
    title: t
    category: authentication
    severity: medium
    confidence: 0.5
    match:
      conditions:
        - field: event_type
          equals: a
          not_equals: b
`,
			wantErr: "exactly one operator",
		},
		{
			name: "confidence out of range",
			yaml: `version: "0.1"
rules:
  - id: R1
    title: t
    category: authentication
    severity: medium
    confidence: 4.2
    match:
      event_type: [x]
`,
			wantErr: "confidence must be within",
		},
		{
			name: "unknown severity",
			yaml: `version: "0.1"
rules:
  - id: R1
    title: t
    category: authentication
    severity: apocalyptic
    confidence: 0.5
    match:
      event_type: [x]
`,
			wantErr: "invalid severity",
		},
		{
			name: "threshold of one is not a threshold",
			yaml: `version: "0.1"
rules:
  - id: R1
    title: t
    category: authentication
    severity: medium
    confidence: 0.5
    match:
      event_type: [x]
    threshold:
      count: 1
      window: 10m
`,
			wantErr: "at least 2",
		},
		{
			name: "an unknown yaml key is a typo, not an extension point",
			yaml: `version: "0.1"
rules:
  - id: R1
    title: t
    categorie: authentication
    severity: medium
    confidence: 0.5
    match:
      event_type: [x]
`,
			wantErr: "parse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{"rules/pack.yaml": &fstest.MapFile{Data: []byte(tt.yaml)}}
			_, err := correlation.LoadRules(fsys, "rules")
			if err == nil {
				t.Fatal("LoadRules() accepted unsafe rule content")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadRulesRejectsDuplicateIDs(t *testing.T) {
	rule := `version: "0.1"
rules:
  - id: DUP
    title: t
    category: authentication
    severity: medium
    confidence: 0.5
    match:
      event_type: [x]
`
	fsys := fstest.MapFS{
		"rules/a.yaml": &fstest.MapFile{Data: []byte(rule)},
		"rules/b.yaml": &fstest.MapFile{Data: []byte(rule)},
	}
	_, err := correlation.LoadRules(fsys, "rules")
	if err == nil || !strings.Contains(err.Error(), "duplicate rule id") {
		t.Fatalf("LoadRules() error = %v, want a duplicate-id error", err)
	}
}

func TestLoadRulesRejectsAnEmptyDirectory(t *testing.T) {
	fsys := fstest.MapFS{"rules/notes.txt": &fstest.MapFile{Data: []byte("ignored")}}
	if _, err := correlation.LoadRules(fsys, "rules"); err == nil {
		t.Fatal("LoadRules() accepted a directory containing no rules")
	}
}

func TestRuleMatching(t *testing.T) {
	rules, err := correlation.DefaultRules()
	if err != nil {
		t.Fatalf("DefaultRules() error = %v", err)
	}
	byID := map[string]correlation.Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}

	signin := byID["GRF-CORR-0001"]
	tests := []struct {
		name string
		ev   *events.SecurityEvent
		want bool
	}{
		{
			name: "sign-in from a new address matches",
			ev: &events.SecurityEvent{
				EventType: "user_signin",
				Network:   &events.Network{FirstSeenForActor: true},
			},
			want: true,
		},
		{
			name: "sign-in from a known address does not",
			ev: &events.SecurityEvent{
				EventType: "user_signin",
				Network:   &events.Network{FirstSeenForActor: false},
			},
			want: false,
		},
		{
			name: "missing network block does not match",
			ev:   &events.SecurityEvent{EventType: "user_signin"},
			want: false,
		},
		{
			name: "a different event type does not match",
			ev: &events.SecurityEvent{
				EventType: "secret_accessed",
				Network:   &events.Network{FirstSeenForActor: true},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := signin.Matches(tt.ev); got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRuleConditionsCannotBeSatisfiedByAttackerNamedLabels(t *testing.T) {
	// A rule may compare a label, but a label can never carry an instruction.
	// This test pins the boundary: the only thing a label can do is decide
	// whether a rule matched.
	yaml := `version: "0.1"
rules:
  - id: R1
    title: labelled
    category: authentication
    severity: low
    confidence: 0.5
    match:
      event_type: [user_signin]
      conditions:
        - field: labels.outcome
          equals: failure
`
	fsys := fstest.MapFS{"rules/pack.yaml": &fstest.MapFile{Data: []byte(yaml)}}
	rules, err := correlation.LoadRules(fsys, "rules")
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}
	rule := rules[0]

	if !rule.Matches(&events.SecurityEvent{EventType: "user_signin", Labels: map[string]string{"outcome": "failure"}}) {
		t.Error("a label condition should match when the label is present")
	}
	if rule.Matches(&events.SecurityEvent{EventType: "user_signin", Labels: map[string]string{"outcome": "success"}}) {
		t.Error("a label condition should not match a different value")
	}
	if rule.Matches(&events.SecurityEvent{EventType: "user_signin"}) {
		t.Error("a label condition should not match when the label is absent")
	}
	// The rule's own severity and category come from the rule file, never from
	// the event, so a hostile producer cannot escalate its own finding.
	if rule.Severity != events.SeverityLow || rule.Category != events.CategoryAuthentication {
		t.Error("rule metadata must come from the rule definition")
	}
}
