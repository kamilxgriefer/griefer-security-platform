package demo_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/fixtures"
	"github.com/kamilxgriefer/griefer-security-platform/internal/demo"
	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/graph"
)

func TestLoadInventoryIsValidAndReferentiallySound(t *testing.T) {
	inv, err := demo.LoadInventory()
	if err != nil {
		t.Fatalf("LoadInventory() error = %v", err)
	}
	if len(inv.Entities) == 0 || len(inv.Edges) == 0 {
		t.Fatal("the baseline inventory is empty")
	}
	// ApplyInventory validates every edge reference, so a typo in the fixture
	// surfaces here rather than as a silently missing blast-radius path.
	if err := graph.New().ApplyInventory(inv, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyInventory() error = %v", err)
	}

	critical := 0
	for _, e := range inv.Entities {
		if e.Criticality == graph.CriticalityCritical {
			critical++
		}
	}
	if critical == 0 {
		t.Error("no asset is classified critical; the critical-asset policy rule would never be exercised by the demo")
	}
}

func TestFixturesContainNoRealIdentifiers(t *testing.T) {
	// The fixtures must stay obviously synthetic. This test is the guard that
	// stops a real capture from being dropped into the directory.
	raw, err := fixtures.FS.ReadFile(fixtures.ScenarioOne)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	body := string(raw)

	// Keys that would hold an actual secret value, and formats that ARE secret
	// values. The trailing colon matters: naming an auth method
	// "password_and_totp" or a secret kind "api_key" is fine, because those are
	// values describing a thing. A FIELD called "api_key" would hold one.
	for _, forbidden := range []string{
		`"password":`, `"passwd":`, `"secret_value":`, `"client_secret":`,
		`"access_token":`, `"refresh_token":`, `"private_key":`, `"api_key":`,
		"BEGIN PRIVATE KEY", "BEGIN RSA", "eyJhbGciOi", "AKIA", "ghp_", "xoxb-",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the scenario fixture contains %q, which would hold or be credential material", forbidden)
		}
	}
	if !strings.Contains(body, "halberd.example") {
		t.Error("the fixture should use an RFC 2606 reserved domain")
	}
	if !strings.Contains(body, "203.0.113.") {
		t.Error("the fixture should use RFC 5737 TEST-NET addresses")
	}
}

func TestLoadScenarioRequiresTheSyntheticMarker(t *testing.T) {
	sc, err := demo.LoadScenario(fixtures.ScenarioOne)
	if err != nil {
		t.Fatalf("LoadScenario() error = %v", err)
	}
	if !sc.Synthetic {
		t.Fatal("the shipped scenario is not marked synthetic")
	}
	if len(sc.Events) != 5 {
		t.Errorf("Events = %d, want the five-step demo chain", len(sc.Events))
	}
	if _, err := demo.LoadScenario("synthetic/does-not-exist.json"); err == nil {
		t.Error("LoadScenario() accepted a missing path")
	}
}

func TestScenarioEventsPassSchemaValidation(t *testing.T) {
	// The demo must go through the same trust boundary as any producer. A
	// fixture that would be rejected by the API is a broken demo.
	v, err := events.NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error = %v", err)
	}
	sc, err := demo.LoadScenario(fixtures.ScenarioOne)
	if err != nil {
		t.Fatalf("LoadScenario() error = %v", err)
	}
	for i, raw := range sc.Events {
		if err := v.Validate(raw); err != nil {
			t.Errorf("event %d fails schema validation: %v", i+1, err)
		}
	}
}

func TestRebaseKeepsRelativeSpacingAndLandsInTheIngestWindow(t *testing.T) {
	sc, err := demo.LoadScenario(fixtures.ScenarioOne)
	if err != nil {
		t.Fatalf("LoadScenario() error = %v", err)
	}
	now := time.Date(2030, 1, 15, 12, 0, 0, 0, time.UTC)
	rebased, err := sc.Rebase(now)
	if err != nil {
		t.Fatalf("Rebase() error = %v", err)
	}
	if len(rebased) != len(sc.Events) {
		t.Fatalf("Rebase() returned %d events, want %d", len(rebased), len(sc.Events))
	}

	originals := timestamps(t, sc.Events)
	shifted := timestamps(t, rebased)

	last := shifted[len(shifted)-1]
	if !last.Equal(now) {
		t.Errorf("last event = %v, want it rebased onto %v", last, now)
	}
	for i := 1; i < len(shifted); i++ {
		wantGap := originals[i].Sub(originals[i-1])
		gotGap := shifted[i].Sub(shifted[i-1])
		if wantGap != gotGap {
			t.Errorf("gap %d = %v, want the original %v", i, gotGap, wantGap)
		}
	}
	// Rebased events must survive normalization, which is the check that keeps
	// the demo working a year from now.
	n := events.NewNormalizerWithClock(func() time.Time { return now })
	v, err := events.NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error = %v", err)
	}
	for i, raw := range rebased {
		ev, err := v.Decode(raw)
		if err != nil {
			t.Fatalf("rebased event %d failed validation: %v", i, err)
		}
		if _, err := n.Normalize(ev); err != nil {
			t.Errorf("rebased event %d fell outside the ingest window: %v", i, err)
		}
	}
}

func timestamps(t *testing.T, raws []json.RawMessage) []time.Time {
	t.Helper()
	out := make([]time.Time, 0, len(raws))
	for i, raw := range raws {
		var doc struct {
			Timestamp string `json:"timestamp"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		parsed, err := time.Parse(time.RFC3339, doc.Timestamp)
		if err != nil {
			t.Fatalf("event %d timestamp %q: %v", i, doc.Timestamp, err)
		}
		out = append(out, parsed)
	}
	return out
}
