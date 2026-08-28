package correlation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/correlation"
	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/graph"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
)

var base = time.Date(2026, 8, 23, 9, 0, 0, 0, time.UTC)

func newEngine(t *testing.T) (*correlation.Engine, *graph.Graph, storage.Store) {
	t.Helper()
	rules, err := correlation.DefaultRules()
	if err != nil {
		t.Fatalf("DefaultRules() error = %v", err)
	}
	g := graph.New()
	store := storage.NewMemoryStore(0)
	engine, err := correlation.NewEngine(correlation.Options{
		Rules: rules, Graph: g, Store: store,
		Now: func() time.Time { return base },
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return engine, g, store
}

func signinEvent(id string, at time.Time) *events.SecurityEvent {
	return &events.SecurityEvent{
		ID: id, SchemaVersion: "0.1", Timestamp: at, ReceivedAt: at,
		SourceType: "identity_provider", SourceName: "test",
		EventType: "user_signin", Category: events.CategoryAuthentication,
		Severity: events.SeverityMedium,
		Actor:    &events.Actor{Type: "identity", ID: "u-1042", Name: "u-1042"},
		Network:  &events.Network{SourceIP: "203.0.113.77", FirstSeenForActor: true},
	}
}

func secretEvent(id string, at time.Time) *events.SecurityEvent {
	return &events.SecurityEvent{
		ID: id, SchemaVersion: "0.1", Timestamp: at, ReceivedAt: at,
		SourceType: "secret_manager", SourceName: "test",
		EventType: "secret_accessed", Category: events.CategoryCredentialAccess,
		Severity: events.SeverityHigh,
		Actor:    &events.Actor{Type: "identity", ID: "u-1042", Privileged: true},
		Target:   &events.Target{Type: "secret", ID: "sec-1", Criticality: "critical"},
	}
}

func TestEngineCreatesAnIncidentFromASingleFinding(t *testing.T) {
	engine, g, _ := newEngine(t)
	ev := signinEvent("evt-1", base)
	g.Project(ev)

	inc, err := engine.Process(context.Background(), ev)
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if inc == nil {
		t.Fatal("Process() returned no incident for a matching event")
	}
	if len(inc.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(inc.Findings))
	}
	if inc.Findings[0].RuleID != "GRF-CORR-0001" {
		t.Errorf("RuleID = %q, want GRF-CORR-0001", inc.Findings[0].RuleID)
	}
	if inc.Status != incidents.StatusOpen {
		t.Errorf("Status = %q, want open", inc.Status)
	}
	if len(inc.EvidenceCategories()) != 1 {
		t.Errorf("EvidenceCategories = %v, want exactly one", inc.EvidenceCategories())
	}
	if inc.Title == "" {
		t.Error("incident has no title")
	}
	if len(inc.Evidence) != 1 {
		t.Errorf("Evidence = %d entries, want 1", len(inc.Evidence))
	}
}

func TestEngineIgnoresEventsThatMatchNoRule(t *testing.T) {
	engine, _, store := newEngine(t)
	ev := &events.SecurityEvent{
		ID: "evt-x", Timestamp: base, EventType: "heartbeat",
		Category: events.CategoryNetworkActivity, Severity: events.SeverityInformational,
		Actor: &events.Actor{Type: "identity", ID: "u-1042"},
	}
	inc, err := engine.Process(context.Background(), ev)
	if err != nil {
		t.Fatalf("Process() error = %v; a non-matching event is not an error", err)
	}
	if inc != nil {
		t.Fatal("Process() invented an incident for an event no rule matched")
	}
	if _, total, _ := store.ListIncidents(context.Background(), storage.IncidentFilter{}); total != 0 {
		t.Errorf("stored %d incidents, want 0", total)
	}
}

func TestEngineGroupsFindingsBySubjectAndRaisesRisk(t *testing.T) {
	engine, g, _ := newEngine(t)
	ctx := context.Background()

	first := signinEvent("evt-1", base)
	g.Project(first)
	incA, err := engine.Process(ctx, first)
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	second := secretEvent("evt-2", base.Add(10*time.Minute))
	g.Project(second)
	incB, err := engine.Process(ctx, second)
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if incA.ID != incB.ID {
		t.Fatalf("findings for one identity produced two incidents (%s, %s)", incA.ID, incB.ID)
	}
	if len(incB.Findings) != 2 {
		t.Fatalf("Findings = %d, want 2", len(incB.Findings))
	}
	if incB.RiskScore <= incA.RiskScore {
		t.Errorf("risk did not rise with new evidence: %d then %d", incA.RiskScore, incB.RiskScore)
	}
	if len(incB.EvidenceCategories()) != 2 {
		t.Errorf("EvidenceCategories = %v, want two independent categories", incB.EvidenceCategories())
	}
	if !incB.LastSeen.Equal(second.Timestamp) {
		t.Errorf("LastSeen = %v, want %v", incB.LastSeen, second.Timestamp)
	}
	if !incB.FirstSeen.Equal(first.Timestamp) {
		t.Errorf("FirstSeen = %v, want %v", incB.FirstSeen, first.Timestamp)
	}
}

func TestEngineDoesNotMergeDifferentSubjects(t *testing.T) {
	engine, g, _ := newEngine(t)
	ctx := context.Background()

	a := signinEvent("evt-1", base)
	g.Project(a)
	incA, _ := engine.Process(ctx, a)

	b := signinEvent("evt-2", base.Add(time.Minute))
	b.Actor.ID = "u-2210"
	g.Project(b)
	incB, _ := engine.Process(ctx, b)

	if incA.ID == incB.ID {
		t.Fatal("two identities were merged into one incident")
	}
}

func TestEngineDeduplicatesRepeatedRuleFirings(t *testing.T) {
	engine, g, _ := newEngine(t)
	ctx := context.Background()

	var last *incidents.Incident
	for i := 0; i < 5; i++ {
		ev := signinEvent("evt-"+string(rune('a'+i)), base.Add(time.Duration(i)*time.Minute))
		g.Project(ev)
		inc, err := engine.Process(ctx, ev)
		if err != nil {
			t.Fatalf("Process() error = %v", err)
		}
		last = inc
	}
	if len(last.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1; the same rule firing repeatedly is one finding with more evidence", len(last.Findings))
	}
	if len(last.Findings[0].EventIDs) != 5 {
		t.Errorf("EventIDs = %d, want all 5 firings recorded on the finding", len(last.Findings[0].EventIDs))
	}
	if len(last.Evidence) != 5 {
		t.Errorf("Evidence = %d entries, want 5", len(last.Evidence))
	}
}

func TestEngineStartsANewIncidentOutsideTheWindow(t *testing.T) {
	rules, err := correlation.DefaultRules()
	if err != nil {
		t.Fatalf("DefaultRules() error = %v", err)
	}
	g := graph.New()
	engine, err := correlation.NewEngine(correlation.Options{
		Rules: rules, Graph: g, Store: storage.NewMemoryStore(0),
		Window: time.Hour, Now: func() time.Time { return base },
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	ctx := context.Background()

	first := signinEvent("evt-1", base)
	g.Project(first)
	incA, _ := engine.Process(ctx, first)

	late := secretEvent("evt-2", base.Add(3*time.Hour))
	g.Project(late)
	incB, _ := engine.Process(ctx, late)

	if incA.ID == incB.ID {
		t.Error("an event three hours past a one-hour window was folded into the old incident")
	}
}

func TestEngineThresholdRuleRequiresRepetitionInsideTheWindow(t *testing.T) {
	engine, g, _ := newEngine(t)
	ctx := context.Background()

	failure := func(id string, at time.Time) *events.SecurityEvent {
		return &events.SecurityEvent{
			ID: id, Timestamp: at, SourceType: "identity_provider", SourceName: "test",
			EventType: "user_signin_failed", Category: events.CategoryAuthentication,
			Severity: events.SeverityLow,
			Actor:    &events.Actor{Type: "identity", ID: "u-3000"},
		}
	}

	// Four failures are below the threshold of five.
	for i := 0; i < 4; i++ {
		ev := failure("f"+string(rune('a'+i)), base.Add(time.Duration(i)*time.Minute))
		g.Project(ev)
		inc, err := engine.Process(ctx, ev)
		if err != nil {
			t.Fatalf("Process() error = %v", err)
		}
		if inc != nil {
			t.Fatalf("threshold rule fired after %d events, want 5", i+1)
		}
	}
	// The fifth crosses it.
	fifth := failure("fe", base.Add(4*time.Minute))
	g.Project(fifth)
	inc, err := engine.Process(ctx, fifth)
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if inc == nil {
		t.Fatal("threshold rule did not fire on the fifth event inside the window")
	}
	if inc.Findings[0].RuleID != "GRF-CORR-0006" {
		t.Errorf("RuleID = %q, want GRF-CORR-0006", inc.Findings[0].RuleID)
	}
}

func TestEngineThresholdWindowExpires(t *testing.T) {
	engine, g, _ := newEngine(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		// Spaced an hour apart, far outside the ten-minute window.
		ev := &events.SecurityEvent{
			ID: "slow-" + string(rune('a'+i)), Timestamp: base.Add(time.Duration(i) * time.Hour),
			SourceType: "identity_provider", SourceName: "test",
			EventType: "user_signin_failed", Category: events.CategoryAuthentication,
			Severity: events.SeverityLow,
			Actor:    &events.Actor{Type: "identity", ID: "u-4000"},
		}
		g.Project(ev)
		inc, err := engine.Process(ctx, ev)
		if err != nil {
			t.Fatalf("Process() error = %v", err)
		}
		if inc != nil {
			t.Fatalf("threshold fired on slow-drip failures at event %d; the window must bound it", i+1)
		}
	}
}

func TestEngineRecommendsActionsWithoutDeciding(t *testing.T) {
	engine, g, _ := newEngine(t)
	ctx := context.Background()

	ev := secretEvent("evt-1", base)
	g.UpsertEntity(graph.Entity{
		Type: graph.TypeSecret, Key: "sec-1", Name: "sec-1",
		Criticality: graph.CriticalityCritical, FirstSeen: base, LastSeen: base,
	})
	g.Project(ev)
	inc, err := engine.Process(ctx, ev)
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	byType := map[string]incidents.RecommendedAction{}
	for _, a := range inc.RecommendedActions {
		byType[a.ActionType] = a
	}
	if _, ok := byType["preserve_evidence"]; !ok {
		t.Error("preserve_evidence must always be proposed; every containment step degrades evidence")
	}
	rotate, ok := byType["rotate_exposed_secret"]
	if !ok {
		t.Fatal("credential access did not produce a rotation recommendation")
	}
	if rotate.Reversible {
		t.Error("rotate_exposed_secret must be reported as irreversible")
	}
	if !rotate.TargetsCriticalAsset {
		t.Error("a rotation targeting a critical secret must be flagged")
	}
	for _, a := range inc.RecommendedActions {
		if a.Destructive {
			t.Errorf("the engine recommended destructive action %q; destructive actions are never proposed", a.ActionType)
		}
		if a.Rationale == "" {
			t.Errorf("action %q has no rationale", a.ActionType)
		}
	}
}

func TestNewEngineRejectsIncompleteWiring(t *testing.T) {
	rules, _ := correlation.DefaultRules()
	tests := []struct {
		name string
		opts correlation.Options
	}{
		{"no rules", correlation.Options{Graph: graph.New(), Store: storage.NewMemoryStore(0)}},
		{"no graph", correlation.Options{Rules: rules, Store: storage.NewMemoryStore(0)}},
		{"no store", correlation.Options{Rules: rules, Graph: graph.New()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := correlation.NewEngine(tt.opts); err == nil {
				t.Error("NewEngine() accepted incomplete wiring")
			}
		})
	}
}

type failingStore struct {
	storage.Store
}

func (f failingStore) SaveIncident(context.Context, *incidents.Incident) error {
	return errors.New("simulated storage failure")
}

func TestEngineSurfacesPersistenceFailures(t *testing.T) {
	rules, _ := correlation.DefaultRules()
	g := graph.New()
	engine, err := correlation.NewEngine(correlation.Options{
		Rules: rules, Graph: g, Store: failingStore{storage.NewMemoryStore(0)},
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	ev := signinEvent("evt-1", base)
	g.Project(ev)
	if _, err := engine.Process(context.Background(), ev); err == nil {
		t.Fatal("Process() hid a persistence failure; a silently lost incident is worse than an error")
	}
}

// TestABackdatedEventCannotSplitASubjectsIncident.
//
// The subject's lastSeen was taken straight from the producer's timestamp, and
// the ingest window bounds that only at thirty days — five times the six-hour
// correlation window. So a subject under investigation could send one event
// backdated a few hours for their own identity: the expiry check is
// ev.Timestamp.Sub(lastSeen), so a backdated event is not expired and merges,
// and then rewinds the mark behind it. Every genuine event that followed
// measured itself against the rewound mark, read as expired, and opened a NEW
// incident holding a single finding.
//
// Evidence then never accumulates: no second category, no risk score above the
// automation floor, and an analyst reading a scatter of one-finding incidents
// instead of a chain.
func TestABackdatedEventCannotSplitASubjectsIncident(t *testing.T) {
	engine, _, _ := newEngine(t)
	ctx := context.Background()

	first, err := engine.Process(ctx, signinEvent("evt-1", base))
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if first == nil {
		t.Fatal("no incident from the first event")
	}

	// The evasion: one event for the same identity, timestamped well outside the
	// correlation window but well inside the ingest window.
	backdated := signinEvent("evt-backdated", base.Add(-72*time.Hour))
	if _, err := engine.Process(ctx, backdated); err != nil {
		t.Fatalf("Process(backdated) error = %v", err)
	}

	// The next genuine event must still belong to the same incident.
	third, err := engine.Process(ctx, signinEvent("evt-2", base.Add(time.Minute)))
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if third == nil {
		t.Fatal("no incident from the third event")
	}
	if third.ID != first.ID {
		t.Fatalf("the genuine event opened incident %s instead of joining %s.\n"+
			"A producer that can rewind its own subject's clock decides when GRIEFER "+
			"forgets it, and evidence stops accumulating.", third.ID, first.ID)
	}
}

// TestAGenuinelyStaleSubjectStillExpires. The fix must not turn the correlation
// window into "forever": a subject whose real last activity is outside the
// window still starts a new incident.
func TestAGenuinelyStaleSubjectStillExpires(t *testing.T) {
	engine, _, _ := newEngine(t)
	ctx := context.Background()

	first, err := engine.Process(ctx, signinEvent("evt-1", base))
	if err != nil || first == nil {
		t.Fatalf("Process() error = %v, incident = %v", err, first)
	}
	later, err := engine.Process(ctx, signinEvent("evt-2", base.Add(correlation.DefaultWindow+time.Hour)))
	if err != nil || later == nil {
		t.Fatalf("Process() error = %v, incident = %v", err, later)
	}
	if later.ID == first.ID {
		t.Error("an event outside the correlation window joined the previous incident; " +
			"the window no longer closes")
	}
}
