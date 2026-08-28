package storage_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/graph"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
)

var at = time.Date(2026, 8, 23, 9, 0, 0, 0, time.UTC)

// storeFactory builds a fresh, empty store.
type storeFactory struct {
	name string
	open func(t *testing.T) storage.Store
}

// factories returns every store implementation available in this environment.
//
// The PostgreSQL store is included whenever GRIEFER_TEST_POSTGRES_DSN is set.
// Running the SAME suite against both implementations is what stops the memory
// store from quietly becoming a more forgiving fake than the real thing.
func factories(t *testing.T) []storeFactory {
	t.Helper()
	out := []storeFactory{{
		name: "memory",
		open: func(*testing.T) storage.Store { return storage.NewMemoryStore(0) },
	}}
	dsn := os.Getenv("GRIEFER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Log("GRIEFER_TEST_POSTGRES_DSN is not set; skipping the PostgreSQL conformance run")
		return out
	}
	out = append(out, storeFactory{
		name: "postgres",
		open: func(t *testing.T) storage.Store {
			t.Helper()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			store, err := storage.NewPostgresStore(ctx, storage.PostgresOptions{DSN: dsn})
			if err != nil {
				t.Fatalf("NewPostgresStore() error = %v", err)
			}
			truncate(t, store)
			t.Cleanup(func() { _ = store.Close() })
			return store
		},
	})
	return out
}

func TestStoreConformance(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			t.Run("events", func(t *testing.T) { testEvents(t, f.open(t)) })
			t.Run("incidents", func(t *testing.T) { testIncidents(t, f.open(t)) })
			t.Run("actions", func(t *testing.T) { testActions(t, f.open(t)) })
			t.Run("audit", func(t *testing.T) { testAudit(t, f.open(t)) })
			t.Run("pagination", func(t *testing.T) { testPagination(t, f.open(t)) })
		})
	}
}

func testEvents(t *testing.T, store storage.Store) {
	ctx := context.Background()
	ev := &events.SecurityEvent{
		ID: "evt-1", SchemaVersion: "0.1", Timestamp: at, ReceivedAt: at,
		SourceType: "identity_provider", SourceName: "test", EventType: "user_signin",
		Category: events.CategoryAuthentication, Severity: events.SeverityMedium,
		Actor:  &events.Actor{Type: "identity", ID: "u-1"},
		Labels: map[string]string{"outcome": "success"},
	}
	stored, err := store.SaveEvent(ctx, ev)
	if err != nil {
		t.Fatalf("SaveEvent() error = %v", err)
	}
	if !stored {
		t.Fatal("SaveEvent() reported a new event as already present")
	}
	// Producers retry; a retry storm must not become an error storm — and the
	// caller has to be able to tell, or it processes the retry as evidence.
	stored, err = store.SaveEvent(ctx, ev)
	if err != nil {
		t.Fatalf("SaveEvent() is not idempotent: %v", err)
	}
	if stored {
		t.Error("SaveEvent() reported a repeat as newly stored; the caller would " +
			"correlate, project and publish it a second time")
	}

	got, total, err := store.ListEvents(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	if total != 1 || len(got) != 1 {
		t.Fatalf("ListEvents() = %d items / total %d, want 1/1", len(got), total)
	}
	if got[0].ID != "evt-1" || got[0].Labels["outcome"] != "success" {
		t.Errorf("round-trip lost data: %+v", got[0])
	}
	if !got[0].Timestamp.UTC().Equal(at) {
		t.Errorf("Timestamp = %v, want %v", got[0].Timestamp.UTC(), at)
	}

	count, err := store.CountEvents(ctx)
	if err != nil || count != 1 {
		t.Errorf("CountEvents() = %d, %v; want 1, nil", count, err)
	}
	if _, err := store.SaveEvent(ctx, &events.SecurityEvent{}); err == nil {
		t.Error("SaveEvent() accepted an event with no id")
	}
}

func sampleIncident(id string, score int, severity events.Severity, lastSeen time.Time) *incidents.Incident {
	return &incidents.Incident{
		ID: id, SchemaVersion: "0.1", Title: "test incident " + id,
		Status: incidents.StatusOpen, Severity: severity, RiskScore: score,
		Confidence: 0.8, FirstSeen: at, LastSeen: lastSeen, UpdatedAt: lastSeen,
		PrimaryIdentity: "identity:u-1",
		Findings: []incidents.Finding{{
			ID: "fnd-1", RuleID: "GRF-CORR-0001", Title: "finding",
			Category: events.CategoryAuthentication, Severity: severity, Confidence: 0.6,
			Techniques: []incidents.Technique{{ID: "T1078", Name: "Valid Accounts"}},
			EntityIDs:  []string{"identity:u-1"}, EventIDs: []string{"evt-1"},
			FirstSeen: at, LastSeen: lastSeen,
		}},
		Entities: []incidents.EntityRef{{
			ID: "identity:u-1", Type: graph.TypeIdentity, Name: "u-1", Criticality: graph.CriticalityHigh,
		}},
		BlastRadius: graph.BlastRadius{
			Score: 40, MaxHops: 2, CriticalAssets: 1, Summary: "summary",
			Reachable: []graph.ReachableEntity{{ID: "secret:s-1", Type: graph.TypeSecret, Hops: 1}},
		},
		RecommendedActions: []incidents.RecommendedAction{{
			ActionType: "preserve_evidence", Title: "Preserve evidence",
			Reversible: true, RollbackAction: "release_evidence_hold",
		}},
		Evidence: []incidents.Evidence{{EventID: "evt-1", OccurredAt: at, Summary: "s", SourceName: "test"}},
	}
}

func testIncidents(t *testing.T, store storage.Store) {
	ctx := context.Background()
	inc := sampleIncident("inc-1", 81, events.SeverityCritical, at)
	if err := store.SaveIncident(ctx, inc); err != nil {
		t.Fatalf("SaveIncident() error = %v", err)
	}

	got, err := store.GetIncident(ctx, "inc-1")
	if err != nil {
		t.Fatalf("GetIncident() error = %v", err)
	}
	if got.RiskScore != 81 || len(got.Findings) != 1 || len(got.BlastRadius.Reachable) != 1 {
		t.Errorf("round-trip lost structure: %+v", got)
	}
	if got.Findings[0].Techniques[0].ID != "T1078" {
		t.Error("nested technique data was lost")
	}

	// Correlation rewrites an incident in full every time evidence changes.
	inc.RiskScore = 90
	inc.Status = incidents.StatusInvestigating
	if err := store.SaveIncident(ctx, inc); err != nil {
		t.Fatalf("SaveIncident() upsert error = %v", err)
	}
	got, _ = store.GetIncident(ctx, "inc-1")
	if got.RiskScore != 90 || got.Status != incidents.StatusInvestigating {
		t.Errorf("upsert did not take effect: %+v", got)
	}

	// A caller mutating a returned incident must not rewrite stored history.
	got.Title = "tampered"
	fresh, _ := store.GetIncident(ctx, "inc-1")
	if fresh.Title == "tampered" {
		t.Error("the store returned a live reference; a handler could rewrite history by accident")
	}

	if _, err := store.GetIncident(ctx, "inc-missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("GetIncident() error = %v, want ErrNotFound", err)
	}

	// Filters.
	if err := store.SaveIncident(ctx, sampleIncident("inc-2", 20, events.SeverityMedium, at.Add(time.Hour))); err != nil {
		t.Fatalf("SaveIncident() error = %v", err)
	}
	list, total, err := store.ListIncidents(ctx, storage.IncidentFilter{Severity: string(events.SeverityMedium)})
	if err != nil {
		t.Fatalf("ListIncidents() error = %v", err)
	}
	if total != 1 || list[0].ID != "inc-2" {
		t.Errorf("severity filter returned %d items", total)
	}
	list, total, _ = store.ListIncidents(ctx, storage.IncidentFilter{MinRiskScore: 50})
	if total != 1 || list[0].ID != "inc-1" {
		t.Errorf("risk filter returned %d items", total)
	}
	list, _, _ = store.ListIncidents(ctx, storage.IncidentFilter{})
	if len(list) != 2 || list[0].ID != "inc-2" {
		t.Errorf("default ordering should be most recently active first, got %v", ids(list))
	}
	if err := store.SaveIncident(ctx, &incidents.Incident{}); err == nil {
		t.Error("SaveIncident() accepted an incident with no id")
	}
}

func testActions(t *testing.T, store storage.Store) {
	ctx := context.Background()
	if err := store.SaveIncident(ctx, sampleIncident("inc-1", 81, events.SeverityCritical, at)); err != nil {
		t.Fatalf("SaveIncident() error = %v", err)
	}
	action := &incidents.ResponseAction{
		ID: "act-1", IncidentID: "inc-1", ActionType: "preserve_evidence",
		Mode: incidents.ModeSimulate, Status: incidents.ActionSimulated,
		RequestedBy: "analyst", CreatedAt: at, Reversible: true,
		RollbackAction: "release_evidence_hold",
		PolicyDecision: &incidents.PolicyDecision{
			Effect: "allow", Allow: true, Reasons: []string{"corroborated"},
			PolicyPackage: "griefer.response", PolicyVersion: "0.1.0", EvaluatedAt: at,
		},
		Simulated: &incidents.SimulatedEffect{
			Description: "would hold evidence", AffectedEntities: []string{"identity:u-1"},
			RollbackPlan: "release_evidence_hold",
		},
	}
	if err := store.SaveAction(ctx, action); err != nil {
		t.Fatalf("SaveAction() error = %v", err)
	}
	got, err := store.GetAction(ctx, "act-1")
	if err != nil {
		t.Fatalf("GetAction() error = %v", err)
	}
	if got.PolicyDecision == nil || got.PolicyDecision.Effect != "allow" {
		t.Error("the policy decision must survive the round trip; it is the audit record of why")
	}
	if got.Simulated == nil || len(got.Simulated.AffectedEntities) != 1 {
		t.Error("the simulated effect was lost")
	}
	if _, err := store.GetAction(ctx, "act-missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("GetAction() error = %v, want ErrNotFound", err)
	}

	list, total, err := store.ListActions(ctx, "inc-1", 10, 0)
	if err != nil || total != 1 || len(list) != 1 {
		t.Fatalf("ListActions() = %d/%d, %v", len(list), total, err)
	}
	_, total, _ = store.ListActions(ctx, "inc-other", 10, 0)
	if total != 0 {
		t.Errorf("ListActions() for another incident returned %d", total)
	}
}

func testAudit(t *testing.T, store storage.Store) {
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		entry := &audit.Entry{
			ID: fmt.Sprintf("aud-%d", i), Timestamp: at.Add(time.Duration(i) * time.Second),
			Actor: "system:griefer", Action: audit.ActionPolicyEvaluated,
			SubjectType: audit.SubjectAction, SubjectID: fmt.Sprintf("act-%d", i),
			Outcome: audit.OutcomeSuccess, Reason: "because",
			Details: map[string]any{"effect": "allow", "index": float64(i)},
		}
		if err := store.Append(ctx, entry); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
		if entry.Sequence == 0 {
			t.Error("Append() did not assign a sequence number")
		}
	}
	got, total, err := store.List(ctx, 10, 0)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 3 || len(got) != 3 {
		t.Fatalf("List() = %d/%d, want 3/3", len(got), total)
	}
	// Oldest first: the trail should read as a narrative.
	for i := 1; i < len(got); i++ {
		if got[i].Sequence <= got[i-1].Sequence {
			t.Errorf("sequence is not increasing: %d then %d", got[i-1].Sequence, got[i].Sequence)
		}
	}
	if got[0].Details["effect"] != "allow" {
		t.Errorf("audit details were lost: %+v", got[0].Details)
	}
	if err := store.Append(ctx, &audit.Entry{}); err == nil {
		t.Error("Append() accepted an entry with no id")
	}
}

func testPagination(t *testing.T, store storage.Store) {
	ctx := context.Background()
	for i := 0; i < 30; i++ {
		if err := store.SaveIncident(ctx, sampleIncident(
			fmt.Sprintf("inc-%02d", i), i, events.SeverityLow, at.Add(time.Duration(i)*time.Minute),
		)); err != nil {
			t.Fatalf("SaveIncident() error = %v", err)
		}
	}
	page1, total, err := store.ListIncidents(ctx, storage.IncidentFilter{Limit: 10, Offset: 0})
	if err != nil {
		t.Fatalf("ListIncidents() error = %v", err)
	}
	if total != 30 || len(page1) != 10 {
		t.Fatalf("page 1 = %d items, total %d", len(page1), total)
	}
	page2, _, _ := store.ListIncidents(ctx, storage.IncidentFilter{Limit: 10, Offset: 10})
	seen := map[string]bool{}
	for _, inc := range append(append([]*incidents.Incident{}, page1...), page2...) {
		if seen[inc.ID] {
			t.Errorf("incident %s appeared on two pages", inc.ID)
		}
		seen[inc.ID] = true
	}
	beyond, _, _ := store.ListIncidents(ctx, storage.IncidentFilter{Limit: 10, Offset: 1000})
	if len(beyond) != 0 {
		t.Errorf("offset past the end returned %d items, want 0", len(beyond))
	}
	// An unbounded page size is a denial-of-service primitive.
	huge, _, _ := store.ListIncidents(ctx, storage.IncidentFilter{Limit: 100000})
	if len(huge) > storage.MaxPageSize {
		t.Errorf("returned %d items, want at most %d", len(huge), storage.MaxPageSize)
	}
	negative, _, _ := store.ListIncidents(ctx, storage.IncidentFilter{Limit: -5, Offset: -5})
	if len(negative) == 0 || len(negative) > storage.DefaultPageSize {
		t.Errorf("negative pagination produced %d items", len(negative))
	}
}

func TestClampLimit(t *testing.T) {
	tests := []struct{ in, want int }{
		{0, storage.DefaultPageSize},
		{-1, storage.DefaultPageSize},
		{10, 10},
		{storage.MaxPageSize, storage.MaxPageSize},
		{storage.MaxPageSize + 1, storage.MaxPageSize},
		{1 << 30, storage.MaxPageSize},
	}
	for _, tt := range tests {
		if got := storage.ClampLimit(tt.in); got != tt.want {
			t.Errorf("ClampLimit(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestMemoryStoreBoundsEventRetention(t *testing.T) {
	store := storage.NewMemoryStore(5)
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		if _, err := store.SaveEvent(ctx, &events.SecurityEvent{
			ID: fmt.Sprintf("evt-%02d", i), Timestamp: at, Category: events.CategoryAuthentication,
		}); err != nil {
			t.Fatalf("SaveEvent() error = %v", err)
		}
	}
	count, err := store.CountEvents(ctx)
	if err != nil {
		t.Fatalf("CountEvents() error = %v", err)
	}
	if count != 5 {
		t.Errorf("retained %d events, want the 5-event cap; unbounded growth is an availability bug", count)
	}
}

func ids(list []*incidents.Incident) []string {
	out := make([]string, 0, len(list))
	for _, inc := range list {
		out = append(out, inc.ID)
	}
	return out
}

// TestTheMemoryStoreBoundsIncidentsAndActions.
//
// Events had a bound and nothing else did, while this store is the DEFAULT:
// GRIEFER_STORAGE_POSTGRES is false unless set. Correlation opens an incident
// per subject and the subject is producer-chosen, so both maps grew with
// distinct subjects and nothing removed from either.
//
// The audit log is deliberately still unbounded here — see the comment on
// MemoryStore. Evicting its oldest entries would leave the chain naming a
// predecessor that is gone, which verify reports as a deleted prefix and cannot
// tell apart from the attack it exists to catch.
func TestTheMemoryStoreBoundsIncidentsAndActions(t *testing.T) {
	const limit = 20
	store := storage.NewMemoryStore(limit)
	ctx := context.Background()

	for i := 0; i < limit*3; i++ {
		inc := sampleIncident(fmt.Sprintf("inc-%04d", i), 10, events.SeverityLow, at)
		if err := store.SaveIncident(ctx, inc); err != nil {
			t.Fatalf("SaveIncident(%d) error = %v", i, err)
		}
		action := &incidents.ResponseAction{
			ID: fmt.Sprintf("act-%04d", i), IncidentID: inc.ID, ActionType: "preserve_evidence",
			Mode: incidents.ModeSimulate, Status: incidents.ActionSimulated,
			RequestedBy: "system:griefer", CreatedAt: at,
		}
		if err := store.SaveAction(ctx, action); err != nil {
			t.Fatalf("SaveAction(%d) error = %v", i, err)
		}
	}

	_, incidentTotal, err := store.ListIncidents(ctx, storage.IncidentFilter{Limit: storage.MaxPageSize})
	if err != nil {
		t.Fatalf("ListIncidents() error = %v", err)
	}
	if incidentTotal > limit {
		t.Errorf("store holds %d incidents, above the bound of %d", incidentTotal, limit)
	}

	_, actionTotal, err := store.ListActions(ctx, "", storage.MaxPageSize, 0)
	if err != nil {
		t.Fatalf("ListActions() error = %v", err)
	}
	if actionTotal > limit {
		t.Errorf("store holds %d actions, above the bound of %d", actionTotal, limit)
	}

	// Oldest-first, like events: the most recent record is the one kept.
	if _, err := store.GetIncident(ctx, fmt.Sprintf("inc-%04d", limit*3-1)); err != nil {
		t.Errorf("the most recent incident was evicted: %v", err)
	}
}
