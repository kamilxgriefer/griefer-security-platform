package integration_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/api"
	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/graph"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
	"github.com/kamilxgriefer/griefer-security-platform/internal/policy"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
)

// TestFullPipeline follows one synthetic scenario through every stage:
//
//	event -> validation -> storage -> finding -> correlation -> incident
//	      -> risk score -> policy evaluation -> audit entry -> API response
func TestFullPipeline(t *testing.T) {
	s := newStack(t, stackOptions{})
	ctx := context.Background()

	inc := s.replayScenario()

	t.Run("every event was validated, normalized and stored", func(t *testing.T) {
		stored, total, err := s.store.ListEvents(ctx, 50, 0)
		if err != nil {
			t.Fatalf("ListEvents() error = %v", err)
		}
		if total != 5 {
			t.Fatalf("stored %d events, want 5", total)
		}
		for _, ev := range stored {
			if ev.ReceivedAt.IsZero() {
				t.Error("an event was stored without a server-assigned receipt time")
			}
			if ev.Timestamp.Location() != time.UTC {
				t.Errorf("event %s timestamp is not UTC", ev.ID)
			}
			if ev.CorrelationID == "" {
				t.Errorf("event %s has no correlation id", ev.ID)
			}
		}
	})

	t.Run("findings were produced and correlated into one incident", func(t *testing.T) {
		if len(inc.Findings) != 5 {
			t.Fatalf("Findings = %d, want 5", len(inc.Findings))
		}
		rules := map[string]bool{}
		for _, f := range inc.Findings {
			rules[f.RuleID] = true
			if f.Title == "" || f.Category == "" {
				t.Errorf("finding %s is incomplete", f.ID)
			}
		}
		for _, want := range []string{"GRF-CORR-0001", "GRF-CORR-0002", "GRF-CORR-0003", "GRF-CORR-0004", "GRF-CORR-0005"} {
			if !rules[want] {
				t.Errorf("rule %s did not fire", want)
			}
		}
		if got := len(inc.EvidenceCategories()); got != 5 {
			t.Errorf("EvidenceCategories = %d, want 5 independent categories", got)
		}
	})

	t.Run("risk, severity and confidence reflect the accumulated evidence", func(t *testing.T) {
		if inc.RiskScore < 70 {
			t.Errorf("RiskScore = %d, want at least 70 for a five-category chain reaching a critical asset", inc.RiskScore)
		}
		if inc.Severity != events.SeverityCritical {
			t.Errorf("Severity = %q, want critical", inc.Severity)
		}
		if inc.Confidence <= 0 || inc.Confidence > 0.95 {
			t.Errorf("Confidence = %v, want 0 < c <= 0.95", inc.Confidence)
		}
	})

	t.Run("the Security Graph links the entities and estimates a blast radius", func(t *testing.T) {
		byID := map[string]incidents.EntityRef{}
		for _, e := range inc.Entities {
			byID[e.ID] = e
		}
		for _, want := range []string{
			"identity:u-1042", "endpoint:wks-4471", "session:sess-9f2c4d18",
			"ip_address:203.0.113.77", "secret:sec-billing-api-key",
			"cloud_resource:arn:aws:s3:::halberd-finance-archive",
		} {
			if _, ok := byID[want]; !ok {
				t.Errorf("entity %q is missing from the incident", want)
			}
		}
		if byID["secret:sec-billing-api-key"].Criticality != graph.CriticalityCritical {
			t.Error("the secret's criticality from the asset inventory was lost")
		}
		if inc.BlastRadius.Score == 0 {
			t.Error("no blast radius was estimated")
		}
		if inc.BlastRadius.CriticalAssets < 2 {
			t.Errorf("CriticalAssets = %d, want at least 2", inc.BlastRadius.CriticalAssets)
		}
		if inc.BlastRadius.Summary == "" {
			t.Error("blast radius has no readable summary")
		}
		// The baseline inventory is what lets the estimate answer "what does
		// this unlock", not merely "what was touched".
		reached := map[string]bool{}
		for _, r := range inc.BlastRadius.Reachable {
			reached[r.ID] = true
		}
		if !reached["service:svc-payments-api"] {
			t.Error("blast radius did not traverse the baseline inventory to the payments service")
		}
	})

	t.Run("ATT&CK techniques are annotated", func(t *testing.T) {
		ids := map[string]bool{}
		for _, tech := range inc.AttackTechniques {
			ids[tech.ID] = true
			if tech.Name == "" {
				t.Errorf("technique %s has no name", tech.ID)
			}
		}
		for _, want := range []string{"T1078", "T1098", "T1530", "T1552.001"} {
			if !ids[want] {
				t.Errorf("technique %s is missing", want)
			}
		}
	})

	t.Run("recommended actions carry honest safety metadata", func(t *testing.T) {
		if len(inc.RecommendedActions) == 0 {
			t.Fatal("no actions were recommended")
		}
		for _, a := range inc.RecommendedActions {
			if a.Destructive {
				t.Errorf("destructive action %q was recommended", a.ActionType)
			}
			if a.Reversible && a.RollbackAction == "" {
				t.Errorf("action %q claims reversibility with no rollback", a.ActionType)
			}
			if a.Rationale == "" {
				t.Errorf("action %q has no rationale", a.ActionType)
			}
		}
	})

	t.Run("policy evaluation produces a decision and an audit entry", func(t *testing.T) {
		resp, action, raw := s.evaluate(inc.ID, "preserve_evidence", "simulate", true)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
		}
		if action.Status != incidents.ActionSimulated {
			t.Fatalf("Status = %q, want simulated", action.Status)
		}
		if action.PolicyDecision == nil || action.PolicyDecision.PolicyVersion == "" {
			t.Fatal("the action does not record which policy decided it")
		}
		if action.Simulated == nil {
			t.Fatal("no simulated effect was produced")
		}

		found := false
		for _, e := range s.auditEntries() {
			if e.Action == audit.ActionPolicyEvaluated && e.SubjectID == action.ID {
				found = true
				if e.Reason == "" {
					t.Error("the audit entry records no reason")
				}
				if e.Details["effect"] != "allow" {
					t.Errorf("audit details effect = %v, want allow", e.Details["effect"])
				}
			}
		}
		if !found {
			t.Error("no audit entry was written for the policy decision")
		}
	})

	t.Run("the API serves the whole incident", func(t *testing.T) {
		resp, body := s.get("/api/v1/incidents/" + inc.ID)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		var served incidents.Incident
		s.decode(body, &served)
		if served.ID != inc.ID || served.RiskScore != inc.RiskScore {
			t.Error("the served incident does not match the stored one")
		}
		if served.SchemaVersion != incidents.SchemaVersion {
			t.Errorf("SchemaVersion = %q", served.SchemaVersion)
		}
	})
}

func TestRiskScoreRisesMonotonicallyAcrossTheScenario(t *testing.T) {
	s := newStack(t, stackOptions{})

	scores := []int{}
	actor := "u-9001"
	steps := []struct{ eventType, category, severity, extra string }{
		{"user_signin", "authentication", "medium", `"network":{"source_ip":"203.0.113.90","first_seen_for_actor":true}`},
		{"session_created", "session_anomaly", "medium", `"actor":{"type":"identity","id":"u-9001","privileged":true,"session_id":"sess-9001"}`},
		{"role_assignment_changed", "privilege_escalation", "high", ""},
		{"secret_accessed", "credential_access", "high", `"target":{"type":"secret","id":"sec-billing-api-key","criticality":"critical"}`},
	}
	for i, step := range steps {
		body := eventAt(step.eventType, step.category, step.severity, actor, step.extra)
		resp, raw := s.post("/api/v1/events", body)
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("step %d: status = %d, body = %s", i+1, resp.StatusCode, raw)
		}
		var result api.IngestResult
		s.decode(raw, &result)
		scores = append(scores, result.RiskScore)
	}
	for i := 1; i < len(scores); i++ {
		if scores[i] < scores[i-1] {
			t.Fatalf("risk score fell from %d to %d at step %d; a falling score during an active attack destroys trust in the number",
				scores[i-1], scores[i], i+1)
		}
	}
	if scores[len(scores)-1] <= scores[0] {
		t.Errorf("risk did not rise across the chain: %v", scores)
	}
}

// failingCorrelator stands in for a correlation engine that has fallen over.
type failingCorrelator struct{}

func (failingCorrelator) Process(context.Context, *events.SecurityEvent) (*incidents.Incident, error) {
	return nil, errors.New("simulated correlation engine failure")
}

// panickingCorrelator stands in for a detection rule that crashes.
type panickingCorrelator struct{}

func (panickingCorrelator) Process(context.Context, *events.SecurityEvent) (*incidents.Incident, error) {
	panic("simulated panic inside a detection rule")
}

func TestTelemetryCaptureSurvivesADegradedCorrelationEngine(t *testing.T) {
	// Safety requirement: an attacker who can break the reasoning path must not
	// thereby stop GRIEFER from recording what they did.
	for name, correlator := range map[string]api.Correlator{
		"correlation returns an error": failingCorrelator{},
		"a detection rule panics":      panickingCorrelator{},
	} {
		t.Run(name, func(t *testing.T) {
			s := newStack(t, stackOptions{correlator: correlator})

			resp, raw := s.post("/api/v1/events", eventAt("user_signin", "authentication", "medium", "u-1042",
				`"network":{"source_ip":"203.0.113.77","first_seen_for_actor":true}`))
			if resp.StatusCode != http.StatusAccepted {
				t.Fatalf("status = %d, want 202; ingestion must not fail with correlation", resp.StatusCode)
			}
			var result api.IngestResult
			s.decode(raw, &result)
			if result.EventID == "" {
				t.Fatal("no event id was returned")
			}
			if result.IncidentID != "" {
				t.Error("an incident was reported despite a broken correlator")
			}
			degraded := false
			for _, d := range result.Degraded {
				if d == "correlation" {
					degraded = true
				}
			}
			if !degraded {
				t.Errorf("Degraded = %v, want it to name correlation; silent degradation is worse than none", result.Degraded)
			}

			// The point of the requirement: the event is durably stored.
			stored, total, err := s.store.ListEvents(context.Background(), 10, 0)
			if err != nil {
				t.Fatalf("ListEvents() error = %v", err)
			}
			if total != 1 || stored[0].ID != result.EventID {
				t.Fatalf("the event was not persisted: total=%d", total)
			}

			// And the failure is itself recorded.
			foundFailure := false
			for _, e := range s.auditEntries() {
				if e.Action == audit.ActionCorrelationFailed {
					foundFailure = true
				}
			}
			if !foundFailure {
				t.Error("no audit entry recorded the correlation failure")
			}
		})
	}
}

func TestBatchIngestFollowsTheSamePipeline(t *testing.T) {
	s := newStack(t, stackOptions{maxBatchEvents: 10})

	body := `{"events":[` +
		eventAt("user_signin", "authentication", "medium", "u-7000", `"network":{"source_ip":"203.0.113.70","first_seen_for_actor":true}`) + `,` +
		eventAt("role_assignment_changed", "privilege_escalation", "high", "u-7000", "") +
		`]}`

	resp, raw := s.post("/api/v1/events/batch", body)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
	}
	var out api.BatchResponse
	s.decode(raw, &out)
	if out.Accepted != 2 {
		t.Fatalf("accepted = %d, want 2", out.Accepted)
	}

	list, total, err := s.store.ListIncidents(context.Background(), storage.IncidentFilter{})
	if err != nil {
		t.Fatalf("ListIncidents() error = %v", err)
	}
	if total != 1 {
		t.Fatalf("total incidents = %d, want 1; both events share one identity", total)
	}
	if len(list[0].EvidenceCategories()) != 2 {
		t.Errorf("EvidenceCategories = %v, want two", list[0].EvidenceCategories())
	}
}

func TestFailClosedKernelIsReportedButDoesNotBreakIngestion(t *testing.T) {
	s := newStack(t, stackOptions{kernel: unreachableKernel{}})

	// Ingestion is unaffected by a dead Policy Kernel.
	resp, raw := s.post("/api/v1/events", eventAt("user_signin", "authentication", "medium", "u-1042",
		`"network":{"source_ip":"203.0.113.77","first_seen_for_actor":true}`))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("ingest status = %d, want 202", resp.StatusCode)
	}
	var result api.IngestResult
	s.decode(raw, &result)

	// But every response action is denied, and the degradation is visible.
	resp, action, body := s.evaluate(result.IncidentID, "preserve_evidence", "simulate", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("evaluate status = %d, body = %s", resp.StatusCode, body)
	}
	if action.Status != incidents.ActionDenied {
		t.Fatalf("Status = %q, want denied", action.Status)
	}
	if !action.PolicyDecision.FailClosed {
		t.Error("the decision does not record that it came from the fail-closed path")
	}
	if resp.Header.Get("X-Griefer-Policy-Degraded") != "true" {
		t.Error("no degradation header; an operator cannot spot a broken kernel without parsing bodies")
	}
	if !strings.Contains(strings.ToLower(action.Reason), "fails closed") {
		t.Errorf("Reason = %q, want it to explain the fail-closed denial", action.Reason)
	}
}

type unreachableKernel struct{}

func (unreachableKernel) Evaluate(context.Context, policy.Input) (incidents.PolicyDecision, error) {
	return incidents.PolicyDecision{
		Effect: policy.EffectDeny, Allow: false, FailClosed: true,
		Engine: policy.EngineUnavailable, EvaluatedAt: time.Now().UTC(),
		PolicyPackage: "griefer.response", PolicyVersion: "0.1.0",
		Reasons: []string{"Policy Kernel is unreachable; GRIEFER fails closed and denies the action."},
	}, errors.New("connection refused")
}
func (unreachableKernel) Health(context.Context) error { return errors.New("connection refused") }
func (unreachableKernel) Engine() string               { return policy.EngineUnavailable }
func (unreachableKernel) Close() error                 { return nil }
