package api_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/api"
	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/graph"
	"github.com/kamilxgriefer/griefer-security-platform/internal/httpx"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
	"github.com/kamilxgriefer/griefer-security-platform/internal/policy"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
)

func validEventJSON(actorID string) string {
	return fmt.Sprintf(`{
		"schema_version":"0.1",
		"timestamp":%q,
		"source_type":"identity_provider",
		"source_name":"test-harness",
		"event_type":"user_signin",
		"category":"authentication",
		"severity":"medium",
		"actor":{"type":"identity","id":%q},
		"network":{"source_ip":"203.0.113.77","first_seen_for_actor":true}
	}`, time.Now().UTC().Format(time.RFC3339), actorID)
}

func TestHealthAndReadiness(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	t.Run("health is a liveness probe and checks no dependency", func(t *testing.T) {
		resp := h.do(http.MethodGet, "/health", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body map[string]any
		h.decode(resp, &body)
		if body["status"] != "ok" {
			t.Errorf("status = %v, want ok", body["status"])
		}
	})

	t.Run("readiness reports every dependency and the simulation-only mode", func(t *testing.T) {
		resp := h.do(http.MethodGet, "/ready", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body api.ReadinessResponse
		h.decode(resp, &body)
		if body.Status != "ready" {
			t.Errorf("status = %q, want ready", body.Status)
		}
		if !body.SimulationOnly || body.ResponseMode != "simulate" {
			t.Error("readiness must state that responses are simulated; a console cannot show GRIEFER without it")
		}
		names := map[string]bool{}
		for _, c := range body.Components {
			names[c.Name] = true
		}
		for _, want := range []string{"storage", "policy_kernel", "event_bus"} {
			if !names[want] {
				t.Errorf("component %q is not reported", want)
			}
		}
	})
}

func TestReadinessIsDegradedWhenThePolicyKernelIsDown(t *testing.T) {
	h := newHarness(t, harnessOptions{kernel: deadKernel{}})
	resp := h.do(http.MethodGet, "/ready", "")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when policy cannot be evaluated", resp.StatusCode)
	}
	var body api.ReadinessResponse
	h.decode(resp, &body)
	if body.Status != "degraded" {
		t.Errorf("status = %q, want degraded", body.Status)
	}
}

func TestMetricsEndpointExposesGrieferCollectors(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	inc := h.seedScenario()
	// Label-bearing counters only appear once they have been observed, so the
	// test exercises each path before scraping.
	h.do(http.MethodPost, "/api/v1/actions/evaluate",
		fmt.Sprintf(`{"incident_id":%q,"action_type":"preserve_evidence"}`, inc.ID))

	resp := h.do(http.MethodGet, "/metrics", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := h.body(resp)
	for _, want := range []string{
		"griefer_events_ingested_total",
		"griefer_http_requests_total",
		"griefer_policy_decisions_total",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output is missing %q", want)
		}
	}
}

func TestIngestAcceptsAValidEvent(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	resp := h.do(http.MethodPost, "/api/v1/events", validEventJSON("u-1042"))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	var result api.IngestResult
	h.decode(resp, &result)
	if result.EventID == "" {
		t.Error("no event id was returned")
	}
	if result.IncidentID == "" {
		t.Error("a matching rule should have produced an incident")
	}
	if resp.Header.Get(httpx.RequestIDHeader) == "" {
		t.Error("no request id header on the response")
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
}

func TestIngestRejectsBadRequests(t *testing.T) {
	h := newHarness(t, harnessOptions{maxRequestSize: 2048})

	tests := []struct {
		name     string
		body     string
		wantCode int
		wantErr  string
	}{
		{"empty body", "", http.StatusBadRequest, httpx.CodeMalformedRequest},
		{"not JSON", "definitely not json", http.StatusBadRequest, httpx.CodeValidationFailed},
		{"missing required fields", `{"schema_version":"0.1"}`, http.StatusBadRequest, httpx.CodeValidationFailed},
		{
			name:     "unknown field",
			body:     `{"schema_version":"0.1","timestamp":"2026-08-23T09:00:00Z","source_type":"application","source_name":"x","event_type":"y","category":"authentication","severity":"low","run_command":"whoami"}`,
			wantCode: http.StatusBadRequest, wantErr: httpx.CodeValidationFailed,
		},
		{
			name:     "oversize body",
			body:     `{"schema_version":"0.1","source_name":"` + strings.Repeat("A", 4096) + `"}`,
			wantCode: http.StatusRequestEntityTooLarge, wantErr: httpx.CodePayloadTooLarge,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := h.do(http.MethodPost, "/api/v1/events", tt.body)
			if resp.StatusCode != tt.wantCode {
				t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, tt.wantCode, h.body(resp))
			}
			var body httpx.ErrorResponse
			h.decode(resp, &body)
			if body.Error.Code != tt.wantErr {
				t.Errorf("error code = %q, want %q", body.Error.Code, tt.wantErr)
			}
			if body.Error.RequestID == "" {
				t.Error("error response has no request id")
			}
			for _, leak := range []string{"/Users/", "goroutine", "griefer-security-platform/internal"} {
				if strings.Contains(h.body(resp), leak) {
					t.Errorf("error response leaks internals: %q", leak)
				}
			}
		})
	}
}

func TestIngestRejectsNonJSONContentType(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		h.Server.URL+"/api/v1/events", strings.NewReader(validEventJSON("u-1")))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.Server.Client().Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", resp.StatusCode)
	}
}

func TestBatchIngest(t *testing.T) {
	h := newHarness(t, harnessOptions{maxBatchEvents: 3})

	t.Run("all valid returns 202", func(t *testing.T) {
		body := fmt.Sprintf(`{"events":[%s,%s]}`, validEventJSON("u-a"), validEventJSON("u-b"))
		resp := h.do(http.MethodPost, "/api/v1/events/batch", body)
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", resp.StatusCode)
		}
		var out api.BatchResponse
		h.decode(resp, &out)
		if out.Accepted != 2 || out.Rejected != 0 {
			t.Errorf("accepted=%d rejected=%d, want 2/0", out.Accepted, out.Rejected)
		}
	})

	t.Run("partial success returns 207 and reports both halves", func(t *testing.T) {
		body := fmt.Sprintf(`{"events":[%s,{"schema_version":"0.1"}]}`, validEventJSON("u-c"))
		resp := h.do(http.MethodPost, "/api/v1/events/batch", body)
		if resp.StatusCode != http.StatusMultiStatus {
			t.Fatalf("status = %d, want 207; 202 would hide the rejects and 400 would hide the accepts", resp.StatusCode)
		}
		var out api.BatchResponse
		h.decode(resp, &out)
		if out.Accepted != 1 || out.Rejected != 1 {
			t.Errorf("accepted=%d rejected=%d, want 1/1", out.Accepted, out.Rejected)
		}
		if out.Results[1].Error == nil {
			t.Error("the rejected item carries no error detail")
		}
	})

	t.Run("all invalid returns 400", func(t *testing.T) {
		resp := h.do(http.MethodPost, "/api/v1/events/batch", `{"events":[{"a":1},{"b":2}]}`)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("empty batch is rejected", func(t *testing.T) {
		resp := h.do(http.MethodPost, "/api/v1/events/batch", `{"events":[]}`)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("too many events is rejected before any are processed", func(t *testing.T) {
		body := fmt.Sprintf(`{"events":[%s,%s,%s,%s]}`,
			validEventJSON("u-1"), validEventJSON("u-2"), validEventJSON("u-3"), validEventJSON("u-4"))
		resp := h.do(http.MethodPost, "/api/v1/events/batch", body)
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, want 413; a small body can still hold thousands of tiny events", resp.StatusCode)
		}
	})
}

func TestIncidentEndpoints(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	inc := h.seedScenario()

	t.Run("list", func(t *testing.T) {
		resp := h.do(http.MethodGet, "/api/v1/incidents", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var page httpx.Page[*incidents.Incident]
		h.decode(resp, &page)
		if page.Total != 1 || len(page.Items) != 1 {
			t.Fatalf("total=%d items=%d, want 1/1", page.Total, len(page.Items))
		}
		if page.Limit != storage.DefaultPageSize {
			t.Errorf("Limit = %d, want the default page size", page.Limit)
		}
	})

	t.Run("get by id", func(t *testing.T) {
		resp := h.do(http.MethodGet, "/api/v1/incidents/"+inc.ID, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var got incidents.Incident
		h.decode(resp, &got)
		if got.ID != inc.ID || len(got.Findings) != 5 {
			t.Errorf("got %s with %d findings, want %s with 5", got.ID, len(got.Findings), inc.ID)
		}
		if len(got.RecommendedActions) == 0 || len(got.AttackTechniques) == 0 {
			t.Error("the incident is missing recommended actions or techniques")
		}
	})

	t.Run("unknown id is 404", func(t *testing.T) {
		resp := h.do(http.MethodGet, "/api/v1/incidents/inc-does-not-exist", "")
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d, want 404", resp.StatusCode)
		}
	})

	t.Run("filters are validated", func(t *testing.T) {
		for _, query := range []string{"?status=exploded", "?severity=apocalyptic", "?min_risk_score=500", "?min_risk_score=abc"} {
			resp := h.do(http.MethodGet, "/api/v1/incidents"+query, "")
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", query, resp.StatusCode)
			}
		}
	})

	t.Run("valid filters work", func(t *testing.T) {
		resp := h.do(http.MethodGet, "/api/v1/incidents?status=open&severity=critical&min_risk_score=50", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var page httpx.Page[*incidents.Incident]
		h.decode(resp, &page)
		if page.Total != 1 {
			t.Errorf("total = %d, want 1", page.Total)
		}
	})
}

func TestEntityEndpoint(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.seedScenario()

	resp := h.do(http.MethodGet, "/api/v1/entities/identity:u-1042", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, h.body(resp))
	}
	var got api.EntityResponse
	h.decode(resp, &got)
	if got.Entity.ID != "identity:u-1042" {
		t.Errorf("Entity.ID = %q", got.Entity.ID)
	}
	if len(got.Edges) == 0 {
		t.Error("no graph edges returned; the console needs them to draw context")
	}
	if got.BlastRadius.Score == 0 {
		t.Error("blast radius was not computed")
	}

	t.Run("unknown entity is 404", func(t *testing.T) {
		resp := h.do(http.MethodGet, "/api/v1/entities/identity:nobody", "")
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d, want 404", resp.StatusCode)
		}
	})
}

func TestActionEvaluationEndpoint(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	inc := h.seedScenario()

	t.Run("a corroborated safe action is simulated", func(t *testing.T) {
		body := fmt.Sprintf(`{"incident_id":%q,"action_type":"preserve_evidence","mode":"simulate","requested_by":"analyst:test","automated":true}`, inc.ID)
		resp := h.do(http.MethodPost, "/api/v1/actions/evaluate", body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, h.body(resp))
		}
		var action incidents.ResponseAction
		h.decode(resp, &action)
		if action.Status != incidents.ActionSimulated {
			t.Fatalf("Status = %q, want simulated", action.Status)
		}
		if action.Simulated == nil || action.Simulated.Description == "" {
			t.Fatal("no simulated effect was described")
		}
		if action.Simulated.RollbackPlan == "" {
			t.Error("no rollback plan was described")
		}
		if action.ExecutedAt != nil {
			t.Error("ExecutedAt is set; v0.1 must never execute anything")
		}

		got := h.do(http.MethodGet, "/api/v1/actions/"+action.ID, "")
		if got.StatusCode != http.StatusOK {
			t.Errorf("GET action status = %d, want 200", got.StatusCode)
		}
	})

	t.Run("the request cannot assert an action's safety properties", func(t *testing.T) {
		// A client that could claim "reversible": true would be able to talk
		// the Policy Kernel into anything.
		body := fmt.Sprintf(`{"incident_id":%q,"action_type":"revoke_sessions","reversible":true,"destructive":false}`, inc.ID)
		resp := h.do(http.MethodPost, "/api/v1/actions/evaluate", body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 for unknown request fields", resp.StatusCode)
		}
	})

	t.Run("missing required fields", func(t *testing.T) {
		for _, body := range []string{`{}`, `{"incident_id":"inc-1"}`, `{"action_type":"require_mfa"}`} {
			resp := h.do(http.MethodPost, "/api/v1/actions/evaluate", body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", body, resp.StatusCode)
			}
		}
	})

	t.Run("unknown incident is 404", func(t *testing.T) {
		resp := h.do(http.MethodPost, "/api/v1/actions/evaluate",
			`{"incident_id":"inc-nope","action_type":"require_mfa"}`)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d, want 404", resp.StatusCode)
		}
	})

	t.Run("unknown action id is 404", func(t *testing.T) {
		resp := h.do(http.MethodGet, "/api/v1/actions/act-nope", "")
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d, want 404", resp.StatusCode)
		}
	})
}

func TestAuditEndpointIsPaginatedAndOrdered(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.seedScenario()

	resp := h.do(http.MethodGet, "/api/v1/audit?limit=5", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var page httpx.Page[*audit.Entry]
	h.decode(resp, &page)
	if page.Total == 0 {
		t.Fatal("the audit trail is empty after a full scenario")
	}
	if len(page.Items) > 5 {
		t.Errorf("returned %d items for limit=5", len(page.Items))
	}
	for i := 1; i < len(page.Items); i++ {
		if page.Items[i].Sequence <= page.Items[i-1].Sequence {
			t.Error("audit entries are not in sequence order")
		}
	}
}

func TestUnknownRoutesReturnJSON(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	resp := h.do(http.MethodGet, "/api/v1/nope", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want JSON so a client has one error shape to parse", ct)
	}
	var body httpx.ErrorResponse
	h.decode(resp, &body)
	if body.Error.Code != httpx.CodeNotFound {
		t.Errorf("code = %q", body.Error.Code)
	}
}

func TestWriteEndpointsAreRateLimited(t *testing.T) {
	h := newHarness(t, harnessOptions{rateLimitRPS: 1, rateLimitBurst: 2})

	var limited bool
	for i := 0; i < 6; i++ {
		resp := h.do(http.MethodPost, "/api/v1/events", validEventJSON("u-rl"))
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
		}
	}
	if !limited {
		t.Error("write endpoints were never rate limited")
	}

	// Read endpoints stay available: an analyst refreshing a console during an
	// incident must not be throttled out of the investigation.
	for i := 0; i < 20; i++ {
		resp := h.do(http.MethodGet, "/api/v1/incidents", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("read request %d = %d, want 200", i, resp.StatusCode)
		}
	}
}

func TestSystemStatusReportsPipelineCounters(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.seedScenario()

	resp := h.do(http.MethodGet, "/api/v1/system/status", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body api.SystemStatus
	h.decode(resp, &body)
	if body.Events != 5 {
		t.Errorf("Events = %d, want 5", body.Events)
	}
	if body.Incidents != 1 {
		t.Errorf("Incidents = %d, want 1", body.Incidents)
	}
	if body.Entities == 0 || body.Edges == 0 {
		t.Error("graph counters are empty")
	}
	if body.Rules == 0 {
		t.Error("rule count is zero; an operator cannot tell a ruleless deployment from a healthy one")
	}
	if !body.SimulationOnly {
		t.Error("SimulationOnly must be true in v0.1")
	}
}

func TestNewServiceRejectsIncompleteWiring(t *testing.T) {
	tests := []struct {
		name string
		opts api.ServiceOptions
	}{
		{"no store", api.ServiceOptions{}},
		{"no graph", api.ServiceOptions{Store: storage.NewMemoryStore(0)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := api.NewService(tt.opts); err == nil {
				t.Error("NewService() accepted incomplete wiring")
			}
		})
	}
}

// --- test doubles -----------------------------------------------------------

type deadKernel struct{}

func (deadKernel) Evaluate(context.Context, policy.Input) (incidents.PolicyDecision, error) {
	return incidents.PolicyDecision{
		Effect: policy.EffectDeny, Allow: false, FailClosed: true,
		Engine: policy.EngineUnavailable, EvaluatedAt: time.Now().UTC(),
		Reasons: []string{"Policy Kernel is unreachable; GRIEFER fails closed and denies the action."},
	}, errors.New("policy kernel unreachable")
}
func (deadKernel) Health(context.Context) error { return errors.New("policy kernel unreachable") }
func (deadKernel) Engine() string               { return policy.EngineUnavailable }
func (deadKernel) Close() error                 { return nil }

var _ = events.SeverityLow
var _ = graph.TypeIdentity
