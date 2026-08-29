package api_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kamilxgriefer/griefer-security-platform/internal/api"
	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/httpx"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
)

const (
	prodToken = "test-internal-token-9f3c1a"
	oktaKey   = "3f9a1c77b0e24d5e8a6c1f0b9d2e4a67c5b8e1d0"
	edrKey    = "aa11bb22cc33dd44ee55ff6677889900aabbccdd"
)

// producerHarness serves the real router with a keyring enrolled.
type producerHarness struct {
	*harness
	server *httptest.Server
}

func newProducerHarness(t *testing.T) *producerHarness {
	t.Helper()
	inner := newHarness(t, harnessOptions{skipInventory: true})
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	handler := api.NewRouter(inner.Service, api.RouterOptions{
		MaxRequestBytes: 1 << 20, RateLimitRPS: 10000, RateLimitBurst: 10000,
		Logger: logger, InternalAPIToken: prodToken,
		Producers: []httpx.ProducerCredential{
			{Name: "okta-prod", Key: oktaKey, Sources: []httpx.SourceRef{
				{Type: "identity_provider", Name: "okta-prod"}}},
			{Name: "edr-fleet", Key: edrKey, Sources: []httpx.SourceRef{
				{Type: "endpoint_agent", Name: "edr-fleet"}}},
		},
	})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &producerHarness{harness: inner, server: server}
}

func (h *producerHarness) ingest(t *testing.T, producer, key, sourceType, sourceName, eventType, category string) *http.Response {
	t.Helper()
	body := `{"schema_version":"0.1","timestamp":"2026-08-27T18:00:00Z",` +
		`"source_type":"` + sourceType + `","source_name":"` + sourceName + `",` +
		`"event_type":"` + eventType + `","category":"` + category + `","severity":"high",` +
		`"actor":{"type":"identity","id":"victim@lab.example"},` +
		`"network":{"source_ip":"203.0.113.7","first_seen_for_actor":true}}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		h.server.URL+"/api/v1/events", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+prodToken)
	if producer != "" {
		req.Header.Set(httpx.HeaderProducer, producer)
	}
	if key != "" {
		req.Header.Set(httpx.HeaderProducerKey, key)
	}
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST events: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (h *producerHarness) audit(t *testing.T) []*audit.Entry {
	t.Helper()
	entries, _, err := h.Store.List(context.Background(), storage.MaxPageSize, 0)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	return entries
}

// TestAnEnrolledDeploymentRefusesUnattributedTelemetry.
//
// Once ONE producer is enrolled the boundary is on for all of them. An opt-in
// per producer would mean an unenrolled sender simply omits the header, which
// is not a boundary.
func TestAnEnrolledDeploymentRefusesUnattributedTelemetry(t *testing.T) {
	h := newProducerHarness(t)
	resp := h.ingest(t, "", "", "identity_provider", "okta-prod", "user_signin", "authentication")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for telemetry with no producer credential", resp.StatusCode)
	}
}

// TestAProducerCannotClaimASourceItIsNotEntitledTo.
//
// This is the control that closes T1's hole, and it is the entitlement rather
// than the credential doing the work. An authenticated producer free to claim
// any source_name would leave the corroboration gate exactly as satisfiable
// from one credential as before — the sender would just need a credential
// first.
func TestAProducerCannotClaimASourceItIsNotEntitledTo(t *testing.T) {
	h := newProducerHarness(t)

	// Its own pair: accepted.
	if resp := h.ingest(t, "okta-prod", oktaKey, "identity_provider", "okta-prod",
		"user_signin", "authentication"); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("entitled ingest: status = %d, want 202", resp.StatusCode)
	}

	// Somebody else's source name, under the same source type. This is the
	// interesting half: source_name is 128 bytes of free text and is what a
	// correlation subject falls back to when an event names no actor.
	resp := h.ingest(t, "okta-prod", oktaKey, "identity_provider", "edr-fleet",
		"user_signin", "authentication")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unentitled source_name: status = %d, want 403", resp.StatusCode)
	}

	// And a source type it holds no entitlement for at all.
	resp = h.ingest(t, "okta-prod", oktaKey, "endpoint_agent", "edr-fleet",
		"process_started", "process_execution")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unentitled source_type: status = %d, want 403", resp.StatusCode)
	}

	// The refusal is in the trail, naming what was claimed — a producer trying
	// to be a second sensor is the shape of the attack this exists to stop, and
	// it must not pass silently.
	var refusals int
	for _, e := range h.audit(t) {
		if e.Action != audit.ActionEventRejected {
			continue
		}
		if kind, _ := e.Details["error_kind"].(string); kind == "producer_source_mismatch" {
			refusals++
			if e.Actor != "producer:okta-prod" {
				t.Errorf("refusal is attributed to %q, want the credential that made the claim", e.Actor)
			}
			if e.Details["claimed_source_name"] == nil {
				t.Error("the refusal does not record what was claimed")
			}
		}
	}
	if refusals != 2 {
		t.Errorf("audited source mismatches = %d, want 2", refusals)
	}
}

// TestAcceptedTelemetryIsAttributedToItsCredential.
//
// The trail records which credential supplied each event, not the source name
// inside the body — which is the string that was never worth anything.
func TestAcceptedTelemetryIsAttributedToItsCredential(t *testing.T) {
	h := newProducerHarness(t)
	if resp := h.ingest(t, "edr-fleet", edrKey, "endpoint_agent", "edr-fleet",
		"process_started", "process_execution"); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	var attributed int
	for _, e := range h.audit(t) {
		if e.Action == audit.ActionEventIngested {
			attributed++
			if e.Actor != "producer:edr-fleet" {
				t.Errorf("Actor = %q, want producer:edr-fleet", e.Actor)
			}
			if e.ActorRole != "producer" {
				t.Errorf("ActorRole = %q, want producer", e.ActorRole)
			}
		}
	}
	if attributed == 0 {
		t.Fatal("no event.ingested entry was written")
	}
}

// TestARefusedCredentialIsCountedAndNotAudited.
//
// A credential that never got past the door supplied no telemetry, so there is
// nothing about it for the trail to account for — and auditing it would let
// anyone holding the service credential grow an append-only table with a wrong
// header. The counter is where a guessing run becomes visible instead.
func TestARefusedCredentialIsCountedAndNotAudited(t *testing.T) {
	h := newProducerHarness(t)
	before := len(h.audit(t))

	for _, tc := range []struct{ producer, key string }{
		{"okta-prod", "wrong-key-but-long-enough-to-be-plausible"},
		{"ghost-sensor", oktaKey},
	} {
		if resp := h.ingest(t, tc.producer, tc.key, "identity_provider", "okta-prod",
			"user_signin", "authentication"); resp.StatusCode != http.StatusForbidden {
			t.Errorf("producer %q: status = %d, want 403", tc.producer, resp.StatusCode)
		}
	}
	if after := len(h.audit(t)); after != before {
		t.Errorf("the trail grew from %d to %d entries on refused credentials", before, after)
	}
}

// TestOneProducerCannotSuppressAnothersEventByTakingItsId.
//
// Event ids are producer-supplied, and a real connector derives them from the
// upstream system — an Okta connector uses Okta's event id — so a neighbour's
// ids are predictable. Dedup used to discard any repeat silently, so a producer
// that pre-registered an id its neighbour would later use made that neighbour's
// genuine event vanish. Evidence suppression from inside the trust boundary,
// with no trace at all.
//
// A retry from the SAME producer stays silent, because that is what a retry is.
func TestOneProducerCannotSuppressAnothersEventByTakingItsId(t *testing.T) {
	h := newProducerHarness(t)

	post := func(producer, key, id string) *http.Response {
		t.Helper()
		body := `{"id":"` + id + `","schema_version":"0.1","timestamp":"2026-08-27T18:00:00Z",` +
			`"source_type":"identity_provider","source_name":"okta-prod",` +
			`"event_type":"user_signin","category":"authentication","severity":"high",` +
			`"actor":{"type":"identity","id":"victim@lab.example"}}`
		if producer == "edr-fleet" {
			body = strings.ReplaceAll(body, "identity_provider", "endpoint_agent")
			body = strings.ReplaceAll(body, `"source_name":"okta-prod"`, `"source_name":"edr-fleet"`)
			body = strings.ReplaceAll(body, "user_signin", "process_started")
			body = strings.ReplaceAll(body, "authentication", "process_execution")
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			h.server.URL+"/api/v1/events", strings.NewReader(body))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+prodToken)
		req.Header.Set(httpx.HeaderProducer, producer)
		req.Header.Set(httpx.HeaderProducerKey, key)
		resp, err := h.server.Client().Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	const contested = "okta-evt-00012345"

	// The squatter gets there first.
	if resp := post("edr-fleet", edrKey, contested); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("first submission: status = %d, want 202", resp.StatusCode)
	}
	// The genuine sensor's event must not simply vanish.
	resp := post("okta-prod", oktaKey, contested)
	if resp.StatusCode == http.StatusAccepted {
		t.Fatal("the second producer's event was silently accepted as a duplicate; " +
			"one producer can make another's evidence disappear")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 naming the collision", resp.StatusCode)
	}

	var collisions int
	for _, e := range h.audit(t) {
		if kind, _ := e.Details["error_kind"].(string); kind == "producer_id_collision" {
			collisions++
			if e.Details["holding_producer"] != "edr-fleet" {
				t.Errorf("the refusal does not name who holds the id: %v", e.Details)
			}
		}
	}
	if collisions != 1 {
		t.Errorf("audited collisions = %d, want 1", collisions)
	}

	// And the holder's own retry is still a retry.
	if resp := post("edr-fleet", edrKey, contested); resp.StatusCode != http.StatusAccepted {
		t.Errorf("the holder's retry: status = %d, want 202 — a retry is not a collision",
			resp.StatusCode)
	}
}

// TestEvidenceProducersIsDerivedFromFindings.
//
// Carried now and gated on later: the binary must SEND evidence_producers
// before any bundle requires it, because a policy demanding a field an older
// binary omits fails input validation and this policy's default is deny.
func TestEvidenceProducersIsDerivedFromFindings(t *testing.T) {
	inc := &incidents.Incident{Findings: []incidents.Finding{
		{RuleID: "GRF-CORR-0001", ProducerIDs: []string{"okta-prod"}},
		{RuleID: "GRF-CORR-0002", ProducerIDs: []string{"edr-fleet", "okta-prod"}},
		{RuleID: "GRF-CORR-0003"},
	}}
	got := inc.EvidenceProducers()
	if len(got) != 2 || got[0] != "edr-fleet" || got[1] != "okta-prod" {
		t.Errorf("EvidenceProducers() = %v, want the distinct set, sorted", got)
	}
	// An unattributed incident is not one anonymous producer.
	empty := &incidents.Incident{Findings: []incidents.Finding{{RuleID: "GRF-CORR-0001"}}}
	if got := empty.EvidenceProducers(); len(got) != 0 {
		t.Errorf("EvidenceProducers() = %v on an unattributed incident, want empty", got)
	}
}
