package api_test

// The tests in this file all defend one property: the caller does not get to
// choose who an action is attributed to.
//
// GRIEFER's audit trail exists to answer "who asked for this". The request body
// is written by whoever made the call, so a body field can only ever record
// what the caller wanted the trail to say. The operator therefore has to come
// from the request context, where httpx.PrincipalMiddleware put it AFTER the
// service credential was verified — and EvaluateRequest.RequestedBy has to be
// ignored entirely, not merely used as a fallback. A fallback is still a way in.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kamilxgriefer/griefer-security-platform/internal/api"
	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/httpx"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
	"github.com/kamilxgriefer/griefer-security-platform/internal/policy"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
	"github.com/kamilxgriefer/griefer-security-platform/policies"
)

const (
	// trustedActor is the operator the console asserts in the headers, after it
	// has authenticated the person and proved it is the console.
	trustedActor = "console:analyst"
	trustedRole  = api.RoleAnalyst
	// forgedActor is the identity the request BODY claims. It names someone
	// with more authority than the header principal on purpose: the interesting
	// failure is not a caller mislabelling itself, it is a caller borrowing a
	// name that would make a denied action look approved in a later review.
	forgedActor = "console:ceo"
	// systemActor mirrors the unexported constant the service and
	// audit.Prepare both fall back to. It is spelled out here so a change to
	// either one shows up as a failing test rather than as a trail that
	// silently starts saying something else.
	systemActor = "system:griefer"
	// actorTestToken is the service credential for this file's router.
	actorTestToken = "actor-trust-service-token"
)

// actorHarness is the shared harness plus a router that enforces the service
// credential.
//
// The second router is the point. httpx.PrincipalMiddleware is mounted only
// when RouterOptions.InternalAPIToken is set, and strictly inside the
// credential check, so that the actor headers are read only once the caller has
// proved it is a component we deployed. The default test harness leaves the API
// unauthenticated, which means the actor headers are never read there at all —
// a test using it would prove nothing about attribution.
type actorHarness struct {
	*harness
	authed *httptest.Server
}

func newActorHarness(t *testing.T, opts harnessOptions) *actorHarness {
	t.Helper()
	h := newHarness(t, opts)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	// Registry is deliberately nil: this router shares the harness's Service,
	// and its collectors are already registered against the harness registry.
	handler := api.NewRouter(h.Service, api.RouterOptions{
		MaxRequestBytes:  1 << 20,
		RateLimitRPS:     10000,
		RateLimitBurst:   10000,
		Logger:           logger,
		InternalAPIToken: actorTestToken,
	})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &actorHarness{harness: h, authed: srv}
}

// evaluate posts an action evaluation through the real router with a valid
// service credential. An empty subject sends no actor headers at all, which is
// how a trusted internal caller acting on nobody's behalf reaches the API.
func (h *actorHarness) evaluate(subject, role, body string) *http.Response {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		h.authed.URL+"/api/v1/actions/evaluate", strings.NewReader(body))
	if err != nil {
		h.t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+actorTestToken)
	if subject != "" {
		req.Header.Set(httpx.HeaderActor, subject)
	}
	if role != "" {
		req.Header.Set(httpx.HeaderActorRole, role)
	}
	resp, err := h.authed.Client().Do(req)
	if err != nil {
		h.t.Fatalf("POST /api/v1/actions/evaluate: %v", err)
	}
	h.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// allAudit reads the whole trail back through the store rather than through
// GET /api/v1/audit. What is being checked is what was persisted, and the read
// endpoint is a second thing that could be wrong; going to the store keeps the
// assertion about the write path only.
func (h *actorHarness) allAudit() []*audit.Entry {
	h.t.Helper()
	var out []*audit.Entry
	for offset := 0; ; offset += storage.MaxPageSize {
		page, total, err := h.Store.List(context.Background(), storage.MaxPageSize, offset)
		if err != nil {
			h.t.Fatalf("List() audit error = %v", err)
		}
		out = append(out, page...)
		if len(page) == 0 || len(out) >= total {
			return out
		}
	}
}

// auditForRequest returns the entries written while serving one request, in the
// order they were appended.
func (h *actorHarness) auditForRequest(requestID string) []*audit.Entry {
	h.t.Helper()
	if requestID == "" {
		h.t.Fatal("the response carried no request id; audit entries cannot be attributed to this call")
	}
	var out []*audit.Entry
	for _, entry := range h.allAudit() {
		if entry.RequestID == requestID {
			out = append(out, entry)
		}
	}
	return out
}

// detailString reads one Details value, failing loudly rather than letting a
// missing key compare equal to a zero value and pass.
func detailString(t *testing.T, entry *audit.Entry, key string) string {
	t.Helper()
	value, ok := entry.Details[key]
	if !ok {
		t.Fatalf("audit entry %s (%s) has no Details[%q]; details = %#v", entry.ID, entry.Action, key, entry.Details)
	}
	s, ok := value.(string)
	if !ok {
		t.Fatalf("audit entry %s Details[%q] = %#v, want a string", entry.ID, key, value)
	}
	return s
}

// evaluateBody builds an evaluation request whose body also claims an actor.
// Every test in this file sends requested_by, because the property under test
// is that the field changes nothing.
func evaluateBody(incidentID, actionType string, claimedBy string, automated bool) string {
	return fmt.Sprintf(
		`{"incident_id":%q,"action_type":%q,"mode":"simulate","requested_by":%q,"automated":%t}`,
		incidentID, actionType, claimedBy, automated)
}

func TestTheActionIsAttributedToTheHeaderPrincipalAndNotToTheRequestBody(t *testing.T) {
	h := newActorHarness(t, harnessOptions{})
	inc := h.seedScenario()

	resp := h.evaluate(trustedActor, trustedRole,
		evaluateBody(inc.ID, "preserve_evidence", forgedActor, false))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, h.body(resp))
	}

	var action incidents.ResponseAction
	h.decode(resp, &action)
	if action.RequestedBy != trustedActor {
		t.Errorf("RequestedBy = %q, want %q", action.RequestedBy, trustedActor)
	}
	if action.RequestedBy == forgedActor {
		t.Errorf("RequestedBy = %q: the body chose the actor, so the trail records whatever the caller wanted it to say", forgedActor)
	}

	// The response is only what the caller was told. What matters for a later
	// review is what was written down.
	stored, err := h.Store.GetAction(context.Background(), action.ID)
	if err != nil {
		t.Fatalf("GetAction(%q) error = %v", action.ID, err)
	}
	if stored.RequestedBy != trustedActor {
		t.Errorf("persisted RequestedBy = %q, want %q", stored.RequestedBy, trustedActor)
	}
}

func TestTheAuditEntriesRecordTheHeaderPrincipalAndTheRoleItHeld(t *testing.T) {
	h := newActorHarness(t, harnessOptions{})
	inc := h.seedScenario()

	resp := h.evaluate(trustedActor, trustedRole,
		evaluateBody(inc.ID, "preserve_evidence", forgedActor, false))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, h.body(resp))
	}

	entries := h.auditForRequest(resp.Header.Get(httpx.RequestIDHeader))
	if len(entries) == 0 {
		t.Fatal("the evaluation left no audit entry; an evaluation with no trail is indistinguishable from one that never happened")
	}
	for _, entry := range entries {
		if entry.Actor != trustedActor {
			t.Errorf("entry %s (%s) Actor = %q, want %q", entry.ID, entry.Action, entry.Actor, trustedActor)
		}
		// The role is stored beside the actor rather than looked up on read,
		// so the trail keeps saying what was true at the time even after the
		// account is promoted or demoted.
		if entry.ActorRole != trustedRole {
			t.Errorf("entry %s (%s) ActorRole = %q, want %q", entry.ID, entry.Action, entry.ActorRole, trustedRole)
		}
	}

	// The forged name must appear nowhere in the trail, not merely lose to the
	// header principal. An entry that recorded it alongside the true actor
	// would still let a reader come away believing the CEO asked for this.
	for _, entry := range h.allAudit() {
		if entry.Actor == forgedActor {
			t.Errorf("entry %s (%s) has Actor = %q, which only ever came from a request body", entry.ID, entry.Action, forgedActor)
		}
	}
}

func TestABodyCannotMarkARequestCarryingAnOperatorAsAutomated(t *testing.T) {
	inner, err := policy.NewEmbeddedKernel()
	if err != nil {
		t.Fatalf("NewEmbeddedKernel() error = %v", err)
	}
	kernel := &recordingKernel{inner: inner}
	h := newActorHarness(t, harnessOptions{kernel: kernel})
	inc := h.seedScenario()

	// automated selects which corroboration bar the policy applies. A caller
	// able to set it could choose the bar it is judged against, so the service
	// derives it instead: a request carrying an operator is a person pressing a
	// button, whatever the body says.
	t.Run("a request carrying an operator is judged as human-initiated", func(t *testing.T) {
		resp := h.evaluate(trustedActor, trustedRole,
			evaluateBody(inc.ID, "preserve_evidence", forgedActor, true))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, h.body(resp))
		}
		in := kernel.last(t)
		if in.Request.Automated {
			t.Error("policy input Automated = true, but the request carried an operator; the body chose the bar it was judged against")
		}
		if in.Request.RequestedBy != trustedActor {
			t.Errorf("policy input RequestedBy = %q, want %q", in.Request.RequestedBy, trustedActor)
		}
	})

	// The companion case: without it, an implementation that hard-coded
	// Automated to false would pass the test above while losing the
	// distinction the policy depends on.
	t.Run("the same body with no operator is judged as automated", func(t *testing.T) {
		resp := h.evaluate("", "", evaluateBody(inc.ID, "preserve_evidence", forgedActor, true))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, h.body(resp))
		}
		in := kernel.last(t)
		if !in.Request.Automated {
			t.Error("policy input Automated = false for a request with no operator; GRIEFER can no longer tell its own automation from a human")
		}
	})
}

func TestAnEvaluationWithNoActorHeadersFallsBackToTheSystemActor(t *testing.T) {
	h := newActorHarness(t, harnessOptions{})
	inc := h.seedScenario()

	resp := h.evaluate("", "", evaluateBody(inc.ID, "preserve_evidence", forgedActor, false))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, h.body(resp))
	}

	var action incidents.ResponseAction
	h.decode(resp, &action)
	// The fallback names the platform itself, which is the truth: such a
	// request came from a component holding the service credential and acting
	// on nobody's behalf. "unknown" would describe the reader's state rather
	// than the caller's, and the body's claim must not fill the gap either —
	// an unattributed request is exactly where a forged name would be most
	// useful to an attacker.
	if action.RequestedBy != systemActor {
		t.Errorf("RequestedBy = %q, want %q", action.RequestedBy, systemActor)
	}

	entries := h.auditForRequest(resp.Header.Get(httpx.RequestIDHeader))
	if len(entries) == 0 {
		t.Fatal("the evaluation left no audit entry")
	}
	for _, entry := range entries {
		if entry.Actor != systemActor {
			t.Errorf("entry %s (%s) Actor = %q, want %q", entry.ID, entry.Action, entry.Actor, systemActor)
		}
		if entry.ActorRole != "" {
			t.Errorf("entry %s (%s) ActorRole = %q, want empty; no operator was asserted, so no role was held", entry.ID, entry.Action, entry.ActorRole)
		}
	}
}

func TestAnUnknownActionTypeStillRecordsItsActionIDAndPolicyRevision(t *testing.T) {
	h := newActorHarness(t, harnessOptions{})
	inc := h.seedScenario()

	const unknownType = "delete_everything"
	resp := h.evaluate(trustedActor, trustedRole,
		evaluateBody(inc.ID, unknownType, forgedActor, false))
	// Rejected before any policy is consulted — and that is precisely the path
	// most likely to skip its audit entry, because nothing "happened".
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", resp.StatusCode, h.body(resp))
	}

	entries := h.auditForRequest(resp.Header.Get(httpx.RequestIDHeader))
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want 1; a request for an action that does not exist is worth recording", len(entries))
	}
	entry := entries[0]

	if entry.Actor != trustedActor {
		t.Errorf("Actor = %q, want %q", entry.Actor, trustedActor)
	}
	// Outcome says the request was refused; result says WHY, which is how an
	// operator tells a rejected action type from a policy denial or a broken
	// Policy Kernel.
	if got := detailString(t, entry, "result"); got != audit.ResultInvalidAction {
		t.Errorf("Details[\"result\"] = %q, want %q", got, audit.ResultInvalidAction)
	}

	actionID := detailString(t, entry, "response_action_id")
	if actionID != entry.SubjectID {
		t.Errorf("Details[\"response_action_id\"] = %q but SubjectID = %q; the entry describes two different actions", actionID, entry.SubjectID)
	}
	// The id has to name a record that exists, otherwise the trail points at
	// nothing and the rejection cannot be reconstructed later.
	stored, err := h.Store.GetAction(context.Background(), actionID)
	if err != nil {
		t.Fatalf("GetAction(%q) error = %v; the audit entry names an action that was never persisted", actionID, err)
	}
	if stored.ActionType != unknownType {
		t.Errorf("persisted ActionType = %q, want %q", stored.ActionType, unknownType)
	}
	if stored.Status != incidents.ActionRejected {
		t.Errorf("persisted Status = %q, want %q", stored.Status, incidents.ActionRejected)
	}
	if stored.RequestedBy != trustedActor {
		t.Errorf("persisted RequestedBy = %q, want %q", stored.RequestedBy, trustedActor)
	}

	// The revision pins the rules that were in force. Without it a later reader
	// knows the verdict but not what produced it, and a policy edit rewrites
	// the meaning of every past entry.
	revision := detailString(t, entry, "policy_revision")
	if !strings.HasPrefix(revision, "sha256:") {
		t.Errorf("Details[\"policy_revision\"] = %q, want a sha256: digest", revision)
	}
	if revision == "sha256:" {
		t.Error("Details[\"policy_revision\"] carries a prefix with no digest behind it")
	}
	if revision != policies.Revision() {
		t.Errorf("Details[\"policy_revision\"] = %q, want %q", revision, policies.Revision())
	}
}

func TestAValidEvaluationWritesAPolicyEntryAndAStatusEntryUnderOneActor(t *testing.T) {
	h := newActorHarness(t, harnessOptions{})
	inc := h.seedScenario()

	resp := h.evaluate(trustedActor, trustedRole,
		evaluateBody(inc.ID, "preserve_evidence", forgedActor, false))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, h.body(resp))
	}
	var action incidents.ResponseAction
	h.decode(resp, &action)

	entries := h.auditForRequest(resp.Header.Get(httpx.RequestIDHeader))
	if len(entries) != 2 {
		var got []string
		for _, entry := range entries {
			got = append(got, entry.Action)
		}
		t.Fatalf("got %d audit entries %v, want 2: what the policy decided and what became of the action", len(entries), got)
	}

	// The verdict comes first, then what GRIEFER did with it. Both are needed:
	// the decision alone does not say whether it was acted on, and the status
	// alone does not say why.
	if entries[0].Action != audit.ActionPolicyEvaluated {
		t.Errorf("first entry Action = %q, want %q", entries[0].Action, audit.ActionPolicyEvaluated)
	}
	statusActions := map[string]bool{
		audit.ActionActionSimulated:     true,
		audit.ActionActionDenied:        true,
		audit.ActionActionRejected:      true,
		audit.ActionActionNeedsApproval: true,
	}
	if !statusActions[entries[1].Action] {
		t.Errorf("second entry Action = %q, want one of the response.* status actions", entries[1].Action)
	}

	for i, entry := range entries {
		if entry.Actor != trustedActor {
			t.Errorf("entry %d (%s) Actor = %q, want %q", i, entry.Action, entry.Actor, trustedActor)
		}
		if entry.ActorRole != trustedRole {
			t.Errorf("entry %d (%s) ActorRole = %q, want %q", i, entry.Action, entry.ActorRole, trustedRole)
		}
		if entry.SubjectID != action.ID {
			t.Errorf("entry %d (%s) SubjectID = %q, want the evaluated action %q", i, entry.Action, entry.SubjectID, action.ID)
		}
	}

	// Both halves of the same decision must name the same rules. A pair that
	// disagreed would mean the trail cannot say which policy produced the
	// outcome it records.
	first := detailString(t, entries[0], "policy_revision")
	second := detailString(t, entries[1], "policy_revision")
	if first != second {
		t.Errorf("policy_revision differs across one evaluation: %q vs %q", first, second)
	}
	if !strings.HasPrefix(first, "sha256:") || first == "sha256:" {
		t.Errorf("policy_revision = %q, want a sha256: digest", first)
	}
}

// --- test doubles -----------------------------------------------------------

// recordingKernel captures what the service actually asked the Policy Kernel.
// The automated flag is only observable there: it never reaches the response
// body, and by the time a decision comes back it has already been folded into
// the verdict.
type recordingKernel struct {
	inner  policy.Kernel
	mu     sync.Mutex
	inputs []policy.Input
}

func (k *recordingKernel) Evaluate(ctx context.Context, in policy.Input) (incidents.PolicyDecision, error) {
	k.mu.Lock()
	k.inputs = append(k.inputs, in)
	k.mu.Unlock()
	return k.inner.Evaluate(ctx, in)
}

func (k *recordingKernel) Health(ctx context.Context) error { return k.inner.Health(ctx) }
func (k *recordingKernel) Engine() string                   { return k.inner.Engine() }
func (k *recordingKernel) Close() error                     { return k.inner.Close() }

func (k *recordingKernel) last(t *testing.T) policy.Input {
	t.Helper()
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.inputs) == 0 {
		t.Fatal("the Policy Kernel was never consulted")
	}
	return k.inputs[len(k.inputs)-1]
}
