package api_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/httpx"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
	"github.com/kamilxgriefer/griefer-security-platform/internal/policy"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
	"github.com/kamilxgriefer/griefer-security-platform/policies"
)

// forcedKernel is a Policy Kernel that always returns the same verdict.
//
// The taxonomy is about how GRIEFER CLASSIFIES what happened, and every branch
// of it has to be reachable in a test. Pinning the verdict here separates that
// from what the real policy happens to say about one seeded incident: a rule
// change in policies/*.rego should not be able to silently stop
// "requires_approval" from ever being exercised.
//
// It also honours the Kernel contract that the decision is safe to act on even
// when err is non-nil, by returning a fail-closed deny alongside the error.
type forcedKernel struct {
	effect string
	err    error
	calls  atomic.Int64
}

func (k *forcedKernel) Evaluate(context.Context, policy.Input) (incidents.PolicyDecision, error) {
	k.calls.Add(1)
	if k.err != nil {
		return incidents.PolicyDecision{
			Effect: policy.EffectDeny, Allow: false, FailClosed: true,
			Engine: policy.EngineUnavailable, EvaluatedAt: time.Now().UTC(),
			Reasons: []string{"Policy Kernel could not be consulted; GRIEFER fails closed."},
		}, k.err
	}
	return incidents.PolicyDecision{
		Effect:        k.effect,
		Allow:         k.effect == policy.EffectAllow,
		Reasons:       []string{"Forced verdict from the test kernel."},
		PolicyPackage: policies.Package,
		PolicyVersion: policies.Version,
		EvaluatedAt:   time.Now().UTC(),
		Engine:        policy.EngineEmbedded,
	}, nil
}

func (k *forcedKernel) Health(context.Context) error { return k.err }
func (k *forcedKernel) Engine() string               { return policy.EngineEmbedded }
func (k *forcedKernel) Close() error                 { return nil }

// secretishDetailKeys must never name a key in an audit detail map.
//
// The audit trail is the one table an operator reads freely, exports into a
// ticket and hands to an auditor. A credential that lands in it turns the
// record of an incident into a second incident, and unlike a log line it cannot
// be rotated away: the trail is append-only by design, so there is no code path
// that can go back and redact it.
var secretishDetailKeys = []string{"password", "token", "authorization", "secret", "cookie", "dsn"}

// assertNoSecretDetailKeys walks details, including nested maps and slices,
// because a whole request or config object is exactly the kind of thing that
// gets attached wholesale to "just one more detail field".
func assertNoSecretDetailKeys(t *testing.T, where string, value any) {
	t.Helper()
	switch v := value.(type) {
	case map[string]any:
		for key, nested := range v {
			lower := strings.ToLower(key)
			for _, banned := range secretishDetailKeys {
				if strings.Contains(lower, banned) {
					t.Errorf("%s: audit detail key %q contains %q; the audit trail must never carry credential material", where, key, banned)
				}
			}
			assertNoSecretDetailKeys(t, where+"."+key, nested)
		}
	case []any:
		for i, nested := range v {
			assertNoSecretDetailKeys(t, fmt.Sprintf("%s[%d]", where, i), nested)
		}
	}
}

// actionAuditEntries returns every audit entry whose subject is a response
// action, oldest first. Entries from ingestion are filtered out so a test sees
// only the trail its evaluation produced.
func actionAuditEntries(t *testing.T, store storage.Store) []*audit.Entry {
	t.Helper()
	var out []*audit.Entry
	for offset := 0; ; {
		page, total, err := store.List(context.Background(), storage.MaxPageSize, offset)
		if err != nil {
			t.Fatalf("List() audit entries: %v", err)
		}
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			if e.SubjectType == audit.SubjectAction {
				out = append(out, e)
			}
		}
		offset += len(page)
		if offset >= total {
			break
		}
	}
	return out
}

// TestEveryEvaluationOutcomeIsRecordedWithItsResultInTheAuditTrail is the
// milestone's central claim: no evaluation is silent, and the trail says what
// happened, not merely whether it succeeded.
//
// Outcome alone cannot carry that. A deliberate denial and an unreachable
// Policy Kernel are both OutcomeDenied — GRIEFER fails closed, so they look
// identical from the outside — and a platform that cannot tell a considered
// refusal from a broken dependency cannot be operated during the incident where
// it matters.
func TestEveryEvaluationOutcomeIsRecordedWithItsResultInTheAuditTrail(t *testing.T) {
	tests := []struct {
		name string
		// kernel is the verdict the Policy Kernel is forced to return.
		kernel *forcedKernel
		// body builds the request from the seeded incident's id.
		body func(incidentID string) string
		// wantResult is the taxonomy value expected in Details["result"].
		wantResult string
		wantStatus int
		// wantAuditActions is the exact set of audit actions the evaluation
		// must leave behind.
		wantAuditActions []string
		// wantPolicyConsulted is false for rejections GRIEFER makes on its own,
		// before any policy is asked.
		wantPolicyConsulted bool
	}{
		{
			name:   "an allowed simulation records allowed",
			kernel: &forcedKernel{effect: policy.EffectAllow},
			body: func(id string) string {
				return fmt.Sprintf(`{"incident_id":%q,"action_type":"preserve_evidence","mode":"simulate"}`, id)
			},
			wantResult:          audit.ResultAllowed,
			wantStatus:          http.StatusOK,
			wantAuditActions:    []string{audit.ActionPolicyEvaluated, audit.ActionActionSimulated},
			wantPolicyConsulted: true,
		},
		{
			name:   "a policy denial records denied",
			kernel: &forcedKernel{effect: policy.EffectDeny},
			body: func(id string) string {
				return fmt.Sprintf(`{"incident_id":%q,"action_type":"preserve_evidence","mode":"simulate"}`, id)
			},
			wantResult:          audit.ResultDenied,
			wantStatus:          http.StatusOK,
			wantAuditActions:    []string{audit.ActionPolicyEvaluated, audit.ActionActionDenied},
			wantPolicyConsulted: true,
		},
		{
			name:   "a decision requiring approval records requires_approval",
			kernel: &forcedKernel{effect: policy.EffectRequireApproval},
			body: func(id string) string {
				return fmt.Sprintf(`{"incident_id":%q,"action_type":"preserve_evidence","mode":"simulate"}`, id)
			},
			wantResult:          audit.ResultRequiresApproval,
			wantStatus:          http.StatusOK,
			wantAuditActions:    []string{audit.ActionPolicyEvaluated, audit.ActionActionNeedsApproval},
			wantPolicyConsulted: true,
		},
		{
			// An action type outside the catalog is refused by GRIEFER itself.
			// The policy is never asked, which is the point: the catalog, not
			// the policy, is what bounds the space of things that can be
			// proposed at all.
			name:   "an unknown action type records invalid_action",
			kernel: &forcedKernel{effect: policy.EffectAllow},
			body: func(id string) string {
				return fmt.Sprintf(`{"incident_id":%q,"action_type":"exfiltrate_everything","mode":"simulate"}`, id)
			},
			wantResult:          audit.ResultInvalidAction,
			wantStatus:          http.StatusBadRequest,
			wantAuditActions:    []string{audit.ActionActionRejected},
			wantPolicyConsulted: false,
		},
		{
			// A mode GRIEFER does not implement must not fall through to a
			// default. "execute" and "simulate" are the only two, and an
			// unrecognised third must never be treated as either.
			name:   "an unrecognised mode records validation_failed",
			kernel: &forcedKernel{effect: policy.EffectAllow},
			body: func(id string) string {
				return fmt.Sprintf(`{"incident_id":%q,"action_type":"preserve_evidence","mode":"obliterate"}`, id)
			},
			wantResult:          audit.ResultValidationFailed,
			wantStatus:          http.StatusBadRequest,
			wantAuditActions:    []string{audit.ActionActionRejected},
			wantPolicyConsulted: false,
		},
		{
			// An action proposed against an incident that does not exist leaves
			// no ResponseAction row to hang a record on, so this is the path
			// most likely to go unrecorded. It is also the path an attacker
			// probing for valid incident ids would walk.
			name:   "a missing incident records validation_failed",
			kernel: &forcedKernel{effect: policy.EffectAllow},
			body: func(string) string {
				return `{"incident_id":"inc-does-not-exist","action_type":"preserve_evidence","mode":"simulate"}`
			},
			wantResult:          audit.ResultValidationFailed,
			wantStatus:          http.StatusNotFound,
			wantAuditActions:    []string{audit.ActionActionRejected},
			wantPolicyConsulted: false,
		},
		{
			// A broken Policy Kernel denies, but it must not be filed as a
			// denial: an operator reading a wall of "denied" needs to see that
			// the reason was an unavailable dependency, not a rule.
			name:   "a kernel error records policy_unavailable",
			kernel: &forcedKernel{effect: policy.EffectDeny, err: errors.New("policy kernel unreachable")},
			body: func(id string) string {
				return fmt.Sprintf(`{"incident_id":%q,"action_type":"preserve_evidence","mode":"simulate"}`, id)
			},
			wantResult:          audit.ResultPolicyUnavailable,
			wantStatus:          http.StatusOK,
			wantAuditActions:    []string{audit.ActionPolicyEvaluated, audit.ActionActionDenied},
			wantPolicyConsulted: true,
		},
		{
			// A timeout is separated from a generic outage because the two lead
			// an operator to different places: one is a slow or overloaded
			// kernel, the other is a kernel that is not there at all.
			name: "a kernel error wrapping a deadline records policy_timeout",
			kernel: &forcedKernel{
				effect: policy.EffectDeny,
				err:    fmt.Errorf("evaluate policy: %w", context.DeadlineExceeded),
			},
			body: func(id string) string {
				return fmt.Sprintf(`{"incident_id":%q,"action_type":"preserve_evidence","mode":"simulate"}`, id)
			},
			wantResult:          audit.ResultPolicyTimeout,
			wantStatus:          http.StatusOK,
			wantAuditActions:    []string{audit.ActionPolicyEvaluated, audit.ActionActionDenied},
			wantPolicyConsulted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, harnessOptions{kernel: tt.kernel})
			inc := h.seedScenario()

			resp := h.do(http.MethodPost, "/api/v1/actions/evaluate", tt.body(inc.ID))
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, tt.wantStatus, h.body(resp))
			}

			if consulted := tt.kernel.calls.Load() > 0; consulted != tt.wantPolicyConsulted {
				t.Errorf("policy consulted = %t, want %t", consulted, tt.wantPolicyConsulted)
			}

			entries := actionAuditEntries(t, h.Store)
			if len(entries) == 0 {
				t.Fatal("the evaluation left no audit entry at all; an evaluation that produced no trail is indistinguishable, later, from one that never happened")
			}

			gotActions := map[string]int{}
			for _, entry := range entries {
				gotActions[entry.Action]++
			}
			if len(gotActions) != len(tt.wantAuditActions) {
				t.Errorf("audit actions = %v, want exactly %v", gotActions, tt.wantAuditActions)
			}
			for _, want := range tt.wantAuditActions {
				if gotActions[want] == 0 {
					t.Errorf("no audit entry with action %q; got %v", want, gotActions)
				}
			}

			for i, entry := range entries {
				where := fmt.Sprintf("entry %d (%s)", i, entry.Action)

				if got, _ := entry.Details["result"].(string); got != tt.wantResult {
					t.Errorf("%s: Details[\"result\"] = %q, want %q", where, got, tt.wantResult)
				}
				// A trail entry that cannot be tied back to the request that
				// caused it cannot be used to reconstruct an incident, and the
				// router supplies the id on every request that reaches a
				// handler.
				if entry.RequestID == "" {
					t.Errorf("%s: RequestID is empty on a request that went through the router", where)
				}
				// Prepare() defaults this to the system actor, so an empty one
				// means the entry never went through Prepare and the trail is
				// recording an unattributed decision.
				if entry.Actor == "" {
					t.Errorf("%s: Actor is empty", where)
				}
				if entry.Outcome == "" {
					t.Errorf("%s: Outcome is empty", where)
				}
				if entry.ID == "" || entry.Timestamp.IsZero() {
					t.Errorf("%s: entry was not stamped with an id and a timestamp", where)
				}
				if entry.SubjectID == "" {
					t.Errorf("%s: SubjectID is empty; the entry names no action", where)
				}

				// These are the fields that make an entry reconstructable
				// without the original request: which incident, what was
				// proposed, in what mode, and which policy bundle judged it.
				for _, key := range []string{"result", "incident_id", "action_type", "mode", "response_action_id", "policy_revision"} {
					if _, ok := entry.Details[key]; !ok {
						t.Errorf("%s: Details is missing %q", where, key)
					}
				}
				if got, _ := entry.Details["policy_revision"].(string); got != policies.Revision() {
					t.Errorf("%s: Details[\"policy_revision\"] = %q, want %q", where, got, policies.Revision())
				}
				if got, _ := entry.Details["response_action_id"].(string); got != entry.SubjectID {
					t.Errorf("%s: Details[\"response_action_id\"] = %q but SubjectID = %q", where, got, entry.SubjectID)
				}

				assertNoSecretDetailKeys(t, where, map[string]any(entry.Details))
			}
		})
	}
}

// TestTheRealPolicyKernelRecordsASimulatedActionAsAllowed guards the forced
// kernel above from drifting away from the thing it stands in for. If the
// embedded policy and the taxonomy ever disagree about what "allowed" means,
// the table test would keep passing on its own stub.
func TestTheRealPolicyKernelRecordsASimulatedActionAsAllowed(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	inc := h.seedScenario()

	body := fmt.Sprintf(`{"incident_id":%q,"action_type":"preserve_evidence","mode":"simulate","automated":true}`, inc.ID)
	resp := h.do(http.MethodPost, "/api/v1/actions/evaluate", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, h.body(resp))
	}
	var action incidents.ResponseAction
	h.decode(resp, &action)
	if action.Status != incidents.ActionSimulated {
		t.Fatalf("Status = %q, want simulated", action.Status)
	}

	entries := actionAuditEntries(t, h.Store)
	if len(entries) == 0 {
		t.Fatal("a simulated action left no audit entry")
	}
	for i, entry := range entries {
		if entry.SubjectID != action.ID {
			t.Errorf("entry %d: SubjectID = %q, want the evaluated action %q", i, entry.SubjectID, action.ID)
		}
		if got, _ := entry.Details["result"].(string); got != audit.ResultAllowed {
			t.Errorf("entry %d (%s): Details[\"result\"] = %q, want %q", i, entry.Action, got, audit.ResultAllowed)
		}
		if entry.RequestID == "" {
			t.Errorf("entry %d (%s): RequestID is empty", i, entry.Action)
		}
		assertNoSecretDetailKeys(t, fmt.Sprintf("entry %d (%s)", i, entry.Action), map[string]any(entry.Details))
	}
}

// TestAnEvaluationRejectedBeforePolicyStillNamesTheRequestInTheTrail pins the
// hardest case for completeness: the request is refused before a ResponseAction
// row exists, so there is nothing for the entry to hang off, and the entry has
// to carry the request's identity on its own.
func TestAnEvaluationRejectedBeforePolicyStillNamesTheRequestInTheTrail(t *testing.T) {
	h := newHarness(t, harnessOptions{kernel: &forcedKernel{effect: policy.EffectAllow}})
	h.seedScenario()

	resp := h.do(http.MethodPost, "/api/v1/actions/evaluate",
		`{"incident_id":"inc-does-not-exist","action_type":"preserve_evidence","mode":"simulate"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	requestID := resp.Header.Get(httpx.RequestIDHeader)
	if requestID == "" {
		t.Fatal("the response carries no request id header")
	}

	entries := actionAuditEntries(t, h.Store)
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want exactly 1 for a pre-policy rejection", len(entries))
	}
	entry := entries[0]
	if entry.RequestID != requestID {
		t.Errorf("RequestID = %q, want %q so the trail and the caller's response agree", entry.RequestID, requestID)
	}
	if got, _ := entry.Details["incident_id"].(string); got != "inc-does-not-exist" {
		t.Errorf("Details[\"incident_id\"] = %q, want the id that was asked for", got)
	}
	// No action row was written, so a reader of the actions table would see
	// nothing; the audit entry is the only record that the attempt happened.
	if _, err := h.Store.GetAction(context.Background(), entry.SubjectID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("GetAction() error = %v, want ErrNotFound; a rejected evaluation must not leave an action row", err)
	}
}
