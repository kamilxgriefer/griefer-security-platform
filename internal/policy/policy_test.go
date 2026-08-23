package policy_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/policy"
)

func embedded(t *testing.T) *policy.EmbeddedKernel {
	t.Helper()
	k, err := policy.NewEmbeddedKernel()
	if err != nil {
		t.Fatalf("NewEmbeddedKernel() error = %v", err)
	}
	t.Cleanup(func() { _ = k.Close() })
	return k
}

// corroborated is a well-formed request for a safe action on a well-evidenced
// incident: the baseline that every safety rule below deviates from by exactly
// one field.
func corroborated() policy.Input {
	return policy.Input{
		Action: policy.ActionInput{
			Type: "preserve_evidence", Mode: "simulate", Known: true,
			Destructive: false, Reversible: true, RollbackAction: "release_evidence_hold",
			TargetsCriticalAsset: false, Isolation: false,
		},
		Incident: policy.IncidentInput{
			ID: "inc-1", RiskScore: 81, Confidence: 0.95, Severity: "critical",
			EvidenceCategories: []string{"authentication", "privilege_escalation", "credential_access"},
			FindingCount:       3,
		},
		Request: policy.RequestInput{Automated: true, RequestedBy: "correlation-engine"},
	}
}

func TestEmbeddedKernelEnforcesTheSafetyRules(t *testing.T) {
	k := embedded(t)
	ctx := context.Background()

	tests := []struct {
		name       string
		mutate     func(*policy.Input)
		wantEffect string
		wantReason string
	}{
		{
			name:       "corroborated, reversible, simulated action is allowed",
			mutate:     func(*policy.Input) {},
			wantEffect: policy.EffectAllow,
			wantReason: "non-destructive",
		},
		{
			name: "rule 3: a destructive action is denied unconditionally",
			mutate: func(in *policy.Input) {
				in.Action.Type = "wipe_endpoint"
				in.Action.Destructive = true
				in.Action.Reversible = false
			},
			wantEffect: policy.EffectDeny,
			wantReason: "destructive",
		},
		{
			name: "a destructive action stays denied even when a human asks",
			mutate: func(in *policy.Input) {
				in.Action.Destructive = true
				in.Request.Automated = false
				in.Request.RequestedBy = "analyst:senior"
			},
			wantEffect: policy.EffectDeny,
			wantReason: "destructive",
		},
		{
			name: "an action outside the catalog is denied",
			mutate: func(in *policy.Input) {
				in.Action.Type = "launch_missiles"
				in.Action.Known = false
			},
			wantEffect: policy.EffectDeny,
			wantReason: "not defined in the GRIEFER action catalog",
		},
		{
			name: "an unrecognised mode is denied",
			mutate: func(in *policy.Input) {
				in.Action.Mode = "yolo"
			},
			wantEffect: policy.EffectDeny,
			wantReason: "not recognised",
		},
		{
			name: "rule 4: an irreversible action requires human approval",
			mutate: func(in *policy.Input) {
				in.Action.Type = "revoke_sessions"
				in.Action.Reversible = false
				in.Action.RollbackAction = ""
			},
			wantEffect: policy.EffectRequireApproval,
			wantReason: "not reversible",
		},
		{
			name: "rule 4: a reversible action with no defined rollback requires approval",
			mutate: func(in *policy.Input) {
				in.Action.RollbackAction = ""
			},
			wantEffect: policy.EffectRequireApproval,
			wantReason: "no rollback action",
		},
		{
			name: "rule 5: an action on a critical asset requires human approval",
			mutate: func(in *policy.Input) {
				in.Action.TargetsCriticalAsset = true
			},
			wantEffect: policy.EffectRequireApproval,
			wantReason: "classified critical",
		},
		{
			name: "rule 2: automated response needs two independent evidence categories",
			mutate: func(in *policy.Input) {
				in.Incident.EvidenceCategories = []string{"authentication"}
			},
			wantEffect: policy.EffectRequireApproval,
			wantReason: "at least 2 independent evidence categories",
		},
		{
			name: "repeating one category does not count as corroboration",
			mutate: func(in *policy.Input) {
				in.Incident.EvidenceCategories = []string{"authentication", "authentication", "authentication"}
			},
			wantEffect: policy.EffectRequireApproval,
			wantReason: "at least 2 independent evidence categories",
		},
		{
			name: "rule 1: a single weak signal cannot trigger automated isolation",
			mutate: func(in *policy.Input) {
				in.Action.Type = "isolate_endpoint"
				in.Action.Isolation = true
				in.Action.RollbackAction = "release_endpoint_isolation"
				in.Incident.EvidenceCategories = []string{"authentication"}
				in.Incident.RiskScore = 11
			},
			wantEffect: policy.EffectRequireApproval,
			wantReason: "cannot be triggered automatically by a single weak signal",
		},
		{
			name: "a low-risk incident does not authorise automation",
			mutate: func(in *policy.Input) {
				in.Incident.RiskScore = 12
			},
			wantEffect: policy.EffectRequireApproval,
			wantReason: "below the automation threshold",
		},
		{
			name: "execute mode always requires human approval at this autonomy level",
			mutate: func(in *policy.Input) {
				in.Action.Mode = "execute"
			},
			wantEffect: policy.EffectRequireApproval,
			wantReason: "always requires human approval",
		},
		{
			name: "rule 6: an isolation action fully corroborated may be simulated automatically",
			mutate: func(in *policy.Input) {
				in.Action.Type = "isolate_endpoint"
				in.Action.Isolation = true
				in.Action.RollbackAction = "release_endpoint_isolation"
			},
			wantEffect: policy.EffectAllow,
			wantReason: "corroborated by 3 independent evidence categories",
		},
		{
			name: "a human request on a weakly evidenced incident is still allowed to simulate",
			mutate: func(in *policy.Input) {
				in.Request.Automated = false
				in.Incident.EvidenceCategories = []string{"authentication"}
				in.Incident.RiskScore = 10
			},
			wantEffect: policy.EffectAllow,
			wantReason: "non-destructive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := corroborated()
			tt.mutate(&in)

			got, err := k.Evaluate(ctx, in)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Effect != tt.wantEffect {
				t.Errorf("Effect = %q, want %q (reasons: %v)", got.Effect, tt.wantEffect, got.Reasons)
			}
			if got.Allow != (tt.wantEffect == policy.EffectAllow) {
				t.Errorf("Allow = %v, inconsistent with effect %q", got.Allow, got.Effect)
			}
			// Requirement 7: every decision carries a readable reason.
			if len(got.Reasons) == 0 {
				t.Fatal("decision carries no reason; an unexplained verdict is not auditable")
			}
			joined := strings.Join(got.Reasons, " | ")
			if !strings.Contains(joined, tt.wantReason) {
				t.Errorf("reasons = %q, want one mentioning %q", joined, tt.wantReason)
			}
			if got.FailClosed {
				t.Error("FailClosed set on a decision the kernel actually evaluated")
			}
			if got.PolicyVersion == "" || got.PolicyPackage == "" {
				t.Error("decision does not identify the policy that produced it")
			}
			if got.EvaluatedAt.IsZero() {
				t.Error("decision has no evaluation timestamp")
			}
		})
	}
}

func TestEmbeddedKernelFailsClosedOnMalformedInput(t *testing.T) {
	k := embedded(t)
	// A request missing the fields the policy needs must not be answered with
	// silence. Rego rules that simply do not fire would otherwise leave the
	// decision undefined, which is indistinguishable from permission.
	got, err := k.Evaluate(context.Background(), policy.Input{
		Action: policy.ActionInput{Type: "require_mfa"},
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Effect != policy.EffectDeny {
		t.Fatalf("Effect = %q, want deny for incomplete input", got.Effect)
	}
	if !strings.Contains(strings.Join(got.Reasons, " "), "incomplete or malformed") {
		t.Errorf("reasons = %v, want an explicit malformed-input denial", got.Reasons)
	}
}

func TestEmbeddedKernelHealthAndEngine(t *testing.T) {
	k := embedded(t)
	if err := k.Health(context.Background()); err != nil {
		t.Errorf("Health() error = %v", err)
	}
	if k.Engine() != policy.EngineEmbedded {
		t.Errorf("Engine() = %q, want %q", k.Engine(), policy.EngineEmbedded)
	}
}

func TestEmbeddedKernelRespectsContextCancellation(t *testing.T) {
	k := embedded(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := k.Evaluate(ctx, corroborated())
	if err == nil {
		t.Fatal("Evaluate() ignored a cancelled context")
	}
	// The contract: even on error, the returned decision is safe to act on.
	if got.Effect != policy.EffectDeny || !got.FailClosed {
		t.Errorf("decision on error = %+v, want a fail-closed deny", got)
	}
}

// ---------------------------------------------------------------------------
// Remote kernel
// ---------------------------------------------------------------------------

func TestRemoteKernelFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "OPA returns an error status",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
		},
		{
			name: "policy document is undefined",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			},
		},
		{
			name: "decision has an unrecognised effect",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"result":{"effect":"maybe","allow":true,"reasons":["shrug"]}}`))
			},
		},
		{
			name: "decision claims allow without the allow effect",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"result":{"effect":"deny","allow":true,"reasons":["contradiction"]}}`))
			},
		},
		{
			name: "decision carries no reason",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"result":{"effect":"allow","allow":true,"reasons":[]}}`))
			},
		},
		{
			name: "response is not JSON",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`<html>proxy error</html>`))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			k, err := policy.NewRemoteKernel(policy.RemoteOptions{
				BaseURL: srv.URL, DecisionPath: "griefer/response/decision", Timeout: 2 * time.Second,
			})
			if err != nil {
				t.Fatalf("NewRemoteKernel() error = %v", err)
			}
			defer func() { _ = k.Close() }()

			got, err := k.Evaluate(context.Background(), corroborated())
			if err == nil {
				t.Fatal("Evaluate() reported success for an unusable policy response")
			}
			if got.Effect != policy.EffectDeny || got.Allow {
				t.Errorf("decision = %+v, want a deny", got)
			}
			if !got.FailClosed {
				t.Error("FailClosed not set; an operator cannot tell a real denial from a degraded kernel")
			}
			if len(got.Reasons) == 0 {
				t.Error("fail-closed denial carries no reason")
			}
			if got.Engine != policy.EngineUnavailable {
				t.Errorf("Engine = %q, want %q", got.Engine, policy.EngineUnavailable)
			}
		})
	}
}

func TestRemoteKernelFailsClosedWhenUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening now

	k, err := policy.NewRemoteKernel(policy.RemoteOptions{
		BaseURL: url, DecisionPath: "griefer/response/decision", Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewRemoteKernel() error = %v", err)
	}
	defer func() { _ = k.Close() }()

	got, err := k.Evaluate(context.Background(), corroborated())
	if err == nil {
		t.Fatal("Evaluate() succeeded against a dead endpoint")
	}
	if got.Effect != policy.EffectDeny || !got.FailClosed {
		t.Errorf("decision = %+v, want a fail-closed deny", got)
	}
	if err := k.Health(context.Background()); err == nil {
		t.Error("Health() reported a dead OPA as healthy")
	}
}

func TestRemoteKernelAcceptsAWellFormedDecision(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":{"effect":"allow","allow":true,"reasons":["ok"],"policy_package":"griefer.response","policy_version":"0.1.0","evidence_category_count":3}}`))
	}))
	defer srv.Close()

	k, err := policy.NewRemoteKernel(policy.RemoteOptions{
		BaseURL: srv.URL, DecisionPath: "griefer/response/decision", Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewRemoteKernel() error = %v", err)
	}
	defer func() { _ = k.Close() }()

	got, err := k.Evaluate(context.Background(), corroborated())
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Effect != policy.EffectAllow || !got.Allow {
		t.Errorf("decision = %+v, want allow", got)
	}
	if got.FailClosed {
		t.Error("FailClosed set on a decision OPA actually produced")
	}
	if got.Engine != policy.EngineRemote {
		t.Errorf("Engine = %q, want %q", got.Engine, policy.EngineRemote)
	}
	if !strings.Contains(gotBody, `"input"`) {
		t.Errorf("request body = %q, want it wrapped in an OPA input envelope", gotBody)
	}
	if err := k.Health(context.Background()); err != nil {
		t.Errorf("Health() error = %v", err)
	}
}

func TestNewRemoteKernelValidatesOptions(t *testing.T) {
	tests := []struct {
		name string
		opts policy.RemoteOptions
	}{
		{"no base URL", policy.RemoteOptions{DecisionPath: "a/b"}},
		{"no decision path", policy.RemoteOptions{BaseURL: "http://localhost:8181"}},
		{"non-HTTP scheme", policy.RemoteOptions{BaseURL: "file:///etc/passwd", DecisionPath: "a/b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := policy.NewRemoteKernel(tt.opts); err == nil {
				t.Error("NewRemoteKernel() accepted invalid options")
			}
		})
	}
}
