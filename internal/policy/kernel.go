// Package policy implements GRIEFER's Policy Kernel: the single gate every
// proposed response action must pass through before it may be carried out.
//
// Two properties define this package:
//
//   - Nothing bypasses it. The correlation engine, the API and (from M7) any AI
//     component all reach an actuator only via a decision produced here.
//   - It fails closed. Every error path returns a valid deny decision, so a
//     caller that ignores the error is still safe. An unreachable kernel
//     produces "no", never "probably fine".
package policy

import (
	"context"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
	"github.com/kamilxgriefer/griefer-security-platform/policies"
)

// Effects returned by the policy.
const (
	EffectAllow           = "allow"
	EffectDeny            = "deny"
	EffectRequireApproval = "require_approval"
)

// Engine names reported on a decision.
const (
	EngineEmbedded    = "embedded"
	EngineRemote      = "remote"
	EngineUnavailable = "unavailable"
)

// ActionInput describes the proposed action. Every field is resolved by GRIEFER
// from its own action catalog; none of it is client- or telemetry-supplied.
type ActionInput struct {
	Type                 string `json:"type"`
	Mode                 string `json:"mode"`
	Known                bool   `json:"known"`
	Destructive          bool   `json:"destructive"`
	Reversible           bool   `json:"reversible"`
	RollbackAction       string `json:"rollback_action"`
	TargetsCriticalAsset bool   `json:"targets_critical_asset"`
	Isolation            bool   `json:"isolation"`
	TargetEntityID       string `json:"target_entity_id,omitempty"`
}

// IncidentInput is the evidence context the policy weighs.
type IncidentInput struct {
	ID                 string   `json:"id"`
	RiskScore          int      `json:"risk_score"`
	Confidence         float64  `json:"confidence"`
	Severity           string   `json:"severity"`
	EvidenceCategories []string `json:"evidence_categories"`
	// EvidenceProducers names the distinct authenticated producers behind the
	// evidence.
	//
	// Sent before any policy requires it, deliberately. A bundle that demanded
	// a field an older binary does not send would fail input_complete, and this
	// policy's default is deny — so the deployment order is: binary first,
	// confirm, then the bundle. Never the reverse.
	EvidenceProducers []string `json:"evidence_producers"`
	FindingCount      int      `json:"finding_count"`
}

// RequestInput describes who is asking.
type RequestInput struct {
	// Automated is true when GRIEFER itself initiated the request rather than a
	// human operator. The policy holds automated requests to a higher bar.
	Automated   bool   `json:"automated"`
	RequestedBy string `json:"requested_by"`
}

// Input is the complete decision request.
type Input struct {
	Action   ActionInput   `json:"action"`
	Incident IncidentInput `json:"incident"`
	Request  RequestInput  `json:"request"`
}

// Kernel evaluates response authorization requests.
type Kernel interface {
	// Evaluate returns the policy decision for in.
	//
	// The returned decision is ALWAYS safe to act on, including when err is
	// non-nil: on any failure the decision is a fail-closed deny. Callers
	// should still surface err, because a degraded kernel is itself an
	// operational signal.
	Evaluate(ctx context.Context, in Input) (incidents.PolicyDecision, error)
	// Health reports whether the kernel can currently evaluate policy.
	Health(ctx context.Context) error
	// Engine names the implementation, for the audit trail.
	Engine() string
	// Close releases resources held by the kernel.
	Close() error
}

// failClosed builds the deny decision returned whenever policy cannot be
// evaluated normally.
func failClosed(engine, reason string, at time.Time) incidents.PolicyDecision {
	return incidents.PolicyDecision{
		Effect:        EffectDeny,
		Allow:         false,
		Reasons:       []string{reason},
		PolicyPackage: policies.Package,
		PolicyVersion: policies.Version,
		EvaluatedAt:   at.UTC(),
		FailClosed:    true,
		Engine:        engine,
	}
}

// rawDecision is the shape the Rego decision document is decoded into.
type rawDecision struct {
	Effect                string   `json:"effect"`
	Allow                 bool     `json:"allow"`
	Reasons               []string `json:"reasons"`
	PolicyPackage         string   `json:"policy_package"`
	PolicyVersion         string   `json:"policy_version"`
	EvidenceCategoryCount int      `json:"evidence_category_count"`
}

// toDecision converts a decoded Rego document into a domain decision,
// rejecting anything that does not look like a well-formed verdict.
//
// This is the last line of defence: if a policy bundle were ever swapped for
// one that returns an unrecognised effect, GRIEFER denies rather than guessing.
func (r rawDecision) toDecision(engine string, at time.Time) (incidents.PolicyDecision, bool) {
	switch r.Effect {
	case EffectAllow, EffectDeny, EffectRequireApproval:
	default:
		return incidents.PolicyDecision{}, false
	}
	if r.Effect == EffectAllow && !r.Allow {
		return incidents.PolicyDecision{}, false
	}
	if r.Effect != EffectAllow && r.Allow {
		return incidents.PolicyDecision{}, false
	}
	if len(r.Reasons) == 0 {
		return incidents.PolicyDecision{}, false
	}
	pkg := r.PolicyPackage
	if pkg == "" {
		pkg = policies.Package
	}
	version := r.PolicyVersion
	if version == "" {
		version = "unknown"
	}
	return incidents.PolicyDecision{
		Effect:        r.Effect,
		Allow:         r.Allow,
		Reasons:       r.Reasons,
		PolicyPackage: pkg,
		PolicyVersion: version,
		// The count the policy itself reported. It was decoded and then dropped,
		// so the audit trail recorded a verdict without the number the verdict
		// turned on — and a reader could not tell a two-category allow from a
		// five-category one.
		EvidenceCategoryCount: r.EvidenceCategoryCount,
		EvaluatedAt:           at.UTC(),
		FailClosed:            false,
		Engine:                engine,
	}, true
}
