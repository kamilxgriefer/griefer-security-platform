// Package incidents holds GRIEFER's investigation and response domain: the
// findings produced by detection logic, the incidents that group them, the
// catalog of response actions the platform is allowed to consider, and the
// record of what the Policy Kernel decided about each one.
package incidents

import (
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/graph"
)

// SchemaVersion is the incident representation version served by this build.
const SchemaVersion = "0.1"

// Technique is a MITRE ATT&CK reference carried as an annotation. GRIEFER
// records techniques to make an incident legible to analysts; it does not claim
// automated ATT&CK coverage measurement.
type Technique struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic,omitempty"`
}

// Finding is one detected security signal: the output of a single detection
// rule over one or more events.
type Finding struct {
	ID          string          `json:"id"`
	RuleID      string          `json:"rule_id"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Category    events.Category `json:"category"`
	Severity    events.Severity `json:"severity"`
	Confidence  float64         `json:"confidence"`
	Techniques  []Technique     `json:"techniques,omitempty"`
	EntityIDs   []string        `json:"entity_ids,omitempty"`
	EventIDs    []string        `json:"event_ids,omitempty"`
	FirstSeen   time.Time       `json:"first_seen"`
	LastSeen    time.Time       `json:"last_seen"`
}

// EntityRef is a lightweight reference to a graph entity, embedded in incident
// responses so a client does not need a second round trip to render context.
type EntityRef struct {
	ID          string            `json:"id"`
	Type        graph.EntityType  `json:"type"`
	Name        string            `json:"name,omitempty"`
	Criticality graph.Criticality `json:"criticality"`
}

// Evidence is a human-readable pointer back to a single source event.
type Evidence struct {
	EventID    string          `json:"event_id"`
	OccurredAt time.Time       `json:"occurred_at"`
	Category   events.Category `json:"category"`
	Summary    string          `json:"summary"`
	SourceName string          `json:"source_name"`
}

// Status is an incident's lifecycle state.
type Status string

// Incident lifecycle states.
const (
	StatusOpen          Status = "open"
	StatusInvestigating Status = "investigating"
	StatusContained     Status = "contained"
	StatusClosed        Status = "closed"
)

// RecommendedAction is a response GRIEFER proposes for an incident. It carries
// the safety metadata the Policy Kernel needs, resolved from the server-side
// catalog — never from telemetry and never from the client.
type RecommendedAction struct {
	ActionType           string `json:"action_type"`
	Title                string `json:"title"`
	Rationale            string `json:"rationale"`
	Reversible           bool   `json:"reversible"`
	Destructive          bool   `json:"destructive"`
	RollbackAction       string `json:"rollback_action,omitempty"`
	TargetEntityID       string `json:"target_entity_id,omitempty"`
	TargetsCriticalAsset bool   `json:"targets_critical_asset"`
}

// Incident is a correlated set of findings attributed to a single subject.
type Incident struct {
	ID                 string              `json:"id"`
	SchemaVersion      string              `json:"schema_version"`
	Title              string              `json:"title"`
	Status             Status              `json:"status"`
	Severity           events.Severity     `json:"severity"`
	RiskScore          int                 `json:"risk_score"`
	Confidence         float64             `json:"confidence"`
	FirstSeen          time.Time           `json:"first_seen"`
	LastSeen           time.Time           `json:"last_seen"`
	UpdatedAt          time.Time           `json:"updated_at"`
	PrimaryIdentity    string              `json:"primary_identity,omitempty"`
	Entities           []EntityRef         `json:"entities"`
	Findings           []Finding           `json:"findings"`
	AttackTechniques   []Technique         `json:"attack_techniques"`
	BlastRadius        graph.BlastRadius   `json:"blast_radius"`
	RecommendedActions []RecommendedAction `json:"recommended_actions"`
	Evidence           []Evidence          `json:"evidence"`
}

// EvidenceCategories returns the distinct evidence categories backing the
// incident, sorted. The Policy Kernel counts these to decide whether automation
// is permitted, so "how many independent kinds of evidence" is a first-class
// property of an incident rather than something recomputed ad hoc.
func (i *Incident) EvidenceCategories() []events.Category {
	seen := make(map[events.Category]bool, len(i.Findings))
	for _, f := range i.Findings {
		seen[f.Category] = true
	}
	out := make([]events.Category, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sortCategories(out)
	return out
}

func sortCategories(c []events.Category) {
	for i := 1; i < len(c); i++ {
		for j := i; j > 0 && c[j] < c[j-1]; j-- {
			c[j], c[j-1] = c[j-1], c[j]
		}
	}
}

// ---------------------------------------------------------------------------
// Response actions
// ---------------------------------------------------------------------------

// Mode is how a response action is to be carried out.
type Mode string

// Response modes. v0.1 implements ModeSimulate only; ModeExecute exists so the
// policy contract and the API surface are already shaped for real enforcement,
// and it is rejected at the API boundary until M3 lands a real actuator.
const (
	ModeSimulate Mode = "simulate"
	ModeExecute  Mode = "execute"
)

// Valid reports whether m is a known mode.
func (m Mode) Valid() bool { return m == ModeSimulate || m == ModeExecute }

// ActionStatus is the lifecycle state of a response action.
type ActionStatus string

// Response action states.
const (
	// ActionSimulated means policy allowed it and GRIEFER computed the effect
	// the action would have had. Nothing was changed in any external system.
	ActionSimulated ActionStatus = "simulated"
	// ActionRequiresApproval means policy requires a human decision.
	ActionRequiresApproval ActionStatus = "requires_approval"
	// ActionDenied means policy refused the action outright.
	ActionDenied ActionStatus = "denied"
	// ActionRejected means GRIEFER refused before policy evaluation, for
	// example an unknown action type.
	ActionRejected ActionStatus = "rejected"
)

// PolicyDecision is the Policy Kernel's verdict, recorded verbatim on the
// action so that a decision can be reconstructed and argued about later.
type PolicyDecision struct {
	Effect        string    `json:"effect"`
	Allow         bool      `json:"allow"`
	Reasons       []string  `json:"reasons"`
	PolicyPackage string    `json:"policy_package"`
	PolicyVersion string    `json:"policy_version"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
	// FailClosed is true when the decision was produced by GRIEFER's
	// fail-closed path because the Policy Kernel could not be reached.
	FailClosed bool `json:"fail_closed"`
	// Engine records which kernel produced the decision ("embedded", "remote"
	// or "unavailable").
	Engine string `json:"engine"`
}

// SimulatedEffect describes what a simulated action would have done. It is
// computed from the graph and the catalog; it never contacts an external system.
type SimulatedEffect struct {
	Description      string   `json:"description"`
	AffectedEntities []string `json:"affected_entities,omitempty"`
	RollbackPlan     string   `json:"rollback_plan"`
}

// ResponseAction is a proposed containment step and everything GRIEFER decided
// about it.
type ResponseAction struct {
	ID             string           `json:"id"`
	IncidentID     string           `json:"incident_id"`
	ActionType     string           `json:"action_type"`
	Mode           Mode             `json:"mode"`
	Status         ActionStatus     `json:"status"`
	RequestedBy    string           `json:"requested_by"`
	PolicyDecision *PolicyDecision  `json:"policy_decision,omitempty"`
	Reason         string           `json:"reason"`
	Reversible     bool             `json:"reversible"`
	Destructive    bool             `json:"destructive"`
	RollbackAction string           `json:"rollback_action,omitempty"`
	TargetEntityID string           `json:"target_entity_id,omitempty"`
	Simulated      *SimulatedEffect `json:"simulated_effect,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
	ExecutedAt     *time.Time       `json:"executed_at,omitempty"`
}
