// Package audit records why GRIEFER did what it did.
//
// The audit trail is append-only at the application level: the Sink interface
// exposes Append and List and nothing else, and no code path in the platform
// can update or delete an entry.
//
// Entries are also hash-chained — each one carries its predecessor's hash, and
// GET /api/v1/audit/verify recomputes the links. That detects alteration; it
// does not prove authenticity, because the chain is stored in the same database
// as the entries and no secret enters the computation, so a role that can
// rewrite the table can recompute the chain with it. Anchoring the chain head
// to storage under a different authority is what would close that, and it has
// not shipped. See chain.go, docs/SAFETY_MODEL.md and
// docs/adr/0007-hash-chained-audit-without-anchor.md.
package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/idgen"
)

// Action names every auditable operation. Using a closed set keeps the trail
// queryable and stops callers inventing near-duplicate verbs.
const (
	ActionEventIngested       = "event.ingested"
	ActionEventRejected       = "event.rejected"
	ActionEventQuarantined    = "event.label_quarantined"
	ActionIncidentCreated     = "incident.created"
	ActionIncidentUpdated     = "incident.updated"
	ActionPolicyEvaluated     = "policy.evaluated"
	ActionActionSimulated     = "response.simulated"
	ActionActionDenied        = "response.denied"
	ActionActionRejected      = "response.rejected"
	ActionActionNeedsApproval = "response.requires_approval"
	ActionCorrelationFailed   = "correlation.failed"
	ActionSystemStarted       = "system.started"
	ActionSystemStopped       = "system.stopped"
)

// Results of a response-action evaluation, recorded in Details["result"].
//
// Outcome above answers "did this succeed"; Result answers "what happened",
// and the two are not the same question. A denial and a policy timeout are both
// OutcomeDenied — GRIEFER fails closed, so an unreachable Policy Kernel refuses
// the action exactly as a deliberate refusal does. Reading only the outcome,
// those are indistinguishable, and a platform that cannot tell a considered
// refusal from a broken dependency cannot be operated.
const (
	ResultAllowed                = "allowed"
	ResultRequiresApproval       = "requires_approval"
	ResultDenied                 = "denied"
	ResultInvalidAction          = "invalid_action"
	ResultInsufficientPermission = "insufficient_permission"
	ResultValidationFailed       = "validation_failed"
	ResultPolicyUnavailable      = "policy_unavailable"
	ResultPolicyTimeout          = "policy_timeout"
	ResultPersistenceFailed      = "persistence_failed"
	ResultInternalError          = "internal_error"
)

// Outcomes recorded on an entry.
const (
	OutcomeSuccess = "success"
	OutcomeDenied  = "denied"
	OutcomeFailure = "failure"
	OutcomePending = "pending"
)

// Subject types.
const (
	SubjectEvent    = "event"
	SubjectIncident = "incident"
	SubjectAction   = "action"
	SubjectSystem   = "system"
)

// Entry is one immutable record of a decision or state change.
//
// Entries must never carry secret material. Details is for identifiers,
// verdicts and counts — the things needed to reconstruct a decision — not for
// tokens, credentials or raw telemetry payloads.
type Entry struct {
	ID        string    `json:"id"`
	Sequence  int64     `json:"sequence"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	// ActorRole is the role the actor held when the entry was written.
	//
	// Stored beside the actor rather than looked up when the trail is read,
	// because a role can change: an account demoted next week must not
	// retroactively appear to have been an analyst when it acted as an
	// administrator. The trail records what was true at the time.
	ActorRole   string         `json:"actor_role,omitempty"`
	Action      string         `json:"action"`
	SubjectType string         `json:"subject_type"`
	SubjectID   string         `json:"subject_id"`
	Outcome     string         `json:"outcome"`
	Reason      string         `json:"reason"`
	RequestID   string         `json:"request_id,omitempty"`
	Details     map[string]any `json:"details,omitempty"`

	// ChainID, PrevHash and EntryHash are store state, not caller input.
	//
	// Prepare zeroes all three and the store stamps them back onto the caller's
	// entry, the same way Sequence already is. A caller does not get to name
	// its own predecessor: if it could, an entry could be spliced into the
	// chain at a position of the writer's choosing.
	//
	// All three are empty on an entry written before the chain existed, which
	// reads as OUTSIDE the chain — not as verified, and not as broken.
	ChainID   string `json:"chain_id,omitempty"`
	PrevHash  string `json:"prev_hash,omitempty"`
	EntryHash string `json:"entry_hash,omitempty"`
}

// Sink is the append-only persistence surface for audit entries.
//
// The interface deliberately has no Update and no Delete. Extending it with
// either would break the guarantee this package exists to provide.
type Sink interface {
	Append(ctx context.Context, entry *Entry) error
	List(ctx context.Context, limit, offset int) ([]*Entry, int, error)
}

// Recorder stamps and writes audit entries.
type Recorder struct {
	sink Sink
	now  func() time.Time
}

// NewRecorder returns a Recorder writing to sink.
func NewRecorder(sink Sink) (*Recorder, error) {
	if sink == nil {
		return nil, fmt.Errorf("audit: sink is required")
	}
	return &Recorder{sink: sink, now: func() time.Time { return time.Now().UTC() }}, nil
}

// NewRecorderWithClock returns a Recorder with an injected clock, for tests.
func NewRecorderWithClock(sink Sink, now func() time.Time) (*Recorder, error) {
	r, err := NewRecorder(sink)
	if err != nil {
		return nil, err
	}
	if now != nil {
		r.now = now
	}
	return r, nil
}

// Prepare validates entry and stamps it with an identity and timestamp,
// WITHOUT writing it.
//
// This exists so that a caller can build the entries for an operation, hand
// them to a store that writes them inside the same transaction as the thing
// they describe, and still get the same validation and stamping every entry
// gets. Without it, atomic callers would have to duplicate the rules here —
// and the copy would drift.
func (r *Recorder) Prepare(entry Entry) (*Entry, error) {
	if entry.Action == "" {
		return nil, fmt.Errorf("audit: action is required")
	}
	if entry.Outcome == "" {
		return nil, fmt.Errorf("audit: outcome is required")
	}
	entry.ID = idgen.New(idgen.PrefixAudit)
	// Truncated at the point of stamping rather than left to each store.
	// TIMESTAMPTZ holds microseconds and time.Time holds nanoseconds, so
	// without this the memory store keeps a precision PostgreSQL discards and
	// the two stores return different timestamps for the same entry — a
	// divergence the conformance suite exists to prevent, and one the chain
	// would turn into a hash that only agrees with itself on one store.
	entry.Timestamp = r.now().UTC().Truncate(time.Microsecond)
	if entry.Actor == "" {
		entry.Actor = "system:griefer"
	}
	// The chain is store state. Whatever a caller put here is not a claim it is
	// entitled to make.
	entry.ChainID, entry.PrevHash, entry.EntryHash = "", "", ""
	SanitiseEntry(&entry)
	entry.Details = boundDetails(entry.Details)
	return &entry, nil
}

// Record assigns an identity and timestamp to entry and appends it.
//
// A failure to write audit is returned to the caller rather than swallowed.
// Whether an operation may proceed without its audit record is a policy
// question, and it belongs to the caller that knows what the operation was.
func (r *Recorder) Record(ctx context.Context, entry Entry) (*Entry, error) {
	prepared, err := r.Prepare(entry)
	if err != nil {
		return nil, err
	}
	if err := r.sink.Append(ctx, prepared); err != nil {
		return nil, fmt.Errorf("audit: append entry: %w", err)
	}
	return prepared, nil
}

// List returns audit entries in insertion order, oldest first.
func (r *Recorder) List(ctx context.Context, limit, offset int) ([]*Entry, int, error) {
	return r.sink.List(ctx, limit, offset)
}
