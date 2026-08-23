// Package audit records why GRIEFER did what it did.
//
// The audit trail is append-only at the application level in v0.1: the Sink
// interface exposes Append and List and nothing else, and no code path in the
// platform can update or delete an entry. That is a design constraint, not a
// cryptographic guarantee — anyone with database access can still rewrite
// history. Making the trail tamper-EVIDENT (hash chaining each entry to its
// predecessor and periodically anchoring the chain) is milestone M4; the plan
// is written up in docs/SAFETY_MODEL.md.
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
	ID          string         `json:"id"`
	Sequence    int64          `json:"sequence"`
	Timestamp   time.Time      `json:"timestamp"`
	Actor       string         `json:"actor"`
	Action      string         `json:"action"`
	SubjectType string         `json:"subject_type"`
	SubjectID   string         `json:"subject_id"`
	Outcome     string         `json:"outcome"`
	Reason      string         `json:"reason"`
	RequestID   string         `json:"request_id,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
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

// Record assigns an identity and timestamp to entry and appends it.
//
// A failure to write audit is returned to the caller rather than swallowed.
// Whether an operation may proceed without its audit record is a policy
// question, and it belongs to the caller that knows what the operation was.
func (r *Recorder) Record(ctx context.Context, entry Entry) (*Entry, error) {
	if entry.Action == "" {
		return nil, fmt.Errorf("audit: action is required")
	}
	if entry.Outcome == "" {
		return nil, fmt.Errorf("audit: outcome is required")
	}
	entry.ID = idgen.New(idgen.PrefixAudit)
	entry.Timestamp = r.now().UTC()
	if entry.Actor == "" {
		entry.Actor = "system:griefer"
	}
	if err := r.sink.Append(ctx, &entry); err != nil {
		return nil, fmt.Errorf("audit: append entry: %w", err)
	}
	return &entry, nil
}

// List returns audit entries in insertion order, oldest first.
func (r *Recorder) List(ctx context.Context, limit, offset int) ([]*Entry, int, error) {
	return r.sink.List(ctx, limit, offset)
}
