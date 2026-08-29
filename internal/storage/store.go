// Package storage persists GRIEFER's events, incidents, response actions and
// audit trail.
//
// Two implementations satisfy the same interface: an in-memory store used by
// tests and by `GRIEFER_STORAGE_POSTGRES=false`, and a PostgreSQL store used by
// the Compose stack. Both are exercised by the same test suite so the memory
// store cannot quietly diverge into a more forgiving fake.
package storage

import (
	"context"
	"errors"

	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
)

// EventSaveResult reports what SaveEvent did.
type EventSaveResult struct {
	// Stored is false when an event with this id was already present.
	Stored bool
	// ExistingProducerID names the producer credited with the row already
	// present. Empty when Stored is true, and empty for a row written before
	// producers were enrolled — which reads as "unattributed", not as "the same
	// producer".
	ExistingProducerID string
}

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("record not found")

// DefaultPageSize and MaxPageSize bound list endpoints. An unbounded list is a
// denial-of-service primitive against both the database and the client.
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
)

// IncidentFilter narrows an incident listing.
type IncidentFilter struct {
	Status       string
	Severity     string
	MinRiskScore int
	Limit        int
	Offset       int
}

// Normalize clamps the filter's pagination to safe bounds.
func (f IncidentFilter) Normalize() IncidentFilter {
	f.Limit = ClampLimit(f.Limit)
	if f.Offset < 0 {
		f.Offset = 0
	}
	if f.MinRiskScore < 0 {
		f.MinRiskScore = 0
	}
	return f
}

// ClampLimit brings a requested page size into range.
func ClampLimit(limit int) int {
	switch {
	case limit <= 0:
		return DefaultPageSize
	case limit > MaxPageSize:
		return MaxPageSize
	default:
		return limit
	}
}

// Store is GRIEFER's persistence surface.
//
// It embeds audit.Sink rather than exposing generic audit CRUD: the audit trail
// has no update and no delete, and the type system is where that is enforced.
type Store interface {
	audit.Sink

	// SaveEvent persists an event and reports what happened to it.
	//
	// It returns a result rather than an error alone because ingestion is
	// idempotent on event id, and both stores used to implement that by
	// discarding a repeat and returning nil — so the caller could not tell a
	// stored event from a discarded one and carried on correlating either way.
	// Re-POSTing one event id therefore fired threshold rules on evidence the
	// database does not hold.
	//
	// The result also names the producer that stored the row already present,
	// because a repeat from a DIFFERENT producer is not a retry. Event ids are
	// producer-supplied and a real connector derives them from the upstream
	// system, so they are predictable — and a producer that pre-registers an id
	// its neighbour will later use makes that neighbour's genuine event vanish
	// as a duplicate. Evidence suppression, from inside the trust boundary,
	// with no trace unless the two are told apart.
	SaveEvent(ctx context.Context, ev *events.SecurityEvent) (EventSaveResult, error)
	ListEvents(ctx context.Context, limit, offset int) ([]*events.SecurityEvent, int, error)
	CountEvents(ctx context.Context) (int, error)

	SaveIncident(ctx context.Context, inc *incidents.Incident) error
	GetIncident(ctx context.Context, id string) (*incidents.Incident, error)
	ListIncidents(ctx context.Context, filter IncidentFilter) ([]*incidents.Incident, int, error)

	SaveAction(ctx context.Context, action *incidents.ResponseAction) error
	GetAction(ctx context.Context, id string) (*incidents.ResponseAction, error)
	ListActions(ctx context.Context, incidentID string, limit, offset int) ([]*incidents.ResponseAction, int, error)

	// SaveActionWithAudit persists a response action together with the audit
	// entries describing its evaluation, as one unit. Either all of it is
	// durable or none of it is.
	//
	// This is on the interface rather than being an optional capability a
	// caller type-asserts for. An optional guarantee is one a caller silently
	// loses when a store does not implement it, and "the audit trail is
	// complete unless you happened to configure the other store" is not a
	// guarantee worth stating. A nil action writes only the entries, which is
	// the shape of an evaluation rejected before any action exists.
	SaveActionWithAudit(ctx context.Context, action *incidents.ResponseAction, entries []*audit.Entry) error

	// VerifyAuditChain recomputes the trail's links over the whole chain and
	// its content over a bounded window.
	//
	// The two checks are separated because they cost different things. Linkage
	// is one ordered scan comparing stored hashes to stored hashes; content has
	// to decode Details and recompute a hash per row. Collapsing them would
	// make the cheap check as expensive as the dear one, and the cheap one is
	// the one that catches deletion.
	//
	// On the interface for the reason SaveActionWithAudit gives above: an
	// integrity check a caller silently loses depending on which store was
	// configured is not a check worth stating.
	VerifyAuditChain(ctx context.Context, limit, offset int) (*AuditChainReport, error)

	// IssueAuditAnchor returns a commitment to the trail's current head, for the
	// operator to keep outside this database.
	//
	// On the interface rather than beside it for the reason above: an integrity
	// control a caller silently loses depending on which store was configured is
	// not a control worth stating.
	IssueAuditAnchor(ctx context.Context) (*AuditAnchor, error)

	// CheckAuditAnchor compares a previously issued anchor against the trail.
	//
	// This is the only check in the platform that can catch a consistent rewrite
	// of the whole chain, because it is the only one whose reference value did
	// not come out of the database being checked.
	CheckAuditAnchor(ctx context.Context, anchor AuditAnchor) (*AuditAnchorReport, error)

	// Ping reports whether the backing store is reachable.
	Ping(ctx context.Context) error
	// Close releases held resources.
	Close() error
	// Kind names the implementation for health reporting.
	Kind() string
}
