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

	SaveEvent(ctx context.Context, ev *events.SecurityEvent) error
	ListEvents(ctx context.Context, limit, offset int) ([]*events.SecurityEvent, int, error)
	CountEvents(ctx context.Context) (int, error)

	SaveIncident(ctx context.Context, inc *incidents.Incident) error
	GetIncident(ctx context.Context, id string) (*incidents.Incident, error)
	ListIncidents(ctx context.Context, filter IncidentFilter) ([]*incidents.Incident, int, error)

	SaveAction(ctx context.Context, action *incidents.ResponseAction) error
	GetAction(ctx context.Context, id string) (*incidents.ResponseAction, error)
	ListActions(ctx context.Context, incidentID string, limit, offset int) ([]*incidents.ResponseAction, int, error)

	// Ping reports whether the backing store is reachable.
	Ping(ctx context.Context) error
	// Close releases held resources.
	Close() error
	// Kind names the implementation for health reporting.
	Kind() string
}
