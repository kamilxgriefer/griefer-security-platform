package storage

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
)

// MemoryStore keeps everything in process memory.
//
// It exists for two reasons: tests need a deterministic store with no external
// dependency, and a first-run demo should not require a database. It is not a
// deployment option — data is lost on restart, and that is stated wherever the
// option is exposed.
type MemoryStore struct {
	mu sync.RWMutex

	events []*events.SecurityEvent
	// eventIDs mirrors the ids currently held so that re-ingesting a known
	// event is a no-op, matching the PostgreSQL store's ON CONFLICT DO NOTHING.
	eventIDs  map[string]struct{}
	incidents map[string]*incidents.Incident
	// incidentOrder preserves first-creation order so listings are stable when
	// several incidents share a timestamp.
	incidentOrder []string
	actions       map[string]*incidents.ResponseAction
	actionOrder   []string
	auditLog      []*audit.Entry
	auditSeq      int64

	// maxEvents bounds retention. An in-memory store with unbounded growth is
	// an availability bug waiting for a busy day.
	maxEvents int
}

// NewMemoryStore returns an empty in-memory store retaining at most maxEvents
// events. A non-positive maxEvents applies the default.
func NewMemoryStore(maxEvents int) *MemoryStore {
	if maxEvents <= 0 {
		maxEvents = 10000
	}
	return &MemoryStore{
		eventIDs:  make(map[string]struct{}),
		incidents: make(map[string]*incidents.Incident),
		actions:   make(map[string]*incidents.ResponseAction),
		maxEvents: maxEvents,
	}
}

// Kind implements Store.
func (s *MemoryStore) Kind() string { return "memory" }

// Ping implements Store.
func (s *MemoryStore) Ping(context.Context) error { return nil }

// Close implements Store.
func (s *MemoryStore) Close() error { return nil }

// SaveEvent implements Store.
func (s *MemoryStore) SaveEvent(_ context.Context, ev *events.SecurityEvent) error {
	if ev == nil || ev.ID == "" {
		return fmt.Errorf("storage: event requires an id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.eventIDs[ev.ID]; exists {
		// Producers retry. A retry storm must not become a duplicate storm.
		return nil
	}
	clone := *ev
	s.events = append(s.events, &clone)
	s.eventIDs[ev.ID] = struct{}{}
	if len(s.events) > s.maxEvents {
		dropped := s.events[:len(s.events)-s.maxEvents]
		for _, old := range dropped {
			delete(s.eventIDs, old.ID)
		}
		s.events = s.events[len(s.events)-s.maxEvents:]
	}
	return nil
}

// ListEvents implements Store, returning newest first.
func (s *MemoryStore) ListEvents(_ context.Context, limit, offset int) ([]*events.SecurityEvent, int, error) {
	limit = ClampLimit(limit)
	if offset < 0 {
		offset = 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.events)
	ordered := make([]*events.SecurityEvent, total)
	for i, ev := range s.events {
		ordered[total-1-i] = ev
	}
	if offset >= total {
		return []*events.SecurityEvent{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := make([]*events.SecurityEvent, 0, end-offset)
	for _, ev := range ordered[offset:end] {
		clone := *ev
		page = append(page, &clone)
	}
	return page, total, nil
}

// CountEvents implements Store.
func (s *MemoryStore) CountEvents(context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events), nil
}

// SaveIncident implements Store.
func (s *MemoryStore) SaveIncident(_ context.Context, inc *incidents.Incident) error {
	if inc == nil || inc.ID == "" {
		return fmt.Errorf("storage: incident requires an id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.incidents[inc.ID]; !exists {
		s.incidentOrder = append(s.incidentOrder, inc.ID)
	}
	clone := deepCopyIncident(inc)
	s.incidents[inc.ID] = clone
	return nil
}

// GetIncident implements Store.
func (s *MemoryStore) GetIncident(_ context.Context, id string) (*incidents.Incident, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inc, ok := s.incidents[id]
	if !ok {
		return nil, ErrNotFound
	}
	return deepCopyIncident(inc), nil
}

// ListIncidents implements Store, returning most recently active first.
func (s *MemoryStore) ListIncidents(_ context.Context, filter IncidentFilter) ([]*incidents.Incident, int, error) {
	filter = filter.Normalize()
	s.mu.RLock()
	defer s.mu.RUnlock()

	matched := make([]*incidents.Incident, 0, len(s.incidentOrder))
	for _, id := range s.incidentOrder {
		inc := s.incidents[id]
		if inc == nil {
			continue
		}
		if filter.Status != "" && string(inc.Status) != filter.Status {
			continue
		}
		if filter.Severity != "" && string(inc.Severity) != filter.Severity {
			continue
		}
		if inc.RiskScore < filter.MinRiskScore {
			continue
		}
		matched = append(matched, inc)
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if !matched[i].LastSeen.Equal(matched[j].LastSeen) {
			return matched[i].LastSeen.After(matched[j].LastSeen)
		}
		return matched[i].ID > matched[j].ID
	})

	total := len(matched)
	if filter.Offset >= total {
		return []*incidents.Incident{}, total, nil
	}
	end := filter.Offset + filter.Limit
	if end > total {
		end = total
	}
	page := make([]*incidents.Incident, 0, end-filter.Offset)
	for _, inc := range matched[filter.Offset:end] {
		page = append(page, deepCopyIncident(inc))
	}
	return page, total, nil
}

// SaveAction implements Store.
func (s *MemoryStore) SaveAction(_ context.Context, action *incidents.ResponseAction) error {
	if action == nil || action.ID == "" {
		return fmt.Errorf("storage: response action requires an id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveActionLocked(action)
	return nil
}

// saveActionLocked assumes the caller holds the write lock.
func (s *MemoryStore) saveActionLocked(action *incidents.ResponseAction) {
	if _, exists := s.actions[action.ID]; !exists {
		s.actionOrder = append(s.actionOrder, action.ID)
	}
	s.actions[action.ID] = deepCopyAction(action)
}

// SaveActionWithAudit implements Store.
//
// The memory store has no transactions, so atomicity is provided by validating
// everything before mutating anything and then doing all the writes under a
// single lock. That is a genuinely equivalent guarantee here: no other
// goroutine can observe a half-applied state, and nothing can fail midway
// because the only failures are the validation this does up front.
//
// It matters that the two implementations agree. The shared conformance suite
// runs the same atomicity tests against both, so a rule that holds only in
// PostgreSQL would be caught rather than discovered in production.
func (s *MemoryStore) SaveActionWithAudit(_ context.Context, action *incidents.ResponseAction, entries []*audit.Entry) error {
	if action != nil && action.ID == "" {
		return fmt.Errorf("storage: response action requires an id")
	}
	for _, entry := range entries {
		if entry == nil || entry.ID == "" {
			return fmt.Errorf("storage: audit entry requires an id")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if action != nil {
		s.saveActionLocked(action)
	}
	for _, entry := range entries {
		s.appendAuditLocked(entry)
	}
	return nil
}

// GetAction implements Store.
func (s *MemoryStore) GetAction(_ context.Context, id string) (*incidents.ResponseAction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	action, ok := s.actions[id]
	if !ok {
		return nil, ErrNotFound
	}
	return deepCopyAction(action), nil
}

// ListActions implements Store, newest first, optionally scoped to an incident.
func (s *MemoryStore) ListActions(_ context.Context, incidentID string, limit, offset int) ([]*incidents.ResponseAction, int, error) {
	limit = ClampLimit(limit)
	if offset < 0 {
		offset = 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	matched := make([]*incidents.ResponseAction, 0, len(s.actionOrder))
	for i := len(s.actionOrder) - 1; i >= 0; i-- {
		action := s.actions[s.actionOrder[i]]
		if action == nil {
			continue
		}
		if incidentID != "" && action.IncidentID != incidentID {
			continue
		}
		matched = append(matched, action)
	}
	total := len(matched)
	if offset >= total {
		return []*incidents.ResponseAction{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := make([]*incidents.ResponseAction, 0, end-offset)
	for _, a := range matched[offset:end] {
		page = append(page, deepCopyAction(a))
	}
	return page, total, nil
}

// Append implements audit.Sink. Entries are only ever appended; there is no
// code path in this type that mutates or removes one.
func (s *MemoryStore) Append(_ context.Context, entry *audit.Entry) error {
	if entry == nil || entry.ID == "" {
		return fmt.Errorf("storage: audit entry requires an id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appendAuditLocked(entry)
	return nil
}

// appendAuditLocked assumes the caller holds the write lock.
func (s *MemoryStore) appendAuditLocked(entry *audit.Entry) {
	s.auditSeq++
	clone := deepCopyAuditEntry(entry)
	clone.Sequence = s.auditSeq
	entry.Sequence = s.auditSeq
	s.auditLog = append(s.auditLog, clone)
}

// deepCopyAuditEntry severs every reference the caller could still hold.
//
// A struct copy is not enough: Details is a map, so `clone := *entry` leaves
// the stored entry sharing the caller's map header. Anyone keeping their
// pointer could then rewrite a committed entry — turning a denial into an
// approval — without calling the store at all, which defeats the append-only
// guarantee the PostgreSQL trigger exists to provide. PostgreSQL is immune
// because it marshals Details to JSON at write time; the memory store has to
// copy deliberately.
//
// Values inside Details are not themselves cloned. They are identifiers,
// verdicts and counts by contract (see internal/audit), and a deep clone of
// arbitrary any-typed values would need reflection for a case this package
// does not accept in the first place.
func deepCopyAuditEntry(in *audit.Entry) *audit.Entry {
	out := *in
	if in.Details != nil {
		out.Details = make(map[string]any, len(in.Details))
		for k, v := range in.Details {
			out.Details[k] = v
		}
	}
	return &out
}

// List implements audit.Sink, returning entries oldest first so the sequence
// reads as a narrative.
func (s *MemoryStore) List(_ context.Context, limit, offset int) ([]*audit.Entry, int, error) {
	limit = ClampLimit(limit)
	if offset < 0 {
		offset = 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.auditLog)
	if offset >= total {
		return []*audit.Entry{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := make([]*audit.Entry, 0, end-offset)
	for _, e := range s.auditLog[offset:end] {
		// Copied on the way out for the same reason as on the way in: a reader
		// handed a live reference could edit the trail it was given to read.
		page = append(page, deepCopyAuditEntry(e))
	}
	return page, total, nil
}

// deepCopyIncident isolates stored state from caller mutation. Without it a
// handler that tweaks a returned incident would silently rewrite history.
func deepCopyIncident(in *incidents.Incident) *incidents.Incident {
	if in == nil {
		return nil
	}
	out := *in
	out.Findings = append([]incidents.Finding(nil), in.Findings...)
	for i := range out.Findings {
		out.Findings[i].EventIDs = append([]string(nil), in.Findings[i].EventIDs...)
		out.Findings[i].EntityIDs = append([]string(nil), in.Findings[i].EntityIDs...)
		out.Findings[i].Techniques = append([]incidents.Technique(nil), in.Findings[i].Techniques...)
	}
	out.Entities = append([]incidents.EntityRef(nil), in.Entities...)
	out.AttackTechniques = append([]incidents.Technique(nil), in.AttackTechniques...)
	out.RecommendedActions = append([]incidents.RecommendedAction(nil), in.RecommendedActions...)
	out.Evidence = append([]incidents.Evidence(nil), in.Evidence...)
	out.BlastRadius.Reachable = append([]graphReachable(nil), in.BlastRadius.Reachable...)
	return &out
}

func deepCopyAction(in *incidents.ResponseAction) *incidents.ResponseAction {
	if in == nil {
		return nil
	}
	out := *in
	if in.PolicyDecision != nil {
		decision := *in.PolicyDecision
		decision.Reasons = append([]string(nil), in.PolicyDecision.Reasons...)
		out.PolicyDecision = &decision
	}
	if in.Simulated != nil {
		effect := *in.Simulated
		effect.AffectedEntities = append([]string(nil), in.Simulated.AffectedEntities...)
		out.Simulated = &effect
	}
	if in.ExecutedAt != nil {
		executed := *in.ExecutedAt
		out.ExecutedAt = &executed
	}
	return &out
}
