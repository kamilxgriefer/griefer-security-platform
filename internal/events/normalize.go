package events

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/idgen"
)

// Ingest-time clock policy. Timestamps are producer-controlled, so they are
// bounded on both sides: a far-future timestamp would keep an incident
// artificially "current" and a very old one would let an attacker replay stale
// telemetry into a live incident.
const (
	// MaxClockSkewAhead is how far ahead of the receiver a source timestamp may
	// be before the event is rejected.
	MaxClockSkewAhead = 5 * time.Minute
	// MaxEventAge is the oldest source timestamp accepted by the ingest API.
	MaxEventAge = 30 * 24 * time.Hour
)

// ErrTimestampOutOfRange is returned when an event's source timestamp falls
// outside the accepted ingest window.
var ErrTimestampOutOfRange = errors.New("event timestamp outside accepted ingest window")

// Normalizer applies GRIEFER's ingest-time normalization rules. It carries an
// injectable clock so that tests are deterministic.
type Normalizer struct {
	now func() time.Time
}

// NewNormalizer returns a Normalizer driven by the wall clock.
func NewNormalizer() *Normalizer {
	return &Normalizer{now: func() time.Time { return time.Now().UTC() }}
}

// NewNormalizerWithClock returns a Normalizer driven by now, for tests.
func NewNormalizerWithClock(now func() time.Time) *Normalizer {
	return &Normalizer{now: now}
}

// Normalize brings a schema-valid event into GRIEFER's canonical form:
// server-assigned identity and receipt time, UTC timestamps, trimmed strings,
// and control-plane labels quarantined.
//
// Normalize mutates ev in place and returns it for convenience.
func (n *Normalizer) Normalize(ev *SecurityEvent) (*SecurityEvent, error) {
	if ev == nil {
		return nil, errors.New("normalize: nil event")
	}
	now := n.now().UTC()

	if ev.Timestamp.IsZero() {
		return nil, fmt.Errorf("%w: timestamp is required", ErrTimestampOutOfRange)
	}
	ev.Timestamp = ev.Timestamp.UTC()
	if ev.Timestamp.After(now.Add(MaxClockSkewAhead)) {
		return nil, fmt.Errorf("%w: more than %s in the future", ErrTimestampOutOfRange, MaxClockSkewAhead)
	}
	if ev.Timestamp.Before(now.Add(-MaxEventAge)) {
		return nil, fmt.Errorf("%w: older than %s", ErrTimestampOutOfRange, MaxEventAge)
	}

	// received_at is server-owned. Anything a producer supplied is discarded.
	ev.ReceivedAt = now

	if ev.ID == "" {
		ev.ID = idgen.New(idgen.PrefixEvent)
	}
	if ev.SchemaVersion == "" {
		ev.SchemaVersion = SchemaVersion
	}

	ev.SourceName = strings.TrimSpace(ev.SourceName)
	ev.EventType = strings.TrimSpace(ev.EventType)
	ev.CorrelationID = strings.TrimSpace(ev.CorrelationID)

	if ev.Actor != nil {
		ev.Actor.ID = strings.TrimSpace(ev.Actor.ID)
		ev.Actor.Name = strings.TrimSpace(ev.Actor.Name)
		ev.Actor.Domain = strings.ToLower(strings.TrimSpace(ev.Actor.Domain))
		ev.Actor.SessionID = strings.TrimSpace(ev.Actor.SessionID)
	}
	if ev.Target != nil {
		ev.Target.ID = strings.TrimSpace(ev.Target.ID)
		ev.Target.Name = strings.TrimSpace(ev.Target.Name)
		if ev.Target.Criticality == "" {
			ev.Target.Criticality = "medium"
		}
	}
	if ev.Device != nil {
		ev.Device.Hostname = strings.ToLower(strings.TrimSpace(ev.Device.Hostname))
		ev.Device.ID = strings.TrimSpace(ev.Device.ID)
	}
	if ev.Network != nil {
		ev.Network.SourceIP = strings.TrimSpace(ev.Network.SourceIP)
		ev.Network.DestinationIP = strings.TrimSpace(ev.Network.DestinationIP)
		ev.Network.Country = strings.ToUpper(strings.TrimSpace(ev.Network.Country))
	}

	// Control-plane guard runs last so it also covers labels that survived
	// trimming.
	Sanitize(ev)

	if ev.CorrelationID == "" {
		ev.CorrelationID = ev.ID
	}
	return ev, nil
}
