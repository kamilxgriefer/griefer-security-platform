// Package bus publishes normalized events onto GRIEFER's event bus.
//
// The bus is deliberately not on the critical path of ingestion. Requirement:
// telemetry capture must keep working when downstream processing is degraded,
// because an attacker who can knock over the correlation path must not thereby
// blind the recorder. Every publisher here therefore reports failure without
// rejecting the event; the caller records the degradation and moves on.
package bus

import (
	"context"
	"sync"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
)

// Publisher publishes an event to interested subscribers.
type Publisher interface {
	// Publish delivers ev. An error means the event was not delivered; it never
	// means the event should be discarded.
	Publish(ctx context.Context, ev *events.SecurityEvent) error
	// Health reports whether the transport is currently usable.
	Health(ctx context.Context) error
	// Kind names the transport for health reporting.
	Kind() string
	// Close releases held resources.
	Close() error
}

// NoopPublisher drops events. It is the transport used when the bus is
// disabled, and it is honest about being a no-op rather than pretending to
// deliver.
type NoopPublisher struct {
	mu        sync.Mutex
	published int
}

// NewNoopPublisher returns a publisher that discards events.
func NewNoopPublisher() *NoopPublisher { return &NoopPublisher{} }

// Publish implements Publisher.
func (p *NoopPublisher) Publish(context.Context, *events.SecurityEvent) error {
	p.mu.Lock()
	p.published++
	p.mu.Unlock()
	return nil
}

// Published reports how many events were handed to this publisher.
func (p *NoopPublisher) Published() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.published
}

// Health implements Publisher.
func (p *NoopPublisher) Health(context.Context) error { return nil }

// Kind implements Publisher.
func (p *NoopPublisher) Kind() string { return "disabled" }

// Close implements Publisher.
func (p *NoopPublisher) Close() error { return nil }

// publishTimeout bounds a single publish so a stalled bus cannot hold an
// ingest request open.
const publishTimeout = 2 * time.Second
