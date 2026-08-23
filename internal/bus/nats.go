package bus

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
)

// NATSPublisher publishes events to a NATS JetStream stream.
type NATSPublisher struct {
	conn    *nats.Conn
	js      jetstream.JetStream
	subject string
	stream  string
}

// NATSOptions configures the JetStream publisher.
type NATSOptions struct {
	URL     string
	Stream  string
	Subject string
	// ConnectTimeout bounds the initial connection.
	ConnectTimeout time.Duration
	// MaxAge bounds how long the stream retains events.
	MaxAge time.Duration
}

// NewNATSPublisher connects to NATS and ensures the stream exists.
func NewNATSPublisher(ctx context.Context, opts NATSOptions) (*NATSPublisher, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("bus: NATS URL is required")
	}
	if opts.Subject == "" {
		return nil, fmt.Errorf("bus: NATS subject is required")
	}
	if opts.Stream == "" {
		return nil, fmt.Errorf("bus: NATS stream is required")
	}
	connectTimeout := opts.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = 5 * time.Second
	}
	maxAge := opts.MaxAge
	if maxAge <= 0 {
		maxAge = 72 * time.Hour
	}

	conn, err := nats.Connect(opts.URL,
		nats.Name("griefer-api"),
		nats.Timeout(connectTimeout),
		// Reconnect quietly and indefinitely: a bus outage degrades GRIEFER,
		// it does not end the process.
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("bus: connect to NATS: %w", err)
	}

	js, err := jetstream.New(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("bus: initialise JetStream: %w", err)
	}

	setupCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	_, err = js.CreateOrUpdateStream(setupCtx, jetstream.StreamConfig{
		Name:        opts.Stream,
		Description: "GRIEFER normalized security events",
		Subjects:    []string{subjectWildcard(opts.Subject)},
		Retention:   jetstream.LimitsPolicy,
		Storage:     jetstream.FileStorage,
		MaxAge:      maxAge,
		// Bound the stream so a telemetry flood cannot fill the disk.
		MaxBytes: 1 << 30,
		Discard:  jetstream.DiscardOld,
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("bus: ensure stream %q: %w", opts.Stream, err)
	}

	return &NATSPublisher{conn: conn, js: js, subject: opts.Subject, stream: opts.Stream}, nil
}

// subjectWildcard widens a concrete subject to a token wildcard so that
// per-category subjects land in the same stream.
func subjectWildcard(subject string) string { return subject + ".>" }

// Publish implements Publisher. Events are published on a per-category subject
// so a consumer can subscribe to one evidence class without filtering.
func (p *NATSPublisher) Publish(ctx context.Context, ev *events.SecurityEvent) error {
	if ev == nil {
		return fmt.Errorf("bus: nil event")
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("bus: encode event: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, publishTimeout)
	defer cancel()

	subject := p.subject + "." + string(ev.Category)
	// The event id is the dedup key: a producer retry republishes the same id
	// and JetStream collapses it rather than duplicating the evidence.
	if _, err := p.js.Publish(ctx, subject, payload, jetstream.WithMsgID(ev.ID)); err != nil {
		return fmt.Errorf("bus: publish event: %w", err)
	}
	return nil
}

// Health implements Publisher.
func (p *NATSPublisher) Health(ctx context.Context) error {
	if !p.conn.IsConnected() {
		return fmt.Errorf("bus: NATS connection is not established (status %s)", p.conn.Status())
	}
	ctx, cancel := context.WithTimeout(ctx, publishTimeout)
	defer cancel()
	if _, err := p.js.Stream(ctx, p.stream); err != nil {
		return fmt.Errorf("bus: stream %q unavailable: %w", p.stream, err)
	}
	return nil
}

// Kind implements Publisher.
func (p *NATSPublisher) Kind() string { return "nats-jetstream" }

// Close implements Publisher, draining in-flight publishes first.
func (p *NATSPublisher) Close() error {
	if err := p.conn.Drain(); err != nil {
		p.conn.Close()
		return fmt.Errorf("bus: drain NATS connection: %w", err)
	}
	return nil
}
