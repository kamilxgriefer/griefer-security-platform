package bus_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/bus"
	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
)

func sampleEvent(id string) *events.SecurityEvent {
	return &events.SecurityEvent{
		ID: id, SchemaVersion: "0.1", Timestamp: time.Now().UTC(), ReceivedAt: time.Now().UTC(),
		SourceType: "identity_provider", SourceName: "bus-test", EventType: "user_signin",
		Category: events.CategoryAuthentication, Severity: events.SeverityMedium,
		Actor: &events.Actor{Type: "identity", ID: "u-1"},
	}
}

func TestNoopPublisherIsHonestAboutDroppingEvents(t *testing.T) {
	p := bus.NewNoopPublisher()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := p.Publish(ctx, sampleEvent("evt-1")); err != nil {
			t.Fatalf("Publish() error = %v", err)
		}
	}
	if p.Published() != 3 {
		t.Errorf("Published() = %d, want 3", p.Published())
	}
	if p.Kind() != "disabled" {
		t.Errorf("Kind() = %q, want \"disabled\"; the no-op transport must not claim to be a bus", p.Kind())
	}
	if err := p.Health(ctx); err != nil {
		t.Errorf("Health() error = %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestNATSPublisherValidatesOptions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tests := []struct {
		name string
		opts bus.NATSOptions
	}{
		{"no URL", bus.NATSOptions{Stream: "S", Subject: "s"}},
		{"no stream", bus.NATSOptions{URL: "nats://localhost:4222", Subject: "s"}},
		{"no subject", bus.NATSOptions{URL: "nats://localhost:4222", Stream: "S"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := bus.NewNATSPublisher(ctx, tt.opts); err == nil {
				t.Error("NewNATSPublisher() accepted invalid options")
			}
		})
	}
}

func TestNATSCredentialsAreRejectedWhenWrong(t *testing.T) {
	url := os.Getenv("GRIEFER_TEST_NATS_URL")
	if url == "" || os.Getenv("GRIEFER_TEST_NATS_USER") == "" {
		t.Skip("set GRIEFER_TEST_NATS_URL and GRIEFER_TEST_NATS_USER to run this test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// A server that requires credentials must refuse the wrong ones. Without
	// this the auth configuration could be silently ineffective.
	if _, err := bus.NewNATSPublisher(ctx, bus.NATSOptions{
		URL: url, Stream: "GRIEFER_TEST", Subject: "griefer.test.events",
		ConnectTimeout: 5 * time.Second,
		User:           "wrong-user", Password: "wrong-password",
	}); err == nil {
		t.Fatal("NewNATSPublisher() connected with the wrong credentials")
	}
}

func TestNATSPublisherAgainstARealServer(t *testing.T) {
	url := os.Getenv("GRIEFER_TEST_NATS_URL")
	if url == "" {
		t.Skip("GRIEFER_TEST_NATS_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	p, err := bus.NewNATSPublisher(ctx, bus.NATSOptions{
		URL: url, Stream: "GRIEFER_TEST", Subject: "griefer.test.events",
		ConnectTimeout: 5 * time.Second, MaxAge: time.Hour,
		User: os.Getenv("GRIEFER_TEST_NATS_USER"), Password: os.Getenv("GRIEFER_TEST_NATS_PASSWORD"),
	})
	if err != nil {
		t.Fatalf("NewNATSPublisher() error = %v", err)
	}
	defer func() { _ = p.Close() }()

	if err := p.Health(ctx); err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if p.Kind() != "nats-jetstream" {
		t.Errorf("Kind() = %q", p.Kind())
	}
	if err := p.Publish(ctx, sampleEvent("evt-bus-1")); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	// The event id is the dedup key, so a producer retry collapses rather than
	// duplicating the evidence.
	if err := p.Publish(ctx, sampleEvent("evt-bus-1")); err != nil {
		t.Fatalf("republish error = %v", err)
	}
	if err := p.Publish(ctx, nil); err == nil {
		t.Error("Publish(nil) should fail")
	}
}
