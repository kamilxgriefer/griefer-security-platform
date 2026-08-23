package integration_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/kamilxgriefer/griefer-security-platform/internal/api"
	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/bus"
	"github.com/kamilxgriefer/griefer-security-platform/internal/correlation"
	"github.com/kamilxgriefer/griefer-security-platform/internal/demo"
	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/graph"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
	"github.com/kamilxgriefer/griefer-security-platform/internal/policy"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
	"github.com/kamilxgriefer/griefer-security-platform/policies"
)

// TestAgainstLiveServices runs the whole platform against real PostgreSQL, real
// NATS JetStream and a real OPA server rather than in-process substitutes.
//
// The in-process components are the same code, so this test is not about
// coverage: it is about the seams. Schema DDL, SQL dialect, JetStream stream
// configuration and OPA's HTTP contract are all places where "compiles and
// passes unit tests" and "works" diverge.
//
// It is skipped unless the three environment variables are set. `make test-live`
// starts the services and sets them.
func TestAgainstLiveServices(t *testing.T) {
	dsn := os.Getenv("GRIEFER_TEST_POSTGRES_DSN")
	natsURL := os.Getenv("GRIEFER_TEST_NATS_URL")
	opaURL := os.Getenv("GRIEFER_TEST_OPA_URL")
	if dsn == "" || natsURL == "" || opaURL == "" {
		t.Skip("set GRIEFER_TEST_POSTGRES_DSN, GRIEFER_TEST_NATS_URL and GRIEFER_TEST_OPA_URL to run this test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	store, err := storage.NewPostgresStore(ctx, storage.PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()
	resetDatabase(t, dsn)

	publisher, err := bus.NewNATSPublisher(ctx, bus.NATSOptions{
		URL: natsURL, Stream: "GRIEFER_LIVE_TEST", Subject: "griefer.live.events",
		ConnectTimeout: 10 * time.Second, MaxAge: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewNATSPublisher() error = %v", err)
	}
	defer func() { _ = publisher.Close() }()

	kernel, err := policy.NewRemoteKernel(policy.RemoteOptions{
		BaseURL: opaURL, DecisionPath: policies.DecisionPath, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewRemoteKernel() error = %v", err)
	}
	defer func() { _ = kernel.Close() }()
	if err := kernel.Health(ctx); err != nil {
		t.Fatalf("OPA health check failed: %v", err)
	}

	g := graph.New()
	inv, err := demo.LoadInventory()
	if err != nil {
		t.Fatalf("LoadInventory() error = %v", err)
	}
	if err := g.ApplyInventory(inv, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyInventory() error = %v", err)
	}

	validator, err := events.NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error = %v", err)
	}
	recorder, err := audit.NewRecorder(store)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rules, err := correlation.DefaultRules()
	if err != nil {
		t.Fatalf("DefaultRules() error = %v", err)
	}
	engine, err := correlation.NewEngine(correlation.Options{Rules: rules, Graph: g, Store: store})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	registry := prometheus.NewRegistry()
	svc, err := api.NewService(api.ServiceOptions{
		Store: store, Graph: g, Validator: validator, Normalizer: events.NewNormalizer(),
		Correlator: engine, Kernel: kernel, Auditor: recorder, Publisher: publisher,
		Metrics: api.NewMetrics(registry), Logger: logger, RuleCount: len(rules),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	server := httptest.NewServer(api.NewRouter(svc, api.RouterOptions{
		Registry: registry, MaxRequestBytes: 1 << 20,
		RateLimitRPS: 10000, RateLimitBurst: 10000, Logger: logger,
	}))
	defer server.Close()

	live := &stack{t: t, server: server, store: store, graph: g, auditor: recorder, client: server.Client()}

	t.Run("readiness reports all three live dependencies healthy", func(t *testing.T) {
		resp, body := live.get("/ready")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
		}
		var ready api.ReadinessResponse
		live.decode(body, &ready)
		for _, c := range ready.Components {
			if !c.Healthy {
				t.Errorf("component %s (%s) is unhealthy: %s", c.Name, c.Kind, c.Detail)
			}
		}
		kinds := map[string]string{}
		for _, c := range ready.Components {
			kinds[c.Name] = c.Kind
		}
		if kinds["storage"] != "postgres" {
			t.Errorf("storage kind = %q, want postgres", kinds["storage"])
		}
		if kinds["policy_kernel"] != "remote" {
			t.Errorf("policy kernel = %q, want remote", kinds["policy_kernel"])
		}
		if kinds["event_bus"] != "nats-jetstream" {
			t.Errorf("event bus = %q, want nats-jetstream", kinds["event_bus"])
		}
	})

	inc := live.replayScenario()

	t.Run("the incident survives a PostgreSQL round trip intact", func(t *testing.T) {
		stored, err := store.GetIncident(ctx, inc.ID)
		if err != nil {
			t.Fatalf("GetIncident() error = %v", err)
		}
		if len(stored.Findings) != 5 || stored.RiskScore < 70 {
			t.Errorf("stored incident has %d findings and risk %d", len(stored.Findings), stored.RiskScore)
		}
		if len(stored.BlastRadius.Reachable) == 0 {
			t.Error("the blast radius was lost in the JSONB round trip")
		}
	})

	t.Run("no event reported a degraded bus", func(t *testing.T) {
		// Every event went through real JetStream. A degraded flag here would
		// mean the publisher silently failed.
		entries, _, err := recorder.List(ctx, storage.MaxPageSize, 0)
		if err != nil {
			t.Fatalf("audit List() error = %v", err)
		}
		for _, e := range entries {
			if e.Action != audit.ActionEventIngested {
				continue
			}
			degraded, _ := e.Details["degraded"].([]any)
			for _, d := range degraded {
				if d == "event_bus" {
					t.Errorf("event %s reported a degraded bus", e.SubjectID)
				}
			}
		}
	})

	t.Run("the remote OPA enforces the same policy as the embedded kernel", func(t *testing.T) {
		cases := []struct {
			actionType string
			want       incidents.ActionStatus
		}{
			{"preserve_evidence", incidents.ActionSimulated},
			{"isolate_endpoint", incidents.ActionSimulated},
			{"revoke_sessions", incidents.ActionRequiresApproval},
			{"rotate_exposed_secret", incidents.ActionRequiresApproval},
			{"wipe_endpoint", incidents.ActionDenied},
		}
		for _, c := range cases {
			t.Run(c.actionType, func(t *testing.T) {
				_, action, body := live.evaluate(inc.ID, c.actionType, "simulate", true)
				if action == nil {
					t.Fatalf("evaluate failed: %s", body)
				}
				if action.Status != c.want {
					t.Errorf("Status = %q, want %q (reasons: %v)", action.Status, c.want, action.PolicyDecision.Reasons)
				}
				if action.PolicyDecision.Engine != policy.EngineRemote {
					t.Errorf("Engine = %q, want remote", action.PolicyDecision.Engine)
				}
				if action.PolicyDecision.FailClosed {
					t.Error("a healthy OPA produced a fail-closed decision")
				}
				if action.PolicyDecision.PolicyVersion != policies.Version {
					t.Errorf("PolicyVersion = %q, want %q; the sidecar is running different policy than the binary embeds",
						action.PolicyDecision.PolicyVersion, policies.Version)
				}
			})
		}
	})

	t.Run("the audit trail is durable and readable", func(t *testing.T) {
		resp, body := live.get("/api/v1/audit?limit=200")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		if !strings.Contains(body, "policy.evaluated") {
			t.Error("no policy decision appears in the trail")
		}
	})
}

func resetDatabase(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	store, err := storage.NewPostgresStore(ctx, storage.PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	defer func() { _ = store.Close() }()
	if err := truncateAll(ctx, dsn); err != nil {
		t.Fatalf("reset: %v", err)
	}
}
