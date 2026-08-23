// Package integration_test exercises GRIEFER end to end: a synthetic event
// enters through the real HTTP API and is followed all the way to the audit
// entry that records what the platform decided and why.
//
// These tests wire real components — the real validator, the real correlation
// engine, the real Security Graph, the real Policy Kernel evaluating the real
// Rego. Only the pieces a specific test needs to break are substituted.
package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
)

type stack struct {
	t       *testing.T
	server  *httptest.Server
	store   storage.Store
	graph   *graph.Graph
	auditor *audit.Recorder
	client  *http.Client
}

type stackOptions struct {
	correlator     api.Correlator
	kernel         policy.Kernel
	maxRequestSize int64
	maxBatchEvents int
}

func newStack(t *testing.T, opts stackOptions) *stack {
	t.Helper()

	store := storage.NewMemoryStore(0)
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

	kernel := opts.kernel
	if kernel == nil {
		embedded, err := policy.NewEmbeddedKernel()
		if err != nil {
			t.Fatalf("NewEmbeddedKernel() error = %v", err)
		}
		kernel = embedded
	}
	t.Cleanup(func() { _ = kernel.Close() })

	correlator := opts.correlator
	if correlator == nil {
		rules, err := correlation.DefaultRules()
		if err != nil {
			t.Fatalf("DefaultRules() error = %v", err)
		}
		engine, err := correlation.NewEngine(correlation.Options{Rules: rules, Graph: g, Store: store})
		if err != nil {
			t.Fatalf("NewEngine() error = %v", err)
		}
		correlator = engine
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	registry := prometheus.NewRegistry()
	svc, err := api.NewService(api.ServiceOptions{
		Store: store, Graph: g, Validator: validator, Normalizer: events.NewNormalizer(),
		Correlator: correlator, Kernel: kernel, Auditor: recorder,
		Publisher: bus.NewNoopPublisher(), Metrics: api.NewMetrics(registry),
		Logger: logger, MaxBatchEvents: opts.maxBatchEvents, RuleCount: 6,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	maxSize := opts.maxRequestSize
	if maxSize == 0 {
		maxSize = 1 << 20
	}
	server := httptest.NewServer(api.NewRouter(svc, api.RouterOptions{
		Registry: registry, MaxRequestBytes: maxSize,
		RateLimitRPS: 10000, RateLimitBurst: 10000, Logger: logger,
	}))
	t.Cleanup(server.Close)

	return &stack{t: t, server: server, store: store, graph: g, auditor: recorder, client: server.Client()}
}

func (s *stack) post(path, body string) (*http.Response, string) {
	s.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.server.URL+path, strings.NewReader(body))
	if err != nil {
		s.t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return s.send(req)
}

func (s *stack) get(path string) (*http.Response, string) {
	s.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.server.URL+path, nil)
	if err != nil {
		s.t.Fatalf("build request: %v", err)
	}
	return s.send(req)
}

func (s *stack) send(req *http.Request) (*http.Response, string) {
	s.t.Helper()
	resp, err := s.client.Do(req)
	if err != nil {
		s.t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		s.t.Fatalf("read body: %v", err)
	}
	return resp, string(payload)
}

func (s *stack) decode(body string, into any) {
	s.t.Helper()
	if err := json.Unmarshal([]byte(body), into); err != nil {
		s.t.Fatalf("decode %q: %v", body, err)
	}
}

// replayScenario ingests the synthetic demo chain and returns the incident.
func (s *stack) replayScenario() *incidents.Incident {
	s.t.Helper()
	sc, err := demo.LoadScenario("synthetic/scenario-01-identity-compromise.json")
	if err != nil {
		s.t.Fatalf("LoadScenario() error = %v", err)
	}
	replay, err := sc.Rebase(time.Now().UTC())
	if err != nil {
		s.t.Fatalf("Rebase() error = %v", err)
	}
	var incidentID string
	for i, raw := range replay {
		resp, body := s.post("/api/v1/events", string(raw))
		if resp.StatusCode != http.StatusAccepted {
			s.t.Fatalf("event %d: status = %d, body = %s", i+1, resp.StatusCode, body)
		}
		var result api.IngestResult
		s.decode(body, &result)
		if result.IncidentID != "" {
			incidentID = result.IncidentID
		}
	}
	if incidentID == "" {
		s.t.Fatal("scenario produced no incident")
	}
	inc, err := s.store.GetIncident(context.Background(), incidentID)
	if err != nil {
		s.t.Fatalf("GetIncident() error = %v", err)
	}
	return inc
}

// auditEntries returns the whole trail.
func (s *stack) auditEntries() []*audit.Entry {
	s.t.Helper()
	entries, _, err := s.auditor.List(context.Background(), storage.MaxPageSize, 0)
	if err != nil {
		s.t.Fatalf("audit List() error = %v", err)
	}
	return entries
}

// evaluate submits a proposed action and returns the resulting record.
func (s *stack) evaluate(incidentID, actionType, mode string, automated bool) (*http.Response, *incidents.ResponseAction, string) {
	s.t.Helper()
	body := fmt.Sprintf(`{"incident_id":%q,"action_type":%q,"mode":%q,"requested_by":"test","automated":%t}`,
		incidentID, actionType, mode, automated)
	resp, raw := s.post("/api/v1/actions/evaluate", body)
	if resp.StatusCode != http.StatusOK {
		return resp, nil, raw
	}
	var action incidents.ResponseAction
	s.decode(raw, &action)
	return resp, &action, raw
}

// eventAt renders a valid single event with the given fields.
func eventAt(eventType, category, severity, actorID string, extra string) string {
	base := fmt.Sprintf(`"schema_version":"0.1","timestamp":%q,"source_type":"identity_provider","source_name":"integration-test","event_type":%q,"category":%q,"severity":%q,"actor":{"type":"identity","id":%q}`,
		time.Now().UTC().Format(time.RFC3339), eventType, category, severity, actorID)
	if extra != "" {
		base += "," + extra
	}
	return "{" + base + "}"
}
