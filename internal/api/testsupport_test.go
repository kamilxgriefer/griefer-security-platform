package api_test

import (
	"context"
	"encoding/json"
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

// harness is a fully wired GRIEFER, assembled from real components rather than
// mocks. Only the pieces a test needs to control — the correlator, the policy
// kernel — are substitutable.
type harness struct {
	t         *testing.T
	Service   *api.Service
	Server    *httptest.Server
	Store     storage.Store
	Graph     *graph.Graph
	Auditor   *audit.Recorder
	Publisher *bus.NoopPublisher

	bodies map[*http.Response]string
}

type harnessOptions struct {
	correlator     api.Correlator
	kernel         policy.Kernel
	publisher      bus.Publisher
	maxRequestSize int64
	rateLimitRPS   float64
	rateLimitBurst int
	maxBatchEvents int
	skipInventory  bool
}

func newHarness(t *testing.T, opts harnessOptions) *harness {
	t.Helper()

	store := storage.NewMemoryStore(0)
	g := graph.New()
	if !opts.skipInventory {
		inv, err := demo.LoadInventory()
		if err != nil {
			t.Fatalf("LoadInventory() error = %v", err)
		}
		if err := g.ApplyInventory(inv, time.Now().UTC()); err != nil {
			t.Fatalf("ApplyInventory() error = %v", err)
		}
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

	noop := bus.NewNoopPublisher()
	var publisher bus.Publisher = noop
	if opts.publisher != nil {
		publisher = opts.publisher
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	registry := prometheus.NewRegistry()

	svc, err := api.NewService(api.ServiceOptions{
		Store: store, Graph: g, Validator: validator, Normalizer: events.NewNormalizer(),
		Correlator: correlator, Kernel: kernel, Auditor: recorder, Publisher: publisher,
		Metrics: api.NewMetrics(registry), Logger: logger,
		MaxBatchEvents: opts.maxBatchEvents, RuleCount: 6,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	maxSize := opts.maxRequestSize
	if maxSize == 0 {
		maxSize = 1 << 20
	}
	rps := opts.rateLimitRPS
	if rps == 0 {
		rps = 10000
	}
	burst := opts.rateLimitBurst
	if burst == 0 {
		burst = 10000
	}

	handler := api.NewRouter(svc, api.RouterOptions{
		Registry: registry, MaxRequestBytes: maxSize,
		RateLimitRPS: rps, RateLimitBurst: burst, Logger: logger,
	})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return &harness{
		t: t, Service: svc, Server: server, Store: store, Graph: g,
		Auditor: recorder, Publisher: noop, bodies: map[*http.Response]string{},
	}
}

func (h *harness) do(method, path, body string) *http.Response {
	h.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.Server.URL+path, reader)
	if err != nil {
		h.t.Fatalf("build request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.Server.Client().Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	h.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// body reads and caches a response body so a test can both decode it and
// inspect the raw bytes for leaked internals.
func (h *harness) body(resp *http.Response) string {
	h.t.Helper()
	if cached, ok := h.bodies[resp]; ok {
		return cached
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		h.t.Fatalf("read body: %v", err)
	}
	if h.bodies == nil {
		h.bodies = map[*http.Response]string{}
	}
	h.bodies[resp] = string(payload)
	return h.bodies[resp]
}

func (h *harness) decode(resp *http.Response, into any) {
	h.t.Helper()
	payload := h.body(resp)
	if err := json.Unmarshal([]byte(payload), into); err != nil {
		h.t.Fatalf("decode body %q: %v", truncateForLog(payload), err)
	}
}

// seedScenario replays the synthetic demo scenario and returns the incident it
// produced.
func (h *harness) seedScenario() *incidents.Incident {
	h.t.Helper()
	sc, err := demo.LoadScenario("synthetic/scenario-01-identity-compromise.json")
	if err != nil {
		h.t.Fatalf("LoadScenario() error = %v", err)
	}
	replay, err := sc.Rebase(time.Now().UTC())
	if err != nil {
		h.t.Fatalf("Rebase() error = %v", err)
	}
	var incidentID string
	for i, raw := range replay {
		resp := h.do(http.MethodPost, "/api/v1/events", string(raw))
		if resp.StatusCode != http.StatusAccepted {
			h.t.Fatalf("event %d: status = %d, want 202", i+1, resp.StatusCode)
		}
		var result api.IngestResult
		h.decode(resp, &result)
		if result.IncidentID != "" {
			incidentID = result.IncidentID
		}
	}
	if incidentID == "" {
		h.t.Fatal("the scenario produced no incident")
	}
	inc, err := h.Store.GetIncident(context.Background(), incidentID)
	if err != nil {
		h.t.Fatalf("GetIncident() error = %v", err)
	}
	return inc
}

func truncateForLog(s string) string {
	if len(s) <= 500 {
		return s
	}
	return s[:500] + "…"
}
