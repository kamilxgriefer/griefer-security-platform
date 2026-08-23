package api

import (
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/kamilxgriefer/griefer-security-platform/internal/httpx"
)

// RouterOptions configures the HTTP surface.
type RouterOptions struct {
	// Registry backs the /metrics endpoint.
	Registry *prometheus.Registry
	// MaxRequestBytes caps every request body.
	MaxRequestBytes int64
	// RateLimitRPS and RateLimitBurst throttle write endpoints per client
	// address. Read endpoints are not throttled: an analyst refreshing a
	// console should never be rate limited out of an investigation.
	RateLimitRPS   float64
	RateLimitBurst int
	Logger         *slog.Logger
	// InternalAPIToken, when set, is required on every endpoint except the
	// liveness and readiness probes. Empty leaves the API unauthenticated,
	// which config.Validate only permits on a loopback bind.
	InternalAPIToken string
}

// NewRouter builds GRIEFER's HTTP handler.
//
// Middleware order is deliberate, outermost first:
//
//	Recover      — a panic below this point becomes a 500, never a dropped
//	               connection or a leaked stack trace
//	RequestID    — everything below can correlate its logs
//	AccessLog    — records the outcome even of requests rejected further down
//	SecurityHdrs — applied to every response, including errors
//	MaxBytes     — body cap enforced before any handler reads
//	RequireJSON  — content type checked before parsing
//	RateLimit    — write endpoints only
//
// Service authentication sits inside that chain rather than outside it: a
// rejected request should still get a request id and still appear in the access
// log, because unauthenticated attempts are exactly what an operator wants to
// see.
func NewRouter(svc *Service, opts RouterOptions) http.Handler {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	maxBytes := opts.MaxRequestBytes
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	limiter := httpx.NewRateLimiter(opts.RateLimitRPS, opts.RateLimitBurst)

	mux := http.NewServeMux()

	// --- Operational endpoints (unversioned, unthrottled) --------------------
	mux.Handle("GET /health", svc.metrics.instrument("/health", http.HandlerFunc(svc.handleHealth)))
	mux.Handle("GET /ready", svc.metrics.instrument("/ready", http.HandlerFunc(svc.handleReady)))
	if opts.Registry != nil {
		// /metrics is NOT exempt from authentication. Operational metrics
		// describe ingest volume, incident counts and policy verdicts — enough
		// to tell an attacker whether they have been noticed.
		mux.Handle("GET /metrics", promhttp.HandlerFor(opts.Registry, promhttp.HandlerOpts{
			// A scrape failure should surface in the scrape, not as a panic.
			ErrorHandling: promhttp.ContinueOnError,
			Registry:      opts.Registry,
		}))
	}

	// --- Write endpoints (rate limited) --------------------------------------
	write := func(route string, h http.HandlerFunc) http.Handler {
		return httpx.Chain(svc.metrics.instrument(route, h), limiter.Middleware, httpx.RequireJSON)
	}
	mux.Handle("POST /api/v1/events", write("/api/v1/events", svc.handleIngestEvent))
	mux.Handle("POST /api/v1/events/batch", write("/api/v1/events/batch", svc.handleIngestBatch))
	mux.Handle("POST /api/v1/actions/evaluate", write("/api/v1/actions/evaluate", svc.handleEvaluateAction))

	// --- Read endpoints -------------------------------------------------------
	read := func(route string, h http.HandlerFunc) http.Handler {
		return svc.metrics.instrument(route, h)
	}
	mux.Handle("GET /api/v1/events", read("/api/v1/events", svc.handleListEvents))
	mux.Handle("GET /api/v1/incidents", read("/api/v1/incidents", svc.handleListIncidents))
	mux.Handle("GET /api/v1/incidents/{id}", read("/api/v1/incidents/{id}", svc.handleGetIncident))
	mux.Handle("GET /api/v1/entities/{id}", read("/api/v1/entities/{id}", svc.handleGetEntity))
	mux.Handle("GET /api/v1/actions", read("/api/v1/actions", svc.handleListActions))
	mux.Handle("GET /api/v1/actions/{id}", read("/api/v1/actions/{id}", svc.handleGetAction))
	mux.Handle("GET /api/v1/audit", read("/api/v1/audit", svc.handleListAudit))
	mux.Handle("GET /api/v1/system/status", read("/api/v1/system/status", svc.handleSystemStatus))

	// Anything unmatched gets a JSON 404 rather than net/http's text default,
	// so a client only ever has one error shape to parse.
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.CodeNotFound,
			"No such endpoint. See /api/v1 documentation in api/openapi.yaml.", nil)
	}))

	middleware := []func(http.Handler) http.Handler{
		httpx.Recover(logger),
		httpx.RequestID,
		httpx.AccessLog(logger, "/metrics", "/health"),
		httpx.SecurityHeaders,
		httpx.MaxBytes(maxBytes),
	}
	if opts.InternalAPIToken != "" {
		// A platform must be able to probe liveness and readiness before it has
		// any credential to present, so those two paths — and only those two —
		// answer unauthenticated.
		auth := httpx.NewServiceAuth(opts.InternalAPIToken, "/health", "/ready")
		middleware = append(middleware, auth.Middleware)
	}

	return httpx.Chain(mux, middleware...)
}
