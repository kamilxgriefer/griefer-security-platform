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
	// liveness and readiness probes.
	//
	// Empty leaves the API unauthenticated. config.Validate permits that on a
	// loopback bind — and ALSO on a routable one, if the operator sets
	// GRIEFER_ALLOW_PUBLIC_BIND to say so out loud. This comment used to claim
	// loopback was the only case, which mattered because of what the other case
	// does to the role gate: PrincipalMiddleware is mounted only when a token
	// is configured, so with no token RequireRole never sees a principal and
	// admits every caller. On a routable interface that serves the audit trail
	// and the chain-integrity report to anyone who can reach the port.
	InternalAPIToken string
	// PublicBind is true when the server listens on a routable address. With no
	// InternalAPIToken it makes the role gate unenforceable, and the role-gated
	// routes are withdrawn rather than served open.
	PublicBind bool
	// Producers is the enrolled telemetry keyring. Empty leaves ingest
	// authenticated only by the service credential, which is where every
	// deployment starts.
	Producers []httpx.ProducerCredential
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
	// Ingest carries a third identity, so it gets its own chain.
	//
	// Producer verification sits INSIDE the rate limiter, which matters: mounted
	// globally beside PrincipalMiddleware it would sit outside, and a caller
	// holding the service credential could turn refused ingest into unbounded
	// writes to an append-only trail — the shape of defect the evaluation path
	// already guards against.
	keyring := httpx.NewProducerKeyring(opts.Producers, svc.recordProducerRejection)
	ingest := func(route string, h http.HandlerFunc) http.Handler {
		return httpx.Chain(svc.metrics.instrument(route, keyring.Middleware(h)),
			limiter.Middleware, httpx.RequireJSON)
	}
	mux.Handle("POST /api/v1/events", ingest("/api/v1/events", svc.handleIngestEvent))
	mux.Handle("POST /api/v1/events/batch", ingest("/api/v1/events/batch", svc.handleIngestBatch))
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
	// adminOnly wraps a role-gated route, and withdraws it entirely in the one
	// configuration where the role gate cannot work.
	//
	// PrincipalMiddleware is mounted only when a credential is configured, so
	// with no token RequireRole sees the zero principal and admits everyone.
	// That is deliberate and documented on loopback, where the caller is the
	// operator. On a routable address it means the audit trail and the
	// chain-integrity report answer anyone who reaches the port, which is not a
	// gate that has been relaxed — it is a gate that is not there.
	//
	// 503 rather than 403: nothing is wrong with the request, the deployment
	// cannot authorise it, and the message says what to set.
	adminOnly := func(h http.Handler) http.Handler {
		if opts.InternalAPIToken == "" && opts.PublicBind {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				httpx.WriteError(w, r, http.StatusServiceUnavailable, httpx.CodeDependencyDegraded,
					"Administrator-only endpoints are withdrawn: this deployment listens on a "+
						"routable address with no INTERNAL_API_TOKEN, so no caller can be "+
						"attributed a role. Configure the credential to enable them.", nil)
			})
		}
		return httpx.RequireRole(RoleAdmin)(h)
	}

	// throttledRead applies the write-path limiter to a read that is expensive.
	//
	// Read endpoints are deliberately unthrottled so an analyst refreshing a
	// console is never throttled out of an investigation. Chain verification is
	// not that: it scans audit_log end to end while holding a pooled
	// connection, and audit_log is a table a producer can grow.
	throttledRead := func(route string, h http.HandlerFunc) http.Handler {
		return httpx.Chain(svc.metrics.instrument(route, h), limiter.Middleware)
	}

	// The audit trail is administrator-only at the API as well as in the
	// console. One layer is one bug away from being none.
	mux.Handle("GET /api/v1/audit",
		adminOnly(read("/api/v1/audit", svc.handleListAudit)))
	// Administrator-only for the same reason, and gated no more tightly than
	// the trail it reports on: RequireRole admits a caller holding the service
	// credential with no actor assertion, which is the platform's own internals
	// and the demonstration script. Tightening only this route would break them
	// while buying nothing with GET /api/v1/audit open beside it. The role gate
	// binds the console; the credential is the trust boundary. Per-caller
	// credentials are M8.
	//
	// instrument sits OUTSIDE the role gate here. Wrapped the other way, a
	// refusal returns before the counter runs — and on an integrity endpoint
	// "nobody could call it" and "nobody called it" must not look the same on a
	// dashboard.
	mux.Handle("GET /api/v1/audit/verify",
		svc.metrics.instrument("/api/v1/audit/verify",
			adminOnly(throttledRead("/api/v1/audit/verify", svc.handleVerifyAudit))))
	// An anchor is issued for the operator to keep OUTSIDE this database, and
	// checked back against it later. Administrator-only on both verbs, like the
	// trail itself.
	//
	// The check is a POST because the anchor travels in a body: the console
	// gateway forwards a fixed set of query parameters and drops the rest, so an
	// anchor sent as a query string would vanish between the two halves with no
	// error anywhere.
	mux.Handle("GET /api/v1/audit/anchor",
		svc.metrics.instrument("/api/v1/audit/anchor",
			adminOnly(http.HandlerFunc(svc.handleIssueAuditAnchor))))
	mux.Handle("POST /api/v1/audit/anchor",
		adminOnly(write("/api/v1/audit/anchor", svc.handleCheckAuditAnchor)))
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
		// Strictly INSIDE the credential check. The operator identity arrives
		// in a header, and a header is only worth reading once the caller has
		// proved it is a component we deployed. Mounted in front of the auth
		// instead, anyone who could reach the API could name themselves in the
		// audit trail without presenting anything.
		middleware = append(middleware, httpx.PrincipalMiddleware)
	}

	return httpx.Chain(mux, middleware...)
}

// Roles the API recognises in an asserted principal.
//
// These mirror console/lib/roles.ts. They are duplicated rather than shared
// because the two run in different languages on different sides of a network
// boundary; what keeps them honest is that a disagreement shows up as a 403 in
// the RBAC tests rather than as a silent grant.
const (
	RoleAdmin   = "admin"
	RoleAnalyst = "analyst"
)
