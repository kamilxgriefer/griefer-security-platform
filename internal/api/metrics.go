package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds GRIEFER's Prometheus collectors.
//
// They are registered against an injected registry rather than the default one
// so that tests can build an isolated Service without collector duplication
// panics, and so an embedding process keeps control of its own registry.
type Metrics struct {
	EventsIngested    *prometheus.CounterVec
	EventsRejected    *prometheus.CounterVec
	IncidentsTouched  *prometheus.CounterVec
	PolicyDecisions   *prometheus.CounterVec
	CorrelationErrors prometheus.Counter
	BusErrors         prometheus.Counter
	RequestsTotal     *prometheus.CounterVec
	RequestDuration   *prometheus.HistogramVec
}

// NewMetrics registers GRIEFER's collectors on reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		EventsIngested: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "griefer_events_ingested_total",
			Help: "Security events accepted by the ingest API, by evidence category.",
		}, []string{"category"}),
		EventsRejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "griefer_events_rejected_total",
			Help: "Security events rejected at the ingest trust boundary, by reason.",
		}, []string{"reason"}),
		IncidentsTouched: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "griefer_incidents_total",
			Help: "Incidents created or updated by the correlation engine.",
		}, []string{"outcome"}),
		PolicyDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "griefer_policy_decisions_total",
			Help: "Policy Kernel decisions, by effect, engine and whether the decision was produced by the fail-closed path.",
		}, []string{"effect", "engine", "fail_closed"}),
		CorrelationErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "griefer_correlation_errors_total",
			Help: "Correlation failures. Ingestion continues when these occur; a rising rate means GRIEFER is recording but not reasoning.",
		}),
		BusErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "griefer_bus_publish_errors_total",
			Help: "Event bus publish failures. Ingestion continues when these occur.",
		}),
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "griefer_http_requests_total",
			Help: "HTTP requests handled, by method, route template and status class.",
		}, []string{"method", "route", "status"}),
		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "griefer_http_request_duration_seconds",
			Help:    "HTTP request duration by route template.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route"}),
	}
	reg.MustRegister(
		m.EventsIngested, m.EventsRejected, m.IncidentsTouched, m.PolicyDecisions,
		m.CorrelationErrors, m.BusErrors, m.RequestsTotal, m.RequestDuration,
	)
	return m
}

// instrument wraps a handler with request counting and latency observation.
// The route template is passed explicitly rather than derived from the URL, so
// that a path parameter can never explode metric cardinality.
func (m *Metrics) instrument(route string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusCapture{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		m.RequestsTotal.WithLabelValues(r.Method, route, strconv.Itoa(rec.status)).Inc()
		m.RequestDuration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
	})
}

type statusCapture struct {
	http.ResponseWriter
	status int
}

func (w *statusCapture) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusCapture) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}
