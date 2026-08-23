package httpx

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/kamilxgriefer/griefer-security-platform/internal/idgen"
)

type contextKey int

const requestIDKey contextKey = iota

// RequestIDHeader is the header carrying the correlation id, both inbound and
// outbound.
const RequestIDHeader = "X-Request-Id"

// maxInboundRequestIDLen bounds an accepted client-supplied request id.
const maxInboundRequestIDLen = 64

// RequestIDFromContext returns the request id, or "" when absent.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// WithRequestID returns ctx carrying id. Exported for tests and background
// workers that continue a request's work.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestID assigns every request a correlation id.
//
// A client-supplied id is honoured only if it is short and consists of safe
// characters: the id is echoed into logs and response headers, so accepting
// arbitrary client text would let a caller forge log lines or inject headers.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := sanitizeRequestID(r.Header.Get(RequestIDHeader))
		if id == "" {
			id = idgen.New(idgen.PrefixRequest)
		}
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(WithRequestID(r.Context(), id)))
	})
}

func sanitizeRequestID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxInboundRequestIDLen {
		return ""
	}
	for _, c := range raw {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == ':':
		default:
			return ""
		}
	}
	return raw
}

// SecurityHeaders applies response headers appropriate for a JSON API.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		// The API serves JSON only; a restrictive CSP costs nothing and closes
		// the door on any future path that accidentally returns HTML.
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// Recover converts a panic into a 500 without leaking the panic value or a
// stack trace to the client. The detail goes to the log, keyed by request id.
func Recover(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// nolint:contextcheck // The deferred closure does carry the request
			// context — through r, which every call below reads it from. It
			// takes no ctx parameter of its own because a recover() handler
			// must run on the deferring goroutine.
			defer func() {
				if rec := recover(); rec != nil {
					if errors.Is(errFromRecover(rec), http.ErrAbortHandler) {
						panic(rec)
					}
					logger.ErrorContext(r.Context(), "panic recovered in HTTP handler",
						slog.String("request_id", RequestIDFromContext(r.Context())),
						slog.String("method", r.Method),
						slog.String("path", r.URL.Path),
						slog.Any("panic", rec))
					WriteError(w, r, http.StatusInternalServerError, CodeInternal,
						"The request could not be completed. Use the request_id when reporting this.", nil)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func errFromRecover(rec any) error {
	if err, ok := rec.(error); ok {
		return err
	}
	return nil
}

// statusRecorder captures the response status for access logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusRecorder) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// AccessLog emits one structured line per request.
func AccessLog(logger *slog.Logger, skipPaths ...string) func(http.Handler) http.Handler {
	skip := make(map[string]bool, len(skipPaths))
	for _, p := range skipPaths {
		skip[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skip[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			if rec.status == 0 {
				rec.status = http.StatusOK
			}
			level := slog.LevelInfo
			if rec.status >= 500 {
				level = slog.LevelError
			} else if rec.status >= 400 {
				level = slog.LevelWarn
			}
			logger.LogAttrs(r.Context(), level, "http request",
				slog.String("request_id", RequestIDFromContext(r.Context())),
				slog.String("method", r.Method),
				// Only the routed path is logged. A raw query string can carry
				// caller-controlled content straight into the log.
				slog.String("path", r.URL.Path),
				slog.Int("status", rec.status),
				slog.Int("bytes", rec.bytes),
				slog.Duration("duration", time.Since(start)),
				slog.String("client", clientIP(r)),
			)
		})
	}
}

// MaxBytes caps the request body. The limit is enforced by the server rather
// than trusting Content-Length, which a client controls.
func MaxBytes(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireJSON rejects write requests that do not carry a JSON body.
func RequireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			ct := r.Header.Get("Content-Type")
			if ct != "" {
				media := strings.TrimSpace(strings.Split(ct, ";")[0])
				if !strings.EqualFold(media, "application/json") {
					WriteError(w, r, http.StatusUnsupportedMediaType, CodeUnsupportedMedia,
						"Request body must be application/json.", nil)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RateLimiter applies a per-client token bucket to write endpoints.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rps      rate.Limit
	burst    int
	ttl      time.Duration
	maxHosts int
	now      func() time.Time
}

type bucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// maxTrackedClients bounds the limiter's own memory. Without a bound, a caller
// rotating source addresses turns the rate limiter into a memory leak.
const maxTrackedClients = 10000

// NewRateLimiter builds a limiter allowing rps requests per second with the
// given burst, per client address.
func NewRateLimiter(rps float64, burst int) *RateLimiter {
	if rps <= 0 {
		rps = 1
	}
	if burst < 1 {
		burst = 1
	}
	return &RateLimiter{
		buckets:  make(map[string]*bucket),
		rps:      rate.Limit(rps),
		burst:    burst,
		ttl:      10 * time.Minute,
		maxHosts: maxTrackedClients,
		now:      time.Now,
	}
}

// Middleware enforces the limit.
func (l *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "1")
			WriteError(w, r, http.StatusTooManyRequests, CodeRateLimited,
				"Too many requests. Slow down and retry.", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *RateLimiter) allow(client string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[client]
	if !ok {
		if len(l.buckets) >= l.maxHosts {
			l.evictLocked(now)
		}
		if len(l.buckets) >= l.maxHosts {
			// Still full after eviction: refuse rather than grow unbounded.
			return false
		}
		b = &bucket{limiter: rate.NewLimiter(l.rps, l.burst)}
		l.buckets[client] = b
	}
	b.lastSeen = now
	return b.limiter.Allow()
}

func (l *RateLimiter) evictLocked(now time.Time) {
	for key, b := range l.buckets {
		if now.Sub(b.lastSeen) > l.ttl {
			delete(l.buckets, key)
		}
	}
}

// clientIP returns the peer address.
//
// GRIEFER deliberately does NOT trust X-Forwarded-For here. Honouring a header
// a caller controls would let anyone reset their own rate-limit bucket by
// changing one string. A future deployment behind a trusted proxy needs an
// explicit allowlist of proxy addresses; that is tracked for M8.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Chain composes middleware so that the first argument is the outermost layer.
func Chain(h http.Handler, middleware ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		h = middleware[i](h)
	}
	return h
}
