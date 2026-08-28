package httpx_test

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kamilxgriefer/griefer-security-platform/internal/httpx"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestRequestIDRejectsUnsafeClientValues(t *testing.T) {
	var seen string
	handler := httpx.RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = httpx.RequestIDFromContext(r.Context())
	}))

	tests := []struct {
		name     string
		supplied string
		wantEcho bool
	}{
		{"a clean id is honoured", "req-abc123", true},
		{"header injection is refused", "abc\r\nX-Admin: true", false},
		{"log forging characters are refused", "abc\ndef", false},
		{"spaces are refused", "req 123", false},
		{"an over-long id is refused", strings.Repeat("a", 200), false},
		{"an empty id is replaced", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.supplied != "" {
				req.Header.Set(httpx.RequestIDHeader, tt.supplied)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if seen == "" {
				t.Fatal("no request id was assigned")
			}
			if tt.wantEcho && seen != tt.supplied {
				t.Errorf("request id = %q, want the supplied %q", seen, tt.supplied)
			}
			if !tt.wantEcho && seen == tt.supplied {
				t.Errorf("request id %q was accepted from the client", seen)
			}
			echoed := rec.Header().Get(httpx.RequestIDHeader)
			if strings.ContainsAny(echoed, "\r\n") {
				t.Errorf("response header carries control characters: %q", echoed)
			}
		})
	}
}

func TestRecoverHidesInternalsFromTheClient(t *testing.T) {
	handler := httpx.Recover(discardLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("secret internal detail: /Users/kamil/db-password")
	}))
	handler = httpx.RequestID(handler)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	body := rec.Body.String()
	for _, leak := range []string{"secret internal detail", "/Users/kamil", "goroutine", "panic"} {
		if strings.Contains(body, leak) {
			t.Errorf("response leaked %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "request_id") {
		t.Error("the error response has no request id, so the log cannot be correlated")
	}
}

func TestSecurityHeaders(t *testing.T) {
	handler := httpx.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Cache-Control":           "no-store",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
}

func TestMaxBytesRejectsOversizeBodies(t *testing.T) {
	handler := httpx.MaxBytes(64)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("within the limit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("a", 32)))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("beyond the limit, and a lying Content-Length does not help", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("a", 4096)))
		req.ContentLength = 8 // the server must not trust this
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, want 413", rec.Code)
		}
	})
}

func TestRequireJSON(t *testing.T) {
	handler := httpx.RequireJSON(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name        string
		method      string
		contentType string
		want        int
	}{
		{"POST with JSON", http.MethodPost, "application/json", http.StatusOK},
		{"POST with charset parameter", http.MethodPost, "application/json; charset=utf-8", http.StatusOK},
		{"POST with form encoding", http.MethodPost, "application/x-www-form-urlencoded", http.StatusUnsupportedMediaType},
		{"POST with XML", http.MethodPost, "text/xml", http.StatusUnsupportedMediaType},
		{"POST with no content type", http.MethodPost, "", http.StatusOK},
		{"GET is unaffected", http.MethodGet, "text/html", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/", strings.NewReader("{}"))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			rec := httptest.NewRecorder()
			httpx.RequestID(handler).ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestRateLimiter(t *testing.T) {
	limiter := httpx.NewRateLimiter(1, 3)
	handler := httpx.RequestID(limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	call := func(remote string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader("{}"))
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	for i := 0; i < 3; i++ {
		if got := call("198.51.100.10:5000"); got != http.StatusOK {
			t.Fatalf("burst request %d = %d, want 200", i+1, got)
		}
	}
	if got := call("198.51.100.10:5000"); got != http.StatusTooManyRequests {
		t.Errorf("beyond the burst = %d, want 429", got)
	}
	// Buckets are per client.
	if got := call("198.51.100.11:5000"); got != http.StatusOK {
		t.Errorf("a different client = %d, want 200; one noisy caller must not throttle everyone", got)
	}
}

func TestRateLimiterIgnoresForwardedForHeaders(t *testing.T) {
	// Honouring a caller-controlled header would let anyone reset their own
	// bucket by changing one string.
	limiter := httpx.NewRateLimiter(1, 2)
	handler := httpx.RequestID(limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	var lastCode int
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader("{}"))
		req.RemoteAddr = "198.51.100.20:5000"
		req.Header.Set("X-Forwarded-For", "203.0.113."+string(rune('1'+i)))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		lastCode = rec.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Errorf("final status = %d, want 429; rotating X-Forwarded-For must not reset the bucket", lastCode)
	}
}

func TestChainAppliesMiddlewareOutermostFirst(t *testing.T) {
	var order []string
	mark := func(name string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	handler := httpx.Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		order = append(order, "handler")
	}), mark("first"), mark("second"), mark("third"))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	want := []string{"first", "second", "third", "handler"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
}

// TestAQuietPathStillLogsItsRefusals.
//
// /metrics requires the service credential and was skipped from the access log
// unconditionally. It is not instrumented either — promhttp serves it directly
// rather than through the metrics wrapper — so a caller with nothing but network
// reach could guess INTERNAL_API_TOKEN against it at full speed and leave no
// access-log line, no counter and no rate-limit state.
//
// The quiet is for successful scrapes every fifteen seconds. It is not for
// somebody without a credential knocking.
func TestAQuietPathStillLogsItsRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   bool
	}{
		{"a successful scrape stays quiet", http.StatusOK, false},
		{"an unauthorised scrape is logged", http.StatusUnauthorized, true},
		{"a forbidden scrape is logged", http.StatusForbidden, true},
		{"a failing scrape is logged", http.StatusInternalServerError, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := httpx.AccessLog(logger, "/metrics")(http.HandlerFunc(
				func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tc.status) }))

			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			handler.ServeHTTP(httptest.NewRecorder(), req)

			logged := strings.Contains(buf.String(), "http request")
			if logged != tc.want {
				t.Errorf("logged = %v for status %d, want %v.\nOutput: %s",
					logged, tc.status, tc.want, buf.String())
			}
		})
	}

	t.Run("an ordinary path is logged either way", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		handler := httpx.AccessLog(logger, "/metrics")(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/events", nil))
		if !strings.Contains(buf.String(), "http request") {
			t.Error("an ordinary successful request was not logged")
		}
	})
}
