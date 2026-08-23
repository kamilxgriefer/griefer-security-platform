package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kamilxgriefer/griefer-security-platform/internal/httpx"
)

const token = "s3rv1ce-t0ken-value-for-testing"

func authHandler(t *testing.T) http.Handler {
	t.Helper()
	auth := httpx.NewServiceAuth(token, "/health", "/ready")
	return httpx.RequestID(auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})))
}

func call(t *testing.T, handler http.Handler, path, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestServiceAuthRejectsEverythingButTheRightToken(t *testing.T) {
	handler := authHandler(t)

	tests := []struct {
		name          string
		authorization string
	}{
		{"no header at all", ""},
		{"empty bearer", "Bearer "},
		{"wrong token", "Bearer not-the-token"},
		{"right token, wrong scheme", "Basic " + token},
		{"token with no scheme", token},
		{"token as a prefix of a longer value", "Bearer " + token + "extra"},
		{"a prefix of the real token", "Bearer " + token[:10]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := call(t, handler, "/api/v1/incidents", tt.authorization)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
				t.Errorf("WWW-Authenticate = %q, want it to name the scheme", got)
			}
			body := rec.Body.String()
			// The response must not say which part was wrong, and must never
			// echo the expected credential.
			if strings.Contains(body, token) {
				t.Error("the response leaked the expected token")
			}
			for _, hint := range []string{"expected", "mismatch", "length", "scheme"} {
				if strings.Contains(strings.ToLower(body), hint) {
					t.Errorf("the response hints at the failure reason (%q): %s", hint, body)
				}
			}
		})
	}
}

func TestServiceAuthAcceptsTheRightToken(t *testing.T) {
	handler := authHandler(t)

	for _, header := range []string{
		"Bearer " + token,
		"bearer " + token, // scheme is case-insensitive per RFC 7235
		"Bearer   " + token + "  ",
	} {
		rec := call(t, handler, "/api/v1/incidents", header)
		if rec.Code != http.StatusOK {
			t.Errorf("Authorization %q => %d, want 200", header, rec.Code)
		}
	}
}

func TestServiceAuthExemptsProbesOnly(t *testing.T) {
	handler := authHandler(t)

	// A platform must be able to probe liveness and readiness before it holds
	// any credential.
	for _, path := range []string{"/health", "/ready"} {
		if rec := call(t, handler, path, ""); rec.Code != http.StatusOK {
			t.Errorf("%s without a credential = %d, want 200", path, rec.Code)
		}
	}

	// Everything else, including metrics: operational metrics describe ingest
	// volume and policy verdicts, which is enough to tell an attacker whether
	// they have been noticed.
	for _, path := range []string{"/metrics", "/api/v1/incidents", "/api/v1/audit", "/api/v1/events"} {
		if rec := call(t, handler, path, ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a credential = %d, want 401", path, rec.Code)
		}
	}
}

func TestServiceAuthDoesNotExemptByPrefix(t *testing.T) {
	// "/health" being exempt must not exempt "/healthz" or "/health/secrets".
	handler := authHandler(t)
	for _, path := range []string{"/healthz", "/health/secrets", "/ready-set-go", "/api/v1/../health"} {
		if rec := call(t, handler, path, ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a credential = %d, want 401", path, rec.Code)
		}
	}
}
