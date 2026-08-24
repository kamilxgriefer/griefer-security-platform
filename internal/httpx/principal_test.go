package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// echoPrincipal records what the handler saw, so a test can tell "ran with no
// principal" apart from "never ran".
func echoPrincipal(t *testing.T, seen *Principal, ran *bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*ran = true
		*seen = PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

func TestAWellFormedAssertionReachesTheHandler(t *testing.T) {
	var seen Principal
	var ran bool
	h := PrincipalMiddleware(echoPrincipal(t, &seen, &ran))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set(HeaderActor, "console:analyst")
	req.Header.Set(HeaderActorRole, "analyst")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !ran {
		t.Fatal("handler did not run")
	}
	if seen.Subject != "console:analyst" || seen.Role != "analyst" {
		t.Errorf("principal = %+v, want subject console:analyst role analyst", seen)
	}
	if seen.Zero() {
		t.Error("Zero() reported true for an asserted principal")
	}
}

func TestNoAssertionMeansNoOperatorRatherThanNoRequest(t *testing.T) {
	// A request with no actor headers is the platform's own machinery — the
	// seeder, a migration, a probe. It must proceed, unattributed.
	var seen Principal
	var ran bool
	h := PrincipalMiddleware(echoPrincipal(t, &seen, &ran))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil))

	if !ran {
		t.Fatal("a request without actor headers was refused; system callers would break")
	}
	if !seen.Zero() {
		t.Errorf("principal = %+v, want the zero Principal", seen)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// TestAMalformedAssertionIsRefusedRatherThanDropped pins the fix for a real
// escalation.
//
// Dropping a malformed assertion leaves the request indistinguishable from one
// that asserted nothing — and RequireRole admits that case, because it is how
// trusted system callers arrive. So a caller could walk past an
// administrator-only route simply by making its own identity header
// unparseable, arriving with strictly less information and strictly more
// access. Refusing closes that.
func TestAMalformedAssertionIsRefusedRatherThanDropped(t *testing.T) {
	cases := []struct {
		name    string
		subject string
		role    string
	}{
		{"a space in the subject", "console analyst", "analyst"},
		{"a newline, which could forge a second log line", "console:analyst\nadmin", "analyst"},
		{"a carriage return", "console:analyst\radmin", "analyst"},
		{"longer than the 128-character bound", strings.Repeat("a", 129), "analyst"},
		{"markup that must not reach a renderer", "<script>x</script>", "analyst"},
		{"a null byte", "console:\x00admin", "analyst"},
		{"a malformed role beside a valid subject", "console:analyst", "admin or die"},
		{"a role asserted with no subject", "", "admin"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen Principal
			var ran bool
			h := PrincipalMiddleware(echoPrincipal(t, &seen, &ran))

			req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
			if tc.subject != "" {
				req.Header.Set(HeaderActor, tc.subject)
			}
			if tc.role != "" {
				req.Header.Set(HeaderActorRole, tc.role)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if ran {
				t.Fatalf("handler ran with principal %+v; a malformed assertion must not reach it", seen)
			}
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			assertJSONError(t, rec)
		})
	}
}

func TestTheBoundaryLengthSubjectIsAccepted(t *testing.T) {
	// 128 is inside the bound; 129 is not, and is covered above. Testing the
	// boundary itself stops the limit drifting by one unnoticed.
	var seen Principal
	var ran bool
	h := PrincipalMiddleware(echoPrincipal(t, &seen, &ran))

	subject := strings.Repeat("a", 128)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(HeaderActor, subject)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !ran || seen.Subject != subject {
		t.Errorf("a 128-character subject was rejected; ran=%v subject len=%d", ran, len(seen.Subject))
	}
}

func TestRequireRoleAdmitsAMatchAndRefusesEverythingElse(t *testing.T) {
	cases := []struct {
		name       string
		assert     bool
		subject    string
		role       string
		wantStatus int
	}{
		{"the required role", true, "console:admin", "admin", http.StatusOK},
		{"a different role", true, "console:analyst", "analyst", http.StatusForbidden},
		{"no role at all", true, "console:someone", "", http.StatusForbidden},
		{"a near miss in spelling", true, "console:x", "administrator", http.StatusForbidden},
		{"a near miss in case", true, "console:x", "ADMIN", http.StatusForbidden},
		// No assertion is a trusted component acting on nobody's behalf. The
		// service credential, not the header, is the trust boundary.
		{"no assertion at all", false, "", "", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ran bool
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ran = true
				w.WriteHeader(http.StatusOK)
			})
			h := PrincipalMiddleware(RequireRole("admin")(inner))

			req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
			if tc.assert {
				req.Header.Set(HeaderActor, tc.subject)
				if tc.role != "" {
					req.Header.Set(HeaderActorRole, tc.role)
				}
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusForbidden {
				if ran {
					t.Error("the handler ran despite a 403")
				}
				assertJSONError(t, rec)
			}
		})
	}
}

// TestAnUnauthenticatedCallerCannotAssertAnIdentity is the ordering invariant.
//
// PrincipalMiddleware must sit INSIDE ServiceAuth. Mounted in front of it,
// anyone who could reach the API could name themselves in the audit trail —
// and, worse, name themselves an administrator — without holding any credential
// at all. This builds the chain the router builds and proves the outer gate
// answers first.
func TestAnUnauthenticatedCallerCannotAssertAnIdentity(t *testing.T) {
	const token = "a-service-credential-for-this-test"

	var ran bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		w.WriteHeader(http.StatusOK)
	})
	auth := NewServiceAuth(token, "/health", "/ready")
	h := Chain(RequireRole("admin")(inner), auth.Middleware, PrincipalMiddleware)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set(HeaderActor, "console:attacker")
	req.Header.Set(HeaderActorRole, "admin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — a self-declared admin with no credential got through", rec.Code)
	}
	if ran {
		t.Error("the handler ran for an unauthenticated caller")
	}

	// And with the credential, the same headers are honoured — so the 401
	// above is the outer gate working, not the chain being broken.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(HeaderActor, "console:admin")
	req.Header.Set(HeaderActorRole, "admin")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for an authenticated admin", rec.Code)
	}
}

func TestContextRoundTripsAPrincipal(t *testing.T) {
	ctx := ContextWithPrincipal(t.Context(), Principal{Subject: "console:admin", Role: "admin"})
	got := PrincipalFromContext(ctx)
	if got.Subject != "console:admin" || got.Role != "admin" {
		t.Errorf("principal = %+v", got)
	}
	if PrincipalFromContext(t.Context()).Zero() != true {
		t.Error("a context with no principal did not report Zero()")
	}
}

// assertJSONError checks the body is the documented envelope rather than HTML.
//
// A gateway or a browser receiving a page of markup where it expected JSON
// reports a parse error, and the actual reason — forbidden — never surfaces.
func assertJSONError(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	if strings.HasPrefix(strings.TrimSpace(body), "<") {
		t.Fatalf("body is markup, not JSON: %s", body)
	}
	var parsed struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, body)
	}
	if parsed.Error.Code == "" || parsed.Error.Message == "" {
		t.Errorf("error envelope is incomplete: %s", body)
	}
}
