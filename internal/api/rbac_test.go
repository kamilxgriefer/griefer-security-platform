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

	"github.com/kamilxgriefer/griefer-security-platform/internal/api"
	"github.com/kamilxgriefer/griefer-security-platform/internal/httpx"
)

// rbacToken is the shared service credential the protected router expects. Its
// exact value is irrelevant; what matters is that only requests presenting it
// get far enough for a principal header to be read at all.
const rbacToken = "test-internal-token-9f3c1a"

// A response action type that exists in the catalog, so an evaluate request
// fails on the incident lookup rather than on validation — which is how we can
// tell "the handler ran" apart from "the middleware refused".
const rbacKnownActionType = "preserve_evidence"

// rbacHarness serves the same fully wired Service as newHarness, but behind a
// router built WITH an InternalAPIToken.
//
// That distinction is the whole point of this file. router.go mounts
// ServiceAuth only when a token is configured, and mounts PrincipalMiddleware
// strictly inside it — so on a tokenless router the actor headers are never
// read and there is no RBAC to test. The default harness is tokenless, which
// makes it the wrong instrument here.
type rbacHarness struct {
	t      *testing.T
	inner  *harness
	server *httptest.Server
}

func newRBACHarness(t *testing.T) *rbacHarness {
	t.Helper()

	// The demo inventory is skipped: none of these tests ingest an event or
	// touch the asset graph, and RBAC must hold on an empty platform too.
	inner := newHarness(t, harnessOptions{skipInventory: true})

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	handler := api.NewRouter(inner.Service, api.RouterOptions{
		MaxRequestBytes:  1 << 20,
		RateLimitRPS:     10000,
		RateLimitBurst:   10000,
		Logger:           logger,
		InternalAPIToken: rbacToken,
	})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return &rbacHarness{t: t, inner: inner, server: server}
}

// do issues a request with an explicit header set, so every test states in one
// place exactly what the caller presented and nothing is inherited implicitly.
func (h *rbacHarness) do(t *testing.T, method, path, body string, headers map[string]string) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.server.URL+path, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// anonymous is a caller holding no credential at all.
func anonymous() map[string]string { return map[string]string{} }

// systemCaller holds the service credential and asserts no operator: the
// seeder, a migration, a background job. It acts on nobody's behalf.
func systemCaller() map[string]string {
	return map[string]string{"Authorization": "Bearer " + rbacToken}
}

// operator holds the service credential and asserts, via headers, that a named
// person with the given role is behind the request. Only the console does this,
// and only after it has authenticated that person itself.
func operator(subject, role string) map[string]string {
	h := systemCaller()
	h[httpx.HeaderActor] = subject
	h[httpx.HeaderActorRole] = role
	return h
}

// readRBACBody reads a response body once and returns it verbatim, so a test
// can assert both on the decoded envelope and on the raw bytes.
func readRBACBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(payload)
}

// assertErrorEnvelope checks that a refusal is the documented JSON envelope
// carrying the expected stable code, and that it is correlatable with the
// access log. A client only ever has one error shape to parse, refusals
// included; a refusal that arrives as HTML or as a bare status line is a
// contract break even when the status code is right.
func assertErrorEnvelope(t *testing.T, resp *http.Response, wantCode string) {
	t.Helper()

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	payload := readRBACBody(t, resp)
	if strings.HasPrefix(strings.TrimSpace(payload), "<") || strings.Contains(strings.ToLower(payload), "<html") {
		t.Fatalf("refusal body is markup, not JSON: %q", truncateForLog(payload))
	}

	var body httpx.ErrorResponse
	if err := json.Unmarshal([]byte(payload), &body); err != nil {
		t.Fatalf("decode error envelope %q: %v", truncateForLog(payload), err)
	}
	if body.Error.Code != wantCode {
		t.Errorf("error.code = %q, want %q", body.Error.Code, wantCode)
	}
	if strings.TrimSpace(body.Error.Message) == "" {
		t.Error("error.message is empty; a client has nothing to show the operator")
	}
	if body.Error.RequestID == "" {
		t.Error("error.request_id is empty; a denial that cannot be correlated with the access log cannot be investigated")
	}
}

// TestNoEndpointAnswersWithoutTheServiceCredential pins the outer boundary.
//
// Authentication is checked before authorisation, so even the admin-only audit
// trail answers 401 — never 403 — to a caller with no credential. A 403 there
// would tell an anonymous caller that the path exists and that role is the only
// thing standing in the way.
func TestNoEndpointAnswersWithoutTheServiceCredential(t *testing.T) {
	h := newRBACHarness(t)

	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"listing incidents", http.MethodGet, "/api/v1/incidents", ""},
		{"reading the audit trail", http.MethodGet, "/api/v1/audit", ""},
		{
			"evaluating a response action", http.MethodPost, "/api/v1/actions/evaluate",
			`{"incident_id":"inc-does-not-exist","action_type":"` + rbacKnownActionType + `"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.do(t, tc.method, tc.path, tc.body, anonymous())
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			assertErrorEnvelope(t, resp, httpx.CodeUnauthorized)
		})
	}
}

// TestOnlyAnAdminPrincipalReadsTheAuditTrail is the core of the API's RBAC.
//
// The console keeps analysts off the audit page already; this is the second
// layer, and it exists because one layer is one bug away from being none. The
// role comparison is exact: near-miss spellings and casings must not be
// silently accepted, or the API's notion of "admin" drifts away from
// console/lib/roles.ts without anyone noticing.
func TestOnlyAnAdminPrincipalReadsTheAuditTrail(t *testing.T) {
	h := newRBACHarness(t)

	tests := []struct {
		name       string
		headers    map[string]string
		wantStatus int
		why        string
	}{
		{
			name:       "a system caller asserting no operator is admitted",
			headers:    systemCaller(),
			wantStatus: http.StatusOK,
			why:        "the seeder and migrations hold the strongest secret there is and act on nobody's behalf; refusing them breaks the platform's own internals",
		},
		{
			name:       "an admin operator is admitted",
			headers:    operator("console:admin", api.RoleAdmin),
			wantStatus: http.StatusOK,
		},
		{
			name:       "an analyst operator is refused",
			headers:    operator("console:analyst", api.RoleAnalyst),
			wantStatus: http.StatusForbidden,
			why:        "an analyst must not read who did what to whom",
		},
		{
			name:       "the longer spelling administrator is refused",
			headers:    operator("console:analyst", "administrator"),
			wantStatus: http.StatusForbidden,
			why:        "matching is exact, not prefix or fuzzy",
		},
		{
			name:       "an uppercase ADMIN is refused",
			headers:    operator("console:analyst", "ADMIN"),
			wantStatus: http.StatusForbidden,
			why:        "matching is case sensitive, so a client that upper-cases roles does not silently gain access",
		},
		{
			name:       "an operator asserted with an empty role is refused",
			headers:    operator("console:analyst", ""),
			wantStatus: http.StatusForbidden,
			why:        "an asserted operator with no role is not the same as no operator at all; an empty role must never read as admin",
		},
		{
			name:       "a role that violates the principal pattern is blanked and refused",
			headers:    operator("console:analyst", "admin or die"),
			wantStatus: http.StatusBadRequest,
			why:        "a role outside the pattern is refused outright; it is a bug in a trusted component and must be visible rather than downgraded",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.do(t, http.MethodGet, "/api/v1/audit", "", tc.headers)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, tc.wantStatus, tc.why)
			}
			switch tc.wantStatus {
			case http.StatusForbidden:
				assertErrorEnvelope(t, resp, httpx.CodeForbidden)
			case http.StatusBadRequest:
				assertErrorEnvelope(t, resp, httpx.CodeValidationFailed)
			}
		})
	}
}

// TestTheRoleGateGuardsOnlyTheAuditTrail keeps the gate from over-reaching.
//
// RBAC that quietly locks an analyst out of incidents or out of requesting a
// response action would be a availability failure dressed up as security: the
// people expected to work an incident are precisely the ones holding the
// analyst role.
func TestTheRoleGateGuardsOnlyTheAuditTrail(t *testing.T) {
	h := newRBACHarness(t)

	t.Run("an analyst lists incidents", func(t *testing.T) {
		resp := h.do(t, http.MethodGet, "/api/v1/incidents", "", operator("console:analyst", api.RoleAnalyst))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("a system caller lists incidents", func(t *testing.T) {
		resp := h.do(t, http.MethodGet, "/api/v1/incidents", "", systemCaller())
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("an analyst reaches the evaluate handler", func(t *testing.T) {
		// 404 proves the request got past auth and RBAC and into the handler,
		// which then failed on the (deliberately absent) incident. Any 401 or
		// 403 here would mean an analyst cannot ask for a containment action.
		body := `{"incident_id":"inc-does-not-exist","action_type":"` + rbacKnownActionType + `"}`
		resp := h.do(t, http.MethodPost, "/api/v1/actions/evaluate", body, operator("console:analyst", api.RoleAnalyst))
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (the analyst must reach the handler, not be refused by RBAC)", resp.StatusCode)
		}
	})
}

// TestProbesAnswerWithoutAnyCredential covers the two paths that are exempt.
//
// A platform must be able to establish liveness and readiness before it holds
// any secret to present. Those two paths — and only those two — are exempt, so
// a regression that exempts more (or fewer) shows up here.
func TestProbesAnswerWithoutAnyCredential(t *testing.T) {
	h := newRBACHarness(t)

	for _, path := range []string{"/health", "/ready"} {
		t.Run(path+" answers unauthenticated", func(t *testing.T) {
			resp := h.do(t, http.MethodGet, path, "", anonymous())
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
		})
	}
}

// TestAMalformedActorAssertionIsRefused pins a closed escalation.
//
// PrincipalMiddleware could instead DROP an assertion it cannot parse, letting
// the request continue unattributed. That reads as cautious and is not:
// RequireRole admits a request with no principal, because that shape means
// "trusted component acting on nobody's behalf". Composed, a malformed subject
// would therefore read as a system caller and walk straight past the
// administrator gate — arriving with strictly less information and strictly
// more access.
//
// So a header that is PRESENT but unparseable is refused. Sending one is a bug
// in a trusted component either way, and a bug should be visible rather than
// silently converted into a grant. An ABSENT header still means "no operator"
// and still passes, which is what keeps the seeder and the probes working.
func TestAMalformedActorAssertionIsRefused(t *testing.T) {
	h := newRBACHarness(t)

	malformed := []struct {
		name    string
		subject string
	}{
		{"a space", "console analyst"},
		{"markup that must not reach a renderer", "<script>x</script>"},
		{"longer than the 128-character bound", strings.Repeat("a", 129)},
		// A newline is deliberately absent here: net/http refuses to SEND a
		// header containing one, so it cannot reach a server over a real
		// connection at all. It is covered at the middleware level in
		// internal/httpx/principal_test.go, where a request can be constructed
		// directly — which is the only way that byte could ever arrive.
	}
	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.do(t, http.MethodGet, "/api/v1/audit", "", operator(tc.subject, api.RoleAnalyst))
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 — a malformed assertion must not be downgraded into a system call", resp.StatusCode)
			}
			assertErrorEnvelope(t, resp, httpx.CodeValidationFailed)
		})
	}

	// A subject at the boundary is well formed, so the analyst role survives
	// and the gate refuses on the role rather than on the shape. This is the
	// half that proves the cases above are about the pattern and not about the
	// header being ignored entirely.
	resp := h.do(t, http.MethodGet, "/api/v1/audit", "", operator(strings.Repeat("a", 128), api.RoleAnalyst))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a well-formed analyst", resp.StatusCode)
	}

	// And the absent case still passes, or every system caller breaks.
	resp = h.do(t, http.MethodGet, "/api/v1/audit", "", systemCaller())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a caller asserting no operator", resp.StatusCode)
	}
}

// TestActorHeadersAreIgnoredWithoutTheServiceCredential is the ordering test.
//
// PrincipalMiddleware is mounted strictly inside ServiceAuth. Mounted the other
// way round, anyone who could reach the API could name themselves admin in the
// audit trail without presenting anything at all. The observable proof is that
// a self-declared admin with no bearer token still gets 401.
func TestActorHeadersAreIgnoredWithoutTheServiceCredential(t *testing.T) {
	h := newRBACHarness(t)

	headers := map[string]string{
		httpx.HeaderActor:     "console:admin",
		httpx.HeaderActorRole: api.RoleAdmin,
	}
	resp := h.do(t, http.MethodGet, "/api/v1/audit", "", headers)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: an actor header must buy nothing without the credential", resp.StatusCode)
	}
	assertErrorEnvelope(t, resp, httpx.CodeUnauthorized)
}
