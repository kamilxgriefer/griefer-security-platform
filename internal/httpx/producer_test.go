package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kamilxgriefer/griefer-security-platform/internal/httpx"
)

const (
	goodKey = "3f9a1c77b0e24d5e8a6c1f0b9d2e4a67c5b8e1d0"
	oldKey  = "0000111122223333444455556666777788889999"
)

func keyring(t *testing.T, onReject func(*http.Request, string, string)) *httpx.ProducerKeyring {
	t.Helper()
	return httpx.NewProducerKeyring([]httpx.ProducerCredential{{
		Name:        "okta-prod",
		Key:         goodKey,
		PreviousKey: oldKey,
		Sources:     []httpx.SourceRef{{Type: "identity_provider", Name: "okta-prod"}},
	}}, onReject)
}

func probe(t *testing.T, k *httpx.ProducerKeyring, name, key string) (int, httpx.Producer) {
	t.Helper()
	var seen httpx.Producer
	h := k.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = httpx.ProducerFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader("{}"))
	if name != "" {
		req.Header.Set(httpx.HeaderProducer, name)
	}
	if key != "" {
		req.Header.Set(httpx.HeaderProducerKey, key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, seen
}

// TestAnUnenrolledDeploymentIsNotSilentlyToldItHasProducers.
//
// With no keyring, ingest behaves exactly as it did. The moment ONE producer is
// enrolled the boundary is on for all of them — an opt-in per producer would
// mean an unenrolled sender simply omits the header, which is not a boundary.
func TestAnUnenrolledDeploymentIsNotSilentlyToldItHasProducers(t *testing.T) {
	empty := httpx.NewProducerKeyring(nil, nil)
	if code, p := probe(t, empty, "", ""); code != http.StatusOK || !p.Zero() {
		t.Errorf("empty keyring: code = %d, producer = %+v; want 200 and the zero producer", code, p)
	}
	if code, _ := probe(t, keyring(t, nil), "", ""); code != http.StatusForbidden {
		t.Errorf("configured keyring with no credential: code = %d, want 403", code)
	}
}

// TestANameWithNoKeyIsMalformedRatherThanAbsent.
//
// The rule PrincipalMiddleware states for operator headers, inherited for the
// same reason: if a half-presented credential fell into the absent case, a
// caller would reach the unauthenticated path by making its own header
// unparseable — which is more access than it asked for, granted by a bug.
func TestANameWithNoKeyIsMalformedRatherThanAbsent(t *testing.T) {
	k := keyring(t, nil)
	for _, tc := range []struct{ name, key string }{
		{"okta-prod", ""},
		{"", goodKey},
		{"Okta-Prod", goodKey},     // upper case is outside the pattern
		{"okta prod", goodKey},     // a space is not in the alphabet
		{"-leading-dash", goodKey}, // must start alphanumeric
		{strings.Repeat("a", 65), goodKey},
		{"okta-prod", strings.Repeat("k", 513)},
	} {
		code, p := probe(t, k, tc.name, tc.key)
		if code != http.StatusBadRequest {
			t.Errorf("name=%q key=%q: code = %d, want 400", truncate(tc.name), truncate(tc.key), code)
		}
		if !p.Zero() {
			t.Errorf("name=%q: a refused credential still reached the handler", truncate(tc.name))
		}
	}
}

// TestAnUnknownProducerAndAWrongKeyAreIndistinguishable.
//
// The difference survives where it helps an operator — the metric label and the
// log — and not where it helps an attacker enumerate.
func TestAnUnknownProducerAndAWrongKeyAreIndistinguishable(t *testing.T) {
	var reasons []string
	k := keyring(t, func(_ *http.Request, _, reason string) { reasons = append(reasons, reason) })

	unknownCode, _ := probe(t, k, "nobody-here", goodKey)
	wrongCode, _ := probe(t, k, "okta-prod", "not-the-key-at-all-but-long-enough-xxxx")
	if unknownCode != http.StatusForbidden || wrongCode != http.StatusForbidden {
		t.Fatalf("codes = %d and %d, want 403 for both", unknownCode, wrongCode)
	}
	if len(reasons) != 2 || reasons[0] != httpx.ProducerRejectUnknown || reasons[1] != httpx.ProducerRejectBadKey {
		t.Errorf("reasons = %v, want the distinction kept server-side", reasons)
	}
}

// TestARotationWindowAcceptsTheOutgoingKey, so a key can be changed without
// deploying GRIEFER and its producer in the same instant.
func TestARotationWindowAcceptsTheOutgoingKey(t *testing.T) {
	k := keyring(t, nil)
	if code, p := probe(t, k, "okta-prod", goodKey); code != http.StatusOK || p.Name != "okta-prod" {
		t.Errorf("current key: code = %d, producer = %+v", code, p)
	}
	if code, p := probe(t, k, "okta-prod", oldKey); code != http.StatusOK || p.Name != "okta-prod" {
		t.Errorf("previous key: code = %d, producer = %+v", code, p)
	}
	// And a keyring without a previous key does not accept one.
	solo := httpx.NewProducerKeyring([]httpx.ProducerCredential{{Name: "okta-prod", Key: goodKey}}, nil)
	if code, _ := probe(t, solo, "okta-prod", oldKey); code != http.StatusForbidden {
		t.Errorf("no rotation window: code = %d, want 403", code)
	}
}

// TestEntitlementMatchesAnExactPair.
//
// This is the control that closes T1's hole, not the credential. Authenticating
// a producer and then letting it claim any source_name would leave the
// corroboration gate exactly as satisfiable from one credential as before — the
// sender would just need a credential first.
func TestEntitlementMatchesAnExactPair(t *testing.T) {
	p := httpx.Producer{Name: "okta-prod", Sources: []httpx.SourceRef{
		{Type: "identity_provider", Name: "okta-prod"},
		{Type: "cloud_audit", Name: "aws-org"},
	}}
	for _, tc := range []struct {
		sourceType, sourceName string
		want                   bool
	}{
		{"identity_provider", "okta-prod", true},
		{"cloud_audit", "aws-org", true},
		// The second half is the half a rule keys on when there is no actor,
		// and it is 128 bytes of free text.
		{"identity_provider", "crowdstrike-prod", false},
		{"cloud_audit", "okta-prod", false},
		{"endpoint_agent", "okta-prod", false},
		{"", "", false},
	} {
		if got := p.Entitled(tc.sourceType, tc.sourceName); got != tc.want {
			t.Errorf("Entitled(%q, %q) = %v, want %v", tc.sourceType, tc.sourceName, got, tc.want)
		}
	}
	if (httpx.Producer{}).Entitled("identity_provider", "okta-prod") {
		t.Error("the zero producer is entitled to something")
	}
}

func truncate(s string) string {
	if len(s) > 24 {
		return s[:24] + "..."
	}
	return s
}
