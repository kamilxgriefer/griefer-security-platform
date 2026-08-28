package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/kamilxgriefer/griefer-security-platform/internal/httpx"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
)

// verifyPath is the integrity endpoint. It sits under the audit prefix so the
// console's admin-only prefix match already covers it.
const verifyPath = "/api/v1/audit/verify"

// TestVerifyAuditIsGatedExactlyLikeTheTrailItReportsOn.
//
// Not more tightly, and not less. A caller holding the service credential with
// no actor assertion must still pass: that is the platform's own internals and
// the demonstration script, and it is pinned as intended for GET /api/v1/audit.
func TestVerifyAuditIsGatedExactlyLikeTheTrailItReportsOn(t *testing.T) {
	h := newRBACHarness(t)

	t.Run("anonymous is refused before the role is ever consulted", func(t *testing.T) {
		resp := h.do(t, http.MethodGet, verifyPath, "", anonymous())
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 — a 403 would confirm the path exists and that "+
				"role is the only obstacle", resp.StatusCode)
		}
		assertErrorEnvelope(t, resp, httpx.CodeUnauthorized)
	})

	t.Run("an analyst is refused", func(t *testing.T) {
		resp := h.do(t, http.MethodGet, verifyPath, "", operator("user:ana", "analyst"))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		assertErrorEnvelope(t, resp, httpx.CodeForbidden)
	})

	t.Run("an administrator is admitted", func(t *testing.T) {
		resp := h.do(t, http.MethodGet, verifyPath, "", operator("user:root", "admin"))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", resp.StatusCode, readRBACBody(t, resp))
		}
	})

	t.Run("the service credential with no asserted operator is admitted", func(t *testing.T) {
		resp := h.do(t, http.MethodGet, verifyPath, "", systemCaller())
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 — the seeder and the demonstration script "+
				"present exactly this shape: %s", resp.StatusCode, readRBACBody(t, resp))
		}
	})
}

// TestVerifyAuditReportsWhatItIsNotEvidenceOf.
//
// The qualification has to be on the wire. Someone pasting a green response
// into an incident report never opens the safety model.
func TestVerifyAuditReportsWhatItIsNotEvidenceOf(t *testing.T) {
	h := newRBACHarness(t)
	resp := h.do(t, http.MethodGet, verifyPath, "", operator("user:root", "admin"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var report storage.AuditChainReport
	if err := json.Unmarshal([]byte(readRBACBody(t, resp)), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.ExternallyAnchored {
		t.Error("externally_anchored is true, but no anchor has shipped")
	}
	if report.Attests != storage.AuditChainAttests {
		t.Errorf("attests = %q, want the fixed qualification", report.Attests)
	}
	if report.Store == "" {
		t.Error("store is empty; a response that does not name the store lets a memory " +
			"result read as the PostgreSQL guarantee")
	}
	if report.Status == "" {
		t.Error("status is empty")
	}
	if report.Warnings == nil {
		t.Error("warnings is null; every other endpoint returns an empty list")
	}
}

// TestVerifyAuditSaysConsistentOnlyOnceThereIsSomethingToVerify.
//
// An empty trail must not report "consistent". It is the one complete form of
// audit destruction the chain cannot detect.
func TestVerifyAuditSaysConsistentOnlyOnceThereIsSomethingToVerify(t *testing.T) {
	h := newRBACHarness(t)

	var before storage.AuditChainReport
	resp := h.do(t, http.MethodGet, verifyPath, "", operator("user:root", "admin"))
	if err := json.Unmarshal([]byte(readRBACBody(t, resp)), &before); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if before.Status != storage.ChainEmpty {
		t.Fatalf("status on an empty trail = %q, want %q", before.Status, storage.ChainEmpty)
	}

	// Any audited operation will do; a refused evaluation writes entries.
	h.do(t, http.MethodPost, "/api/v1/actions/evaluate", `{"incident_id":"inc-missing","action_type":"`+
		rbacKnownActionType+`"}`, operator("user:root", "admin"))

	var after storage.AuditChainReport
	resp = h.do(t, http.MethodGet, verifyPath, "", operator("user:root", "admin"))
	if err := json.Unmarshal([]byte(readRBACBody(t, resp)), &after); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if after.Status != storage.ChainConsistent {
		t.Fatalf("status after an audited operation = %q, want %q (linkage %+v, content %+v)",
			after.Status, storage.ChainConsistent, after.Linkage.Break, after.Content.Break)
	}
	if after.Linkage.Entries == 0 {
		t.Error("the chain reports no entries after an operation that audits")
	}
	if after.Linkage.HeadHash == "" {
		t.Error("no head hash is reported; a head recorded outside this database is the only " +
			"thing that would catch a wholesale rewrite, and it cannot be recorded if it is not published")
	}
}

// TestVerifyAuditWritesNoAuditEntry. A verification that appended would move
// the head of the chain it had just verified on every read of it.
func TestVerifyAuditWritesNoAuditEntry(t *testing.T) {
	h := newRBACHarness(t)
	admin := operator("user:root", "admin")

	h.do(t, http.MethodPost, "/api/v1/actions/evaluate", `{"incident_id":"inc-missing","action_type":"`+
		rbacKnownActionType+`"}`, admin)

	read := func() int64 {
		t.Helper()
		var report storage.AuditChainReport
		resp := h.do(t, http.MethodGet, verifyPath, "", admin)
		if err := json.Unmarshal([]byte(readRBACBody(t, resp)), &report); err != nil {
			t.Fatalf("decode report: %v", err)
		}
		return report.Linkage.Entries
	}
	before := read()
	read()
	if after := read(); after != before {
		t.Errorf("the trail grew from %d to %d entries across verifications that should leave no trace",
			before, after)
	}
}

const anchorPath = "/api/v1/audit/anchor"

// TestTheAnchorEndpointsAreAdministratorOnly. An anchor names the trail's head
// hash and its length; the check tells a caller whether the trail was rewritten.
// Both belong with the trail itself.
func TestTheAnchorEndpointsAreAdministratorOnly(t *testing.T) {
	h := newRBACHarness(t)
	admin := operator("user:root", "admin")

	// Something to anchor.
	h.do(t, http.MethodPost, "/api/v1/actions/evaluate",
		`{"incident_id":"inc-missing","action_type":"`+rbacKnownActionType+`"}`, admin)

	for _, tc := range []struct {
		name    string
		method  string
		body    string
		headers map[string]string
		want    int
		code    string
	}{
		{"issue, anonymous", http.MethodGet, "", anonymous(), http.StatusUnauthorized, httpx.CodeUnauthorized},
		{"issue, analyst", http.MethodGet, "", operator("user:ana", "analyst"), http.StatusForbidden, httpx.CodeForbidden},
		{"check, anonymous", http.MethodPost, `{}`, anonymous(), http.StatusUnauthorized, httpx.CodeUnauthorized},
		{"check, analyst", http.MethodPost, `{}`, operator("user:ana", "analyst"), http.StatusForbidden, httpx.CodeForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.do(t, tc.method, anchorPath, tc.body, tc.headers)
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
			assertErrorEnvelope(t, resp, tc.code)
		})
	}
}

// TestAnIssuedAnchorChecksOutAndSaysWhereToKeepIt.
//
// The round trip, and the instruction that makes the artefact worth anything.
func TestAnIssuedAnchorChecksOutAndSaysWhereToKeepIt(t *testing.T) {
	h := newRBACHarness(t)
	admin := operator("user:root", "admin")
	h.do(t, http.MethodPost, "/api/v1/actions/evaluate",
		`{"incident_id":"inc-missing","action_type":"`+rbacKnownActionType+`"}`, admin)

	resp := h.do(t, http.MethodGet, anchorPath, "", admin)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, readRBACBody(t, resp))
	}
	raw := readRBACBody(t, resp)
	var anchor storage.AuditAnchor
	if err := json.Unmarshal([]byte(raw), &anchor); err != nil {
		t.Fatalf("decode anchor: %v", err)
	}
	if anchor.EntryHash == "" || anchor.Sequence <= 0 || anchor.ChainID == "" {
		t.Fatalf("anchor is not usable: %+v", anchor)
	}
	if anchor.Keep == "" || !strings.Contains(anchor.Keep, "outside") {
		t.Errorf("the anchor does not say where to keep it: %q\n"+
			"An anchor left in the system it describes is evidence of nothing, and a "+
			"document nobody opens is not where that belongs.", anchor.Keep)
	}

	// Straight back: intact.
	resp = h.do(t, http.MethodPost, anchorPath, raw, admin)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("check status = %d, want 200: %s", resp.StatusCode, readRBACBody(t, resp))
	}
	var report storage.AuditAnchorReport
	if err := json.Unmarshal([]byte(readRBACBody(t, resp)), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.Verdict != storage.AnchorIntact {
		t.Fatalf("verdict = %q, want %q (%s)", report.Verdict, storage.AnchorIntact, report.Detail)
	}
	if report.Attests != storage.AnchorAttests {
		t.Errorf("attests = %q, want the fixed qualification", report.Attests)
	}

	// An anchor naming a hash the trail does not hold is reported, not accepted,
	// and still answers 200 so the bad news cannot be read as an outage.
	tampered := anchor
	tampered.EntryHash = strings.Repeat("0", 64)
	body, err := json.Marshal(tampered)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp = h.do(t, http.MethodPost, anchorPath, string(body), admin)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 even on a bad verdict", resp.StatusCode)
	}
	if err := json.Unmarshal([]byte(readRBACBody(t, resp)), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.Verdict != storage.AnchorEntryAltered {
		t.Errorf("verdict = %q, want %q", report.Verdict, storage.AnchorEntryAltered)
	}
}
