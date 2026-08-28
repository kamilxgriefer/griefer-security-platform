package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
)

// canon is the read side: the side that has to agree with whatever PostgreSQL
// hands back.
func canon(t *testing.T, raw string) []byte {
	t.Helper()
	got, err := audit.CanonicalDetailsFromRaw([]byte(raw))
	if err != nil {
		t.Fatalf("CanonicalDetailsFromRaw(%s) error = %v", raw, err)
	}
	return got
}

// TestEquivalentNumberSpellingsCanonicaliseIdentically is the test standing
// between this platform and a verifier that cries tampering on healthy rows.
//
// PostgreSQL stores jsonb numbers as NUMERIC and re-renders them on output. It
// is entitled to return 1e+21 where the writer sent 1000000000000000000000, or
// to drop the trailing zero of 1.50. If any of those changed the hash, every
// affected entry would read as altered.
func TestEquivalentNumberSpellingsCanonicaliseIdentically(t *testing.T) {
	equivalent := [][2]string{
		{`{"n":1e21}`, `{"n":1000000000000000000000}`},
		{`{"n":1.50}`, `{"n":1.5}`},
		{`{"n":0}`, `{"n":-0}`},
		{`{"n":1E2}`, `{"n":100}`},
		{`{"n":1.0}`, `{"n":1}`},
		{`{"n":0.00}`, `{"n":0e99}`},
	}
	for _, pair := range equivalent {
		if a, b := canon(t, pair[0]), canon(t, pair[1]); !bytes.Equal(a, b) {
			t.Errorf("%s and %s canonicalise differently:\n %x\n %x", pair[0], pair[1], a, b)
		}
	}
}

// TestDistinctValuesCanonicaliseDifferently is the other half: folding too much
// would let an attacker edit a value without moving the hash.
func TestDistinctValuesCanonicaliseDifferently(t *testing.T) {
	distinct := [][2]string{
		// The string "42" must not collide with the number 42. This is why the
		// encoding is type-tagged rather than JSON text.
		{`{"n":42}`, `{"n":"42"}`},
		{`{"n":1}`, `{"n":10}`},
		{`{"n":1}`, `{"n":0.1}`},
		{`{"n":1}`, `{"n":-1}`},
		// An empty object is not the absence of details.
		{`{}`, `null`},
		{`{"a":1,"b":2}`, `{"a":2,"b":1}`},
		{`{"a":true}`, `{"a":false}`},
		{`{"a":[1,2]}`, `{"a":[2,1]}`},
		{`{"a":null}`, `{"a":""}`},
	}
	for _, pair := range distinct {
		if a, b := canon(t, pair[0]), canon(t, pair[1]); bytes.Equal(a, b) {
			t.Errorf("%s and %s canonicalise identically to %x", pair[0], pair[1], a)
		}
	}
}

// TestKeyOrderDoesNotReachTheHash. Go sorts map keys lexicographically when
// marshalling; jsonb sorts by length then bytes. Neither may matter.
func TestKeyOrderDoesNotReachTheHash(t *testing.T) {
	if a, b := canon(t, `{"zz":1,"a":2}`), canon(t, `{"a":2,"zz":1}`); !bytes.Equal(a, b) {
		t.Errorf("key order changed the canonical form:\n %x\n %x", a, b)
	}
}

// TestALargeIntegerSurvivesTheCanonicalForm. Decoded into float64,
// 9007199254740993 becomes 9007199254740992 -- the trail would then record a
// number nobody wrote, and the two stores would disagree about which.
func TestALargeIntegerSurvivesTheCanonicalForm(t *testing.T) {
	big := int64(9007199254740993)
	_, _, fromValue, err := audit.CanonicalDetails(map[string]any{"n": big})
	if err != nil {
		t.Fatalf("CanonicalDetails() error = %v", err)
	}
	fromRaw := canon(t, `{"n":9007199254740993}`)
	if !bytes.Equal(fromValue, fromRaw) {
		t.Fatalf("write side and read side disagree:\n %x\n %x", fromValue, fromRaw)
	}
	if neighbour := canon(t, `{"n":9007199254740992}`); bytes.Equal(fromRaw, neighbour) {
		t.Error("9007199254740993 and 9007199254740992 canonicalise identically; precision was lost")
	}
}

// TestTheWriteSideAgreesWithTheReadSide over the awkward shapes a round trip
// through jsonb actually changes.
func TestTheWriteSideAgreesWithTheReadSide(t *testing.T) {
	cases := []map[string]any{
		nil,
		{},
		{"a": 1, "b": "two", "c": true, "d": nil},
		{"nested": map[string]any{"x": []any{1, "2", false}}},
		{"list": []string{"a", "b"}},
		{"unicode": "zazolc gesla jazn — ✓"},
		{"float": 1.5, "negative": -3, "zero": 0},
		{"empty_list": []any{}, "empty_map": map[string]any{}},
	}
	for _, details := range cases {
		stored, _, fromValue, err := audit.CanonicalDetails(details)
		if err != nil {
			t.Fatalf("CanonicalDetails(%v) error = %v", details, err)
		}
		fromRaw, err := audit.CanonicalDetailsFromRaw(stored)
		if err != nil {
			t.Fatalf("CanonicalDetailsFromRaw(%s) error = %v", stored, err)
		}
		if !bytes.Equal(fromValue, fromRaw) {
			t.Errorf("details %v: write side %x != read side %x", details, fromValue, fromRaw)
		}
	}
}

func chainTestEntry() *audit.Entry {
	return &audit.Entry{
		ID:          "aud-1",
		Timestamp:   time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
		Actor:       "user:ana",
		ActorRole:   "admin",
		Action:      audit.ActionPolicyEvaluated,
		SubjectType: audit.SubjectAction,
		SubjectID:   "act-1",
		Outcome:     audit.OutcomeSuccess,
		Reason:      "allowed by policy",
		RequestID:   "req-1",
	}
}

func hashOf(t *testing.T, e *audit.Entry) string {
	t.Helper()
	_, _, canonical, err := audit.CanonicalDetails(e.Details)
	if err != nil {
		t.Fatalf("CanonicalDetails() error = %v", err)
	}
	return audit.ChainHash("chn-1", "prev", e, canonical)
}

// TestEveryHashedFieldChangesTheHash. A field outside the hash is a field an
// attacker may edit freely.
func TestEveryHashedFieldChangesTheHash(t *testing.T) {
	base := hashOf(t, chainTestEntry())
	mutations := map[string]func(*audit.Entry){
		"id":           func(e *audit.Entry) { e.ID = "aud-2" },
		"timestamp":    func(e *audit.Entry) { e.Timestamp = e.Timestamp.Add(time.Second) },
		"actor":        func(e *audit.Entry) { e.Actor = "user:bo" },
		"actor_role":   func(e *audit.Entry) { e.ActorRole = "analyst" },
		"action":       func(e *audit.Entry) { e.Action = audit.ActionActionSimulated },
		"subject_type": func(e *audit.Entry) { e.SubjectType = audit.SubjectIncident },
		"subject_id":   func(e *audit.Entry) { e.SubjectID = "act-2" },
		"outcome":      func(e *audit.Entry) { e.Outcome = audit.OutcomeDenied },
		"reason":       func(e *audit.Entry) { e.Reason = "denied by policy" },
		"request_id":   func(e *audit.Entry) { e.RequestID = "req-2" },
		"details":      func(e *audit.Entry) { e.Details = map[string]any{"result": audit.ResultDenied} },
	}
	for name, mutate := range mutations {
		e := chainTestEntry()
		mutate(e)
		if got := hashOf(t, e); got == base {
			t.Errorf("changing %s did not change the hash", name)
		}
	}
	e := chainTestEntry()
	_, _, canonical, err := audit.CanonicalDetails(e.Details)
	if err != nil {
		t.Fatalf("CanonicalDetails() error = %v", err)
	}
	if audit.ChainHash("chn-2", "prev", e, canonical) == base {
		t.Error("changing chain_id did not change the hash")
	}
	if audit.ChainHash("chn-1", "other", e, canonical) == base {
		t.Error("changing prev_hash did not change the hash")
	}
}

// TestFieldsCannotRunTogether. Without length prefixes, actor "ab" with action
// "c" hashes the same as actor "a" with action "bc", and an attacker gets to
// move a character across a field boundary for free.
func TestFieldsCannotRunTogether(t *testing.T) {
	a, b := chainTestEntry(), chainTestEntry()
	a.Actor, a.Action = "ab", "c"
	b.Actor, b.Action = "a", "bc"
	if hashOf(t, a) == hashOf(t, b) {
		t.Error("two entries differing only in where a field boundary falls hash identically")
	}
}

// TestSubMicrosecondPrecisionIsOutsideTheHash. TIMESTAMPTZ cannot hold it, so
// hashing it would make every entry fail verification after a round trip.
func TestSubMicrosecondPrecisionIsOutsideTheHash(t *testing.T) {
	a, b := chainTestEntry(), chainTestEntry()
	b.Timestamp = b.Timestamp.Add(999 * time.Nanosecond)
	if hashOf(t, a) != hashOf(t, b) {
		t.Error("a sub-microsecond difference changed the hash; PostgreSQL cannot store it, so verification would fail on healthy rows")
	}
	c := chainTestEntry()
	c.Timestamp = c.Timestamp.Add(time.Microsecond)
	if hashOf(t, a) == hashOf(t, c) {
		t.Error("a one-microsecond difference did not change the hash")
	}
}

// TestTheHashIsIndependentOfTheCallersTimeZone. The same instant expressed in
// two zones is the same instant, and must not read as two entries.
func TestTheHashIsIndependentOfTheCallersTimeZone(t *testing.T) {
	a := chainTestEntry()
	b := chainTestEntry()
	b.Timestamp = a.Timestamp.In(time.FixedZone("CEST", 2*60*60))
	if hashOf(t, a) != hashOf(t, b) {
		t.Error("the same instant in a different zone produced a different hash")
	}
}

// TestSanitiseEntryReplacesRatherThanRefuses.
//
// Reason on an accepted event is built from the producer's own source_name,
// which ingest bounds in length but not in content. A NUL byte there is valid
// JSON and passes validation, and a TEXT column will not store it. If the audit
// path refused the entry, anyone able to submit one event could have it
// recorded with no audit entry describing it -- recordAudit logs a failed write
// and carries on.
func TestSanitiseEntryReplacesRatherThanRefuses(t *testing.T) {
	e := chainTestEntry()
	e.Reason = "event accepted from cloud_audit/evil\x00name"
	e.SubjectID = "evt-\x00"
	audit.SanitiseEntry(e)

	if strings.ContainsRune(e.Reason, 0) || strings.ContainsRune(e.SubjectID, 0) {
		t.Fatalf("a NUL survived sanitisation: reason=%q subject_id=%q", e.Reason, e.SubjectID)
	}
	if !strings.Contains(e.Reason, "evil") {
		t.Errorf("sanitisation discarded more than the offending byte: %q", e.Reason)
	}
	// The entry has to say that it was changed. Silently altering a recorded
	// value would be the same defect as coercing Details to suit the hash.
	changed, ok := e.Details["sanitised_fields"].([]any)
	if !ok {
		t.Fatalf("Details does not record which fields were changed: %v", e.Details)
	}
	got := map[string]bool{}
	for _, f := range changed {
		got[f.(string)] = true
	}
	if !got["reason"] || !got["subject_id"] {
		t.Errorf("sanitised_fields = %v, want both reason and subject_id", changed)
	}
}

// TestSanitiseEntryLeavesACleanEntryAlone, so that an ordinary entry does not
// gain a marker key -- which would change its hash for no reason.
func TestSanitiseEntryLeavesACleanEntryAlone(t *testing.T) {
	e := chainTestEntry()
	e.Details = map[string]any{"result": audit.ResultAllowed}
	before := hashOf(t, e)
	audit.SanitiseEntry(e)
	if _, ok := e.Details["sanitised_fields"]; ok {
		t.Error("a clean entry gained a sanitised_fields marker")
	}
	if hashOf(t, e) != before {
		t.Error("sanitising a clean entry changed its hash")
	}
}

// TestPrepareBoundsOversizeDetailsRatherThanRefusingTheEntry.
//
// Refusing would hand an attacker who can influence Details a way to suppress
// the entry describing their own event, because both audit call sites log and
// carry on when Prepare fails.
func TestPrepareBoundsOversizeDetailsRatherThanRefusingTheEntry(t *testing.T) {
	rec, err := audit.NewRecorder(noopSink{})
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	huge := map[string]any{"blob": strings.Repeat("x", audit.MaxDetailsBytes*2)}
	got, err := rec.Prepare(audit.Entry{
		Action: audit.ActionEventIngested, Outcome: audit.OutcomeSuccess, Details: huge,
	})
	if err != nil {
		t.Fatalf("Prepare() refused an oversize Details: %v -- this is a suppression primitive", err)
	}
	if _, ok := got.Details["details_omitted"]; !ok {
		t.Errorf("oversize Details was kept rather than replaced with a marker: %v", got.Details)
	}
	if got.Details["details_key_count"] != 1 {
		t.Errorf("the marker does not record what was dropped: %v", got.Details)
	}
}

// TestPrepareZeroesChainStateSuppliedByTheCaller. A caller that could name its
// own predecessor could splice an entry in at a position of its choosing.
func TestPrepareZeroesChainStateSuppliedByTheCaller(t *testing.T) {
	rec, err := audit.NewRecorder(noopSink{})
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	got, err := rec.Prepare(audit.Entry{
		Action: audit.ActionEventIngested, Outcome: audit.OutcomeSuccess,
		ChainID: "chn-attacker", PrevHash: "deadbeef", EntryHash: "cafebabe",
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if got.ChainID != "" || got.PrevHash != "" || got.EntryHash != "" {
		t.Errorf("Prepare kept caller-supplied chain state: %+v", got)
	}
}

// TestPrepareTruncatesToMicroseconds, so that the memory store cannot keep a
// precision PostgreSQL discards.
func TestPrepareTruncatesToMicroseconds(t *testing.T) {
	odd := time.Date(2026, 8, 27, 12, 0, 0, 123456789, time.UTC)
	rec, err := audit.NewRecorderWithClock(noopSink{}, func() time.Time { return odd })
	if err != nil {
		t.Fatalf("NewRecorderWithClock() error = %v", err)
	}
	got, err := rec.Prepare(audit.Entry{Action: audit.ActionEventIngested, Outcome: audit.OutcomeSuccess})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if got.Timestamp.Nanosecond()%1000 != 0 {
		t.Errorf("Prepare kept sub-microsecond precision: %v", got.Timestamp)
	}
	if want := odd.Truncate(time.Microsecond); !got.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %v, want %v", got.Timestamp, want)
	}
}

// TestSanitiseEntryReachesIntoDetails.
//
// Details is stored as jsonb, which refuses a NUL exactly as TEXT does, and it
// carries producer-derived values of its own -- the quarantine entry records
// the offending source_name there. Sanitising only the scalar fields would have
// moved the suppression path rather than closed it.
func TestSanitiseEntryReachesIntoDetails(t *testing.T) {
	e := chainTestEntry()
	e.Details = map[string]any{
		"source_name":      "evil\x00name",
		"quarantined_keys": []string{"griefer.control\x00", "clean.key"},
		"nested":           map[string]any{"deep": []any{"bad\x00", 42}},
		"count":            7,
	}
	audit.SanitiseEntry(e)

	flat, err := json.Marshal(e.Details)
	if err != nil {
		t.Fatalf("marshal details: %v", err)
	}
	if bytes.ContainsRune(flat, 0) {
		t.Fatalf("a NUL survived inside Details: %q", flat)
	}
	if !strings.Contains(string(flat), "evil") || !strings.Contains(string(flat), "clean.key") {
		t.Errorf("sanitisation discarded more than the offending bytes: %s", flat)
	}
	if e.Details["count"] != 7 {
		t.Errorf("a non-string value was disturbed: %v", e.Details["count"])
	}
	changed, _ := e.Details["sanitised_fields"].([]any)
	found := false
	for _, c := range changed {
		if c == "details" {
			found = true
		}
	}
	if !found {
		t.Errorf("sanitised_fields = %v, want it to name details", changed)
	}
}

// TestSanitiseEntryDoesNotEditTheCallersDetails. An audit path that reached
// back into the operation it describes would be changing the thing it is
// supposed to be recording.
func TestSanitiseEntryDoesNotEditTheCallersDetails(t *testing.T) {
	callers := map[string]any{"source_name": "evil\x00name"}
	e := chainTestEntry()
	e.Details = callers
	audit.SanitiseEntry(e)

	if callers["source_name"] != "evil\x00name" {
		t.Errorf("the caller's map was edited: %q", callers["source_name"])
	}
	if _, ok := callers["sanitised_fields"]; ok {
		t.Error("the caller's map gained a marker key")
	}
}

// noopSink lets Prepare be tested without a store. Prepare does not write.
type noopSink struct{}

func (noopSink) Append(context.Context, *audit.Entry) error { return nil }

func (noopSink) List(context.Context, int, int) ([]*audit.Entry, int, error) {
	return nil, 0, nil
}
