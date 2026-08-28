package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// This file is the ONLY definition of an audit entry's canonical form.
//
// The hash is computed from a Go value on the way in and recomputed from what
// the database returned on the way out. Anywhere those two disagree, the
// verifier reports tampering on a row nobody touched — which is worse than
// having no verifier at all, because it destroys the signal the verifier exists
// to carry. A second implementation would drift, and the drift would surface
// exactly there, so there is one implementation and both stores call it.
//
// The decision and its limits are recorded in
// docs/adr/0007-hash-chained-audit-without-anchor.md.

const (
	// GenesisPrevHash is the prev_hash of the first entry in a chain.
	//
	// The empty string is a claim — this entry starts the chain — where SQL
	// NULL is the absence of one, which is what a row written before the chain
	// existed carries. The nullable() convention in internal/storage that
	// collapses "" into NULL deliberately does not apply to prev_hash:
	// collapsing the two would let an unchained row read as a genesis, and that
	// is precisely what deleting a prefix of the trail looks like.
	GenesisPrevHash = ""

	// ChainHashVersion is the canonical form this build implements, recorded on
	// every row.
	//
	// A verifier meeting a version it does not implement reports that row
	// unverifiable rather than broken. "This binary is older than that row" and
	// "someone edited that row" must not look the same to whoever was woken up.
	ChainHashVersion = 1

	// MaxDetailsBytes bounds the canonical JSON of Details.
	//
	// Details carries producer-derived values, and CONTRIBUTING.md is explicit
	// that "it would never be that large in practice" is not a limit. The
	// number is chosen to be generous against the largest thing GRIEFER writes
	// today — a quarantined-label key list — rather than derived from a
	// measured distribution, which is worth knowing before treating it as a
	// tuned value.
	MaxDetailsBytes = 8 << 10
)

// chainDomain separates this hash from every other SHA-256 in the platform, so
// that a digest computed for some other purpose can never be mistaken for a
// chain link. The version in it moves with ChainHashVersion.
const chainDomain = "griefer.audit.chain.v1\n"

// Type tags for the Details encoding.
//
// Details is encoded as type-tagged, length-prefixed binary rather than as JSON
// text. There is then no escaping question to get wrong, and the string "42"
// cannot collide with the number 42.
const (
	tagNull   byte = 0x00
	tagFalse  byte = 0x01
	tagTrue   byte = 0x02
	tagNumber byte = 0x03
	tagString byte = 0x04
	tagArray  byte = 0x05
	tagObject byte = 0x06
)

// ErrDetailsNotCanonical reports Details that cannot be brought to canonical
// form. It is unreachable on the write path — see CanonicalDetails — so meeting
// it while verifying means the column holds something no GRIEFER write produced.
var ErrDetailsNotCanonical = errors.New("audit: details cannot be canonicalised")

// CanonicalDetails returns the bytes a store persists, the value tree it keeps,
// and the canonical encoding that goes into the hash.
//
// All three come from one call because they must agree. Hashing one
// representation and storing another is how a verify endpoint comes to report
// tampering on a row nobody touched.
//
// A nil map returns (nil, nil, []byte{tagNull}, nil): nil Details becomes SQL
// NULL, which stays distinguishable from an empty object.
//
// The write side deliberately round-trips its own json.Marshal output back
// through the same decoder the read side uses. That extra decode per audit
// write is what turns an open-ended list of "things that might differ between a
// Go value and jsonb" into a closed one: no Go type reaches the encoder, only
// the JSON value domain. A struct or a map[int]string in Details, which
// json.Marshal emits in declaration order and in numeric key order, arrives at
// the encoder as the same map[string]any it will be read back as.
func CanonicalDetails(d map[string]any) (stored []byte, tree map[string]any, canonical []byte, err error) {
	if d == nil {
		return nil, nil, []byte{tagNull}, nil
	}
	stored, err = json.Marshal(d)
	if err != nil {
		// NaN and ±Inf land here: json.Marshal refuses them before the
		// canonicaliser could. A caller that bypassed Recorder.Prepare and put
		// one in Details has a programming error, and it should fail loudly.
		return nil, nil, nil, fmt.Errorf("audit: encode details: %w", err)
	}
	value, err := decodeJSONValue(stored)
	if err != nil {
		return nil, nil, nil, err
	}
	m, ok := value.(map[string]any)
	if !ok {
		// json.Marshal of a non-nil map always yields a JSON object, so this is
		// unreachable rather than merely unlikely. It is checked because the
		// alternative to checking is a type assertion panic in the audit path.
		return nil, nil, nil, fmt.Errorf("%w: marshalled details decoded as %T", ErrDetailsNotCanonical, value)
	}
	canonical, err = canonicalEncode(m)
	if err != nil {
		return nil, nil, nil, err
	}
	return stored, m, canonical, nil
}

// CanonicalDetailsFromRaw is the read side of CanonicalDetails: the canonical
// encoding computed from the bytes the database returned rather than from a Go
// value.
//
// Both sides run the same decoder over the same JSON, so nothing about how
// jsonb chose to re-render it — key order, whitespace, how a NUMERIC prints —
// can reach the hash.
//
// An empty slice is SQL NULL and encodes as tagNull, the same as a nil map on
// the write side. A literal JSON `null` in the column would encode identically;
// that conflation is harmless because no GRIEFER write can produce one — a
// non-nil map marshals to an object and a nil map is never written at all.
func CanonicalDetailsFromRaw(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return []byte{tagNull}, nil
	}
	value, err := decodeJSONValue(raw)
	if err != nil {
		return nil, err
	}
	return canonicalEncode(value)
}

// decodeJSONValue decodes exactly one JSON value into the closed domain the
// encoder understands: nil, bool, json.Number, string, []any, map[string]any.
//
// UseNumber is what keeps a large integer out of float64. Without it,
// 9007199254740993 decodes to 9007199254740992 and the trail records a number
// its producer did not write.
func decodeJSONValue(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDetailsNotCanonical, err)
	}
	// Trailing content would mean two values where the contract is one, and
	// hashing only the first would leave the rest outside the chain.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: details is not a single JSON value", ErrDetailsNotCanonical)
	}
	return v, nil
}

func canonicalEncode(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// encodeValue writes v in the type-tagged, length-prefixed form.
//
//	null    0x00
//	false   0x01
//	true    0x02
//	number  0x03 || len||bytes of the canonical decimal form
//	string  0x04 || len||bytes of the UTF-8 text
//	array   0x05 || uint64be(n) || each element
//	object  0x06 || uint64be(n) || (len||key, value) * n, keys ascending by byte
func encodeValue(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteByte(tagNull)
	case bool:
		if t {
			buf.WriteByte(tagTrue)
		} else {
			buf.WriteByte(tagFalse)
		}
	case json.Number:
		c, err := canonicalNumber(t)
		if err != nil {
			return err
		}
		buf.WriteByte(tagNumber)
		writeLengthPrefixed(buf, c)
	case string:
		buf.WriteByte(tagString)
		writeLengthPrefixed(buf, t)
	case []any:
		buf.WriteByte(tagArray)
		writeCount(buf, len(t))
		for _, e := range t {
			if err := encodeValue(buf, e); err != nil {
				return err
			}
		}
	case map[string]any:
		buf.WriteByte(tagObject)
		writeCount(buf, len(t))
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// Ascending by raw UTF-8 byte order. Go sorts map keys
		// lexicographically when marshalling and jsonb sorts by length then
		// bytes; sorting here means neither reaches the hash.
		sort.Strings(keys)
		for _, k := range keys {
			writeLengthPrefixed(buf, k)
			if err := encodeValue(buf, t[k]); err != nil {
				return err
			}
		}
	default:
		// Reached only if decodeJSONValue's domain is widened without this
		// switch following, which would silently change every hash.
		return fmt.Errorf("%w: unexpected type %T", ErrDetailsNotCanonical, v)
	}
	return nil
}

// writeLengthPrefixed writes len(s) as a big-endian uint64 and then s.
//
// Every field is length-prefixed so the concatenation is injective: actor="ab"
// with action="c" cannot produce the same bytes as actor="a" with action="bc".
// Fixed-width prefixes rather than decimal netstrings — no parsing, and no
// length-of-the-length edge case.
func writeLengthPrefixed(buf *bytes.Buffer, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	buf.Write(n[:])
	buf.WriteString(s)
}

func writeCount(buf *bytes.Buffer, n int) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	buf.Write(b[:])
}

// canonicalNumber normalises a JSON number to one (mantissa, exponent) form,
// working on the decimal digits and never through float64.
//
// PostgreSQL stores jsonb numbers as NUMERIC and re-renders them on output.
// Whether it returns 1e+21 or 1000000000000000000000, and whether it keeps the
// trailing zero of 1.50, are server-side choices. Normalising by value makes
// the question moot: any rendering of the same NUMERIC normalises to the same
// bytes. Going through float64 instead would make the hash depend both on that
// rendering and on strconv's shortest-representation algorithm holding still
// across Go releases.
//
//	42                      -> 42e0
//	1e21                    -> 1e21
//	1000000000000000000000  -> 1e21
//	0.1                     -> 1e-1
//	1.50                    -> 15e-1
//	-0                      -> 0
//	9007199254740993        -> 9007199254740993e0
func canonicalNumber(n json.Number) (string, error) {
	s := n.String()
	if s == "" {
		return "", fmt.Errorf("%w: empty number", ErrDetailsNotCanonical)
	}

	i := 0
	neg := false
	if s[i] == '-' {
		neg = true
		i++
	}
	intStart := i
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	intDigits := s[intStart:i]

	var fracDigits string
	if i < len(s) && s[i] == '.' {
		i++
		fracStart := i
		for i < len(s) && isDigit(s[i]) {
			i++
		}
		fracDigits = s[fracStart:i]
	}

	var expDigits string
	sawExponent := false
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		sawExponent = true
		i++
		expStart := i
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		digitsStart := i
		for i < len(s) && isDigit(s[i]) {
			i++
		}
		if i > digitsStart {
			expDigits = s[expStart:i]
		}
	}

	// An exponent marker with no digits after it, a number with no digits at
	// all, or anything left over: all malformed. json.Decoder and PostgreSQL
	// both validate before this is reached, so meeting one means the value did
	// not come through either.
	if i != len(s) || (intDigits == "" && fracDigits == "") || (sawExponent && expDigits == "") {
		return "", fmt.Errorf("%w: malformed number %q", ErrDetailsNotCanonical, s)
	}

	exp10 := int64(0)
	if expDigits != "" {
		v, err := strconv.ParseInt(expDigits, 10, 64)
		if err != nil {
			return "", fmt.Errorf("%w: exponent in %q is out of range", ErrDetailsNotCanonical, s)
		}
		exp10 = v
	}

	// Removing the decimal point scales the mantissa up by the fraction length.
	var err error
	if exp10, err = addExp(exp10, -int64(len(fracDigits))); err != nil {
		return "", fmt.Errorf("%w: %q", err, s)
	}

	mantissa := strings.TrimLeft(intDigits+fracDigits, "0")
	trailing := 0
	for len(mantissa)-trailing > 0 && mantissa[len(mantissa)-trailing-1] == '0' {
		trailing++
	}
	mantissa = mantissa[:len(mantissa)-trailing]
	if mantissa == "" {
		// Every spelling of zero — 0, -0, 0.00, 0e99, 0E-7 — folds here, so the
		// sign and the exponent of a zero cannot make two equal values hash
		// differently.
		return "0", nil
	}
	if exp10, err = addExp(exp10, int64(trailing)); err != nil {
		return "", fmt.Errorf("%w: %q", err, s)
	}

	var b strings.Builder
	if neg {
		b.WriteByte('-')
	}
	b.WriteString(mantissa)
	b.WriteByte('e')
	b.WriteString(strconv.FormatInt(exp10, 10))
	return b.String(), nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// addExp adds delta to exp, refusing an overflow rather than wrapping silently.
//
// Unreachable from json.Marshal output, whose exponents come from float64 and
// so stay within ±324. It fires only for a number read back out of the
// database that no GRIEFER write could have put there, which the verifier
// reports rather than ignores.
func addExp(exp, delta int64) (int64, error) {
	sum := exp + delta
	if (delta > 0 && sum < exp) || (delta < 0 && sum > exp) {
		return 0, fmt.Errorf("%w: exponent overflows int64", ErrDetailsNotCanonical)
	}
	return sum, nil
}

// ChainHash returns the entry's hash: SHA-256 over its canonical serialisation
// together with its predecessor's hash, hex-encoded lowercase.
//
// It is infallible by construction — every failable step happened in
// CanonicalDetails — which is what lets the memory store do its hashing under a
// lock it can no longer fail inside.
//
// Sequence is deliberately NOT hashed. It does not exist until the INSERT
// returns, and computing the hash afterwards would need an UPDATE, which the
// append-only trigger refuses. Position is pinned by prev_hash instead:
// swapping two rows' sequence values changes the walk order and breaks the link
// at that point.
func ChainHash(chainID, prevHash string, e *Entry, canonicalDetails []byte) string {
	h := sha256.New()
	_, _ = io.WriteString(h, chainDomain)
	fields := [...]string{
		// The version is hashed. Outside the pre-image it is a free-floating
		// column that alone decides whether a verifier recomputes a row at all
		// — so an edit could be paired with a version bump and the content
		// check would skip the row it should have caught.
		strconv.Itoa(ChainHashVersion),
		chainID,
		prevHash,
		e.ID,
		// UnixMicro, not a formatted string: TIMESTAMPTZ holds microseconds and
		// time.Time holds nanoseconds, so hashing the truncated integer keeps
		// the sub-microsecond part outside the hash by construction rather than
		// by hoping the driver rounds the way Go does.
		strconv.FormatInt(e.Timestamp.UTC().UnixMicro(), 10),
		e.Actor,
		e.ActorRole,
		e.Action,
		e.SubjectType,
		e.SubjectID,
		e.Outcome,
		e.Reason,
		e.RequestID,
	}
	var n [8]byte
	for _, f := range fields {
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		_, _ = h.Write(n[:])
		_, _ = io.WriteString(h, f)
	}
	_, _ = h.Write(canonicalDetails)
	return hex.EncodeToString(h.Sum(nil))
}

// SanitiseEntry replaces characters a PostgreSQL TEXT column cannot store, and
// records in Details which fields it had to change.
//
// It REPLACES; it does not refuse. That is the whole point, and the reason it is
// not called ValidateEntry.
//
// Not every field on an entry is platform-generated. `Reason` on an accepted
// event is built from the producer's own `source_name`, which the ingest schema
// bounds in length but not in content, and `SubjectID` carries a
// producer-supplied event id. A NUL byte in either is valid JSON, passes ingest
// validation, and makes the INSERT fail — and `recordAudit` logs a failed audit
// write and carries on. A caller that refused here would therefore hand anyone
// who can submit one event a way to have that event recorded with no audit
// entry describing it.
//
// So the trail keeps the entry and says, in the entry, that it had to change
// something. Losing a character of an attacker-chosen name is a far smaller loss
// than losing the record that they acted.
//
// U+FFFD is the replacement, which is what a UTF-8 decoder would already
// substitute; strings.ToValidUTF8 handles the invalid-sequence case and the
// explicit NUL replacement handles the byte that is valid UTF-8 but that
// PostgreSQL still refuses.
//
// Details is sanitised too, and for the same reason rather than a different
// one. jsonb refuses a NUL exactly as TEXT does, and Details carries
// producer-derived values of its own — the quarantine entry records the
// offending source_name there. Leaving it out would have moved the suppression
// path rather than closed it. Its SIZE is bounded separately, by
// boundDetails, and by replacement rather than refusal for the same reason
// again.
func SanitiseEntry(e *Entry) {
	if e == nil {
		return
	}
	fields := [...]struct {
		name  string
		value *string
	}{
		{"id", &e.ID},
		{"actor", &e.Actor},
		{"actor_role", &e.ActorRole},
		{"action", &e.Action},
		{"subject_type", &e.SubjectType},
		{"subject_id", &e.SubjectID},
		{"outcome", &e.Outcome},
		{"reason", &e.Reason},
		{"request_id", &e.RequestID},
	}
	var changed []any
	for _, f := range fields {
		if clean := sanitiseString(*f.value); clean != *f.value {
			*f.value = clean
			changed = append(changed, f.name)
		}
	}
	// Details too. It is stored as jsonb, which refuses a NUL just as TEXT
	// does, and it carries producer-derived values of its own -- the quarantine
	// entry records the offending source_name there. Leaving Details out would
	// have moved the suppression path rather than closed it.
	if cleaned, dirty := sanitiseDetails(e.Details); dirty {
		if m, ok := cleaned.(map[string]any); ok {
			e.Details = m
			changed = append(changed, "details")
		}
	}
	if len(changed) == 0 {
		return
	}
	// A fresh map: the caller still owns the one it passed, and an audit path
	// that edited it would be reaching back into the operation it describes.
	annotated := make(map[string]any, len(e.Details)+1)
	for k, v := range e.Details {
		annotated[k] = v
	}
	annotated["sanitised_fields"] = changed
	e.Details = annotated
}

// replacementRune is U+FFFD REPLACEMENT CHARACTER.
const replacementRune = "\uFFFD"

func sanitiseString(s string) string {
	clean := strings.ToValidUTF8(s, replacementRune)
	return strings.ReplaceAll(clean, "\x00", replacementRune)
}

// sanitiseDetails walks the shapes GRIEFER actually puts in Details and returns
// a copy with unstorable characters replaced, plus whether anything changed.
//
// A copy, never an edit in place: the caller still owns the map it passed, and
// an audit path that reached back into the operation it describes would be
// changing the thing it is supposed to be recording.
//
// Values outside these shapes are returned unchanged. They cannot carry a raw
// Go string that jsonb would refuse -- json.Marshal would have to render it
// first, and every renderable string type is covered here.
func sanitiseDetails(v any) (any, bool) {
	switch t := v.(type) {
	case nil:
		return nil, false
	case string:
		clean := sanitiseString(t)
		return clean, clean != t
	case []string:
		out, dirty := make([]string, len(t)), false
		for i, e := range t {
			out[i] = sanitiseString(e)
			dirty = dirty || out[i] != e
		}
		if !dirty {
			return t, false
		}
		return out, true
	case []any:
		out, dirty := make([]any, len(t)), false
		for i, e := range t {
			c, d := sanitiseDetails(e)
			out[i], dirty = c, dirty || d
		}
		if !dirty {
			return t, false
		}
		return out, true
	case map[string]any:
		out, dirty := make(map[string]any, len(t)), false
		for k, e := range t {
			ck := sanitiseString(k)
			c, d := sanitiseDetails(e)
			out[ck], dirty = c, dirty || d || ck != k
		}
		if !dirty {
			return t, false
		}
		return out, true
	default:
		return v, false
	}
}

// boundDetails caps Details at MaxDetailsBytes by REPLACING an oversize map
// with a marker, never by refusing the entry.
//
// The distinction is the whole point. recordAudit logs and returns on a Prepare
// failure and persistEvaluation logs and continues, so any rejection reachable
// from producer-influenced content — quarantined label keys, a source name — is
// a way for an attacker to suppress the audit entry describing their own event.
// Hashing must never become a denial primitive against the trail it protects.
//
// The record then says plainly that there was a payload this size and it was
// not kept, which is a far smaller loss than the entry disappearing.
func boundDetails(d map[string]any) map[string]any {
	if d == nil {
		return nil
	}
	encoded, err := json.Marshal(d)
	if err == nil && len(encoded) <= MaxDetailsBytes {
		return d
	}
	marker := map[string]any{
		"details_omitted":   "exceeded MaxDetailsBytes",
		"details_key_count": len(d),
		"details_max_bytes": MaxDetailsBytes,
	}
	// Carried across the replacement. SanitiseEntry runs first and writes this
	// key, and an entry that dropped it here would stop saying that one of its
	// own fields had been altered.
	if s, ok := d["sanitised_fields"]; ok {
		marker["sanitised_fields"] = s
	}
	if err != nil {
		// Unencodable rather than oversize. The entry still gets written; what
		// it says is that its details could not be represented.
		marker["details_omitted"] = "not encodable as JSON"
		return marker
	}
	marker["details_bytes"] = len(encoded)
	return marker
}
