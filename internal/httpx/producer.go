package httpx

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"regexp"
	"strings"
)

// A producer is the THIRD identity GRIEFER recognises, and the three answer
// different questions:
//
//	service credential  may this connection reach the API at all?
//	producer credential which sensor is this telemetry from?
//	operator assertion  which person is behind this request?
//
// They are ANDed and never ranked. A producer does not satisfy RequireRole and
// never becomes a Principal: RequireRole admits a request with no operator
// because such a request comes from a trusted component acting on nobody's
// behalf, and reading a present producer as a role grant would turn that
// admission into an escalation.
//
// See docs/adr/0009-authenticated-event-producers.md.

// SourceRef is one (source_type, source_name) pair a producer may claim.
type SourceRef struct {
	Type string
	Name string
}

// Producer is an authenticated telemetry source.
type Producer struct {
	Name string
	// Sources is the exact set this producer may claim. No wildcards: the
	// entitlement is the control that closes T1's hole, and a wildcard would
	// return the platform to trusting the body.
	Sources []SourceRef
}

// Zero reports that no producer was authenticated.
func (p Producer) Zero() bool { return p.Name == "" }

// Entitled reports whether this producer may claim the given source identity.
//
// Exact pair matching. A producer entitled to (identity_provider, okta-prod)
// cannot claim (identity_provider, crowdstrike-prod): the second half is the
// half a rule keys on when there is no actor, and it is 128 bytes of free text.
func (p Producer) Entitled(sourceType, sourceName string) bool {
	for _, s := range p.Sources {
		if s.Type == sourceType && s.Name == sourceName {
			return true
		}
	}
	return false
}

const producerKey contextKey = 2

// Headers carrying the producer credential.
//
// Two headers rather than one so the name is a map lookup: a misconfiguration
// then produces "producer okta-prod presented an unknown key" in the log rather
// than "nothing matched", which is the difference between an operator fixing it
// in a minute and an operator guessing.
const (
	HeaderProducer    = "X-Griefer-Producer"
	HeaderProducerKey = "X-Griefer-Producer-Key" //nolint:gosec // a header name, not a credential
)

// producerPattern bounds a producer name.
//
// Tighter than principalPattern, and for the reasons that comment gives plus
// one more: the name becomes an environment-variable suffix, a Prometheus label
// value and the audit Actor, so it is lower-case, short, and free of anything
// that could smuggle a second log line or a metric cardinality explosion.
var producerPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Bounds on the credential headers.
//
// Checked before the pattern, because GRIEFER_MAX_REQUEST_BYTES bounds the body
// and nothing in this codebase had chosen a bound for a header.
const (
	maxProducerNameBytes = 64
	maxProducerKeyBytes  = 512
)

// Reasons a producer credential is refused. A closed set, because it becomes a
// metric label.
const (
	ProducerRejectUnknown   = "unknown_producer"
	ProducerRejectBadKey    = "wrong_key"
	ProducerRejectMalformed = "malformed"
	ProducerRejectAbsent    = "absent"
)

// ProducerFromContext returns the authenticated producer, or the zero Producer.
func ProducerFromContext(ctx context.Context) Producer {
	p, _ := ctx.Value(producerKey).(Producer)
	return p
}

// ContextWithProducer returns ctx carrying p.
func ContextWithProducer(ctx context.Context, p Producer) context.Context {
	return context.WithValue(ctx, producerKey, p)
}

// ProducerKeyring verifies producer credentials.
//
// It stores SHA-256 digests rather than keys, the way ServiceAuth does, so the
// process holds nothing a leak could replay.
type ProducerKeyring struct {
	entries map[string]producerEntry
	// dummy is compared against when the name is unknown, so an unknown name
	// costs the same as a wrong key and the API is not an enumeration oracle.
	dummy [32]byte
	// onReject is called before the refusal is written, so the audit trail can
	// record an attempt without this package importing the audit one. The shape
	// AccessLog already uses for its logger.
	onReject func(r *http.Request, claimed, reason string)
}

type producerEntry struct {
	producer Producer
	current  [32]byte
	// previous accepts the outgoing key during a rotation, so a key can be
	// changed without a synchronised deploy of GRIEFER and the producer.
	previous    [32]byte
	hasPrevious bool
}

// ProducerCredential is one configured producer, as the keyring is built.
type ProducerCredential struct {
	Name        string
	Key         string
	PreviousKey string
	Sources     []SourceRef
}

// NewProducerKeyring builds a keyring. onReject may be nil.
func NewProducerKeyring(creds []ProducerCredential, onReject func(r *http.Request, claimed, reason string)) *ProducerKeyring {
	k := &ProducerKeyring{entries: make(map[string]producerEntry, len(creds)), onReject: onReject}
	// A random dummy rather than a fixed one, so the digest an unknown name is
	// compared against is not a value an attacker can precompute against.
	_, _ = rand.Read(k.dummy[:])
	for _, c := range creds {
		e := producerEntry{
			producer: Producer{Name: c.Name, Sources: c.Sources},
			current:  sha256.Sum256([]byte(c.Key)),
		}
		if c.PreviousKey != "" {
			e.previous = sha256.Sum256([]byte(c.PreviousKey))
			e.hasPrevious = true
		}
		k.entries[c.Name] = e
	}
	return k
}

// Configured reports whether any producer is enrolled.
func (k *ProducerKeyring) Configured() bool { return k != nil && len(k.entries) > 0 }

// Middleware authenticates a producer on the routes it wraps.
//
// With no producers configured it admits the request carrying the zero
// Producer: a deployment that has not enrolled anybody is not silently told it
// has. Once ONE producer is enrolled the boundary is on for all of them, which
// is the only rule that leaves no bypass — an opt-in per route or per producer
// would mean an unenrolled sender simply omits the header.
func (k *ProducerKeyring) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSpace(r.Header.Get(HeaderProducer))
		key := strings.TrimSpace(r.Header.Get(HeaderProducerKey))

		if name == "" && key == "" {
			if !k.Configured() {
				next.ServeHTTP(w, r)
				return
			}
			k.reject(r, "", ProducerRejectAbsent)
			WriteError(w, r, http.StatusForbidden, CodeForbidden,
				"This deployment requires an authenticated event producer.", nil)
			return
		}

		// Length before pattern: an over-long header is refused without the
		// regex ever seeing it.
		if len(name) > maxProducerNameBytes || len(key) > maxProducerKeyBytes {
			k.reject(r, "", ProducerRejectMalformed)
			WriteError(w, r, http.StatusBadRequest, CodeValidationFailed,
				"The producer credential headers exceed their limits.", nil)
			return
		}
		// A name with no key is MALFORMED, not absent. Treating it as absent is
		// how an absent case becomes a bypass — the rule PrincipalMiddleware
		// states for operator headers, inherited here for the same reason.
		if !producerPattern.MatchString(name) || key == "" {
			k.reject(r, "", ProducerRejectMalformed)
			WriteError(w, r, http.StatusBadRequest, CodeValidationFailed,
				"The producer credential is not in an acceptable form.", nil)
			return
		}

		presented := sha256.Sum256([]byte(key))
		entry, known := k.entries[name]
		if !known {
			// Same work as a real comparison, so timing does not answer "is
			// there a producer by this name".
			subtle.ConstantTimeCompare(presented[:], k.dummy[:])
			k.reject(r, name, ProducerRejectUnknown)
			k.refuse(w, r)
			return
		}
		ok := subtle.ConstantTimeCompare(presented[:], entry.current[:]) == 1
		if !ok && entry.hasPrevious {
			ok = subtle.ConstantTimeCompare(presented[:], entry.previous[:]) == 1
		}
		if !ok {
			k.reject(r, name, ProducerRejectBadKey)
			k.refuse(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(ContextWithProducer(r.Context(), entry.producer)))
	})
}

// refuse writes the one refusal a caller ever sees.
//
// An unknown name and a wrong key are indistinguishable on the wire; the
// difference survives in the metric label and the log, where it helps an
// operator and not an attacker. 403 rather than 401 because the service
// credential WAS valid — telling this caller to authenticate again is advice
// that cannot help.
func (k *ProducerKeyring) refuse(w http.ResponseWriter, r *http.Request) {
	WriteError(w, r, http.StatusForbidden, CodeForbidden,
		"The producer credential was refused.", nil)
}

func (k *ProducerKeyring) reject(r *http.Request, claimed, reason string) {
	if k != nil && k.onReject != nil {
		k.onReject(r, claimed, reason)
	}
}

// ValidProducerName reports whether name is an acceptable producer name.
//
// Exported so configuration can refuse a bad name at startup rather than
// enrolling a producer no request could ever match.
func ValidProducerName(name string) bool { return producerPattern.MatchString(name) }
