package httpx

import (
	"context"
	"net/http"
	"regexp"
	"strings"
)

// Principal is the operator on whose behalf a request was made.
//
// GRIEFER's API is not reached by people. Only the console's server-side
// gateway and the seeder hold the service credential, and both are trusted
// components. The credential therefore answers "is this a component we
// deployed", and it cannot answer "which person is behind this request" —
// which is the question the audit trail has to answer.
//
// A Principal is that second answer. It arrives in headers that are read ONLY
// after the service credential has been verified, so the claim is as trustworthy
// as the component making it. A caller without the credential never gets as far
// as this being read.
//
// This is not a substitute for real end-user authentication at the API. It is a
// trusted-subsystem assertion, and it is honest about being one: the console
// authenticates the person, and the API trusts the console because the console
// proved it is the console.
type Principal struct {
	// Subject identifies the operator, e.g. "console:analyst".
	Subject string
	// Role is the role the operator held for this request.
	Role string
}

// Zero reports whether no principal was asserted.
func (p Principal) Zero() bool { return p.Subject == "" }

const principalKey contextKey = 1

// Headers carrying the asserted principal.
const (
	HeaderActor     = "X-Griefer-Actor"
	HeaderActorRole = "X-Griefer-Actor-Role"
)

// principalPattern bounds what an asserted identity may look like.
//
// The value reaches the audit trail and the Policy Kernel, so it is constrained
// rather than trusted to be sensible: no newlines to forge a second log line,
// no unbounded length to bloat a row, and a small alphabet so it cannot smuggle
// markup or a control character into whatever later renders it.
var principalPattern = regexp.MustCompile(`^[A-Za-z0-9._:@-]{1,128}$`)

// PrincipalFromContext returns the asserted operator, or the zero Principal.
func PrincipalFromContext(ctx context.Context) Principal {
	p, _ := ctx.Value(principalKey).(Principal)
	return p
}

// ContextWithPrincipal returns ctx carrying p.
func ContextWithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalMiddleware reads the asserted operator from the request headers.
//
// It MUST be mounted inside ServiceAuth, never in front of it. Ordered the
// other way, anyone who could reach the API could name themselves in the audit
// trail without presenting any credential at all.
//
// An ABSENT assertion is fine and means "no operator": the caller is a trusted
// component acting on nobody's behalf — the seeder, a migration, a probe. Those
// requests proceed unattributed and are recorded against the system actor.
//
// An assertion that is PRESENT but malformed is refused, and the difference
// matters. Dropping it instead would leave the request looking exactly like the
// absent case, and RequireRole admits the absent case — so a caller could walk
// past an administrator-only route simply by making its own identity header
// unparseable. Sending a header the API cannot read is a bug in a trusted
// component either way, and it should be visible rather than silently
// downgraded into more access than the caller asked for.
func PrincipalMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawSubject := r.Header.Get(HeaderActor)
		rawRole := r.Header.Get(HeaderActorRole)

		if strings.TrimSpace(rawSubject) == "" && strings.TrimSpace(rawRole) == "" {
			next.ServeHTTP(w, r)
			return
		}

		subject := strings.TrimSpace(rawSubject)
		role := strings.TrimSpace(rawRole)
		if !principalPattern.MatchString(subject) {
			WriteError(w, r, http.StatusBadRequest, CodeValidationFailed,
				"The asserted actor is not in an acceptable form.", nil)
			return
		}
		if role != "" && !principalPattern.MatchString(role) {
			WriteError(w, r, http.StatusBadRequest, CodeValidationFailed,
				"The asserted actor role is not in an acceptable form.", nil)
			return
		}
		ctx := ContextWithPrincipal(r.Context(), Principal{Subject: subject, Role: role})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole refuses a request whose asserted operator does not hold role.
//
// This is a SECOND layer, not the first. The console already keeps an analyst
// away from the audit trail (console/lib/roles.ts), and that check is the one a
// person actually meets. This one exists because a single layer means a single
// bug: if the console's route table and its API allowlist ever disagree, or a
// new page forgets its gate, the API still refuses.
//
// A request with NO asserted operator passes. That is deliberate and worth
// being explicit about: such a request came from a component holding the
// service credential and acting on nobody's behalf — the seeder, a migration, a
// health probe. Refusing those would break the platform's own internals to
// guard against a caller that already holds the strongest secret there is. The
// credential is the trust boundary; the role refines attribution inside it.
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := PrincipalFromContext(r.Context())
			if p.Zero() || p.Role == role {
				next.ServeHTTP(w, r)
				return
			}
			WriteError(w, r, http.StatusForbidden, CodeForbidden,
				"This account does not have access to that resource.", nil)
		})
	}
}
