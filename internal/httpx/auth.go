package httpx

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

// ServiceAuth requires a shared bearer token on every request it wraps.
//
// This is service-to-service authentication between GRIEFER's console gateway
// and its API — not user authentication. It exists so that the API is not
// reachable by anything that merely has network access to it, which matters as
// soon as the API runs anywhere other than loopback.
//
// It is deliberately NOT a substitute for the real authentication and RBAC
// tracked as M8: one shared secret cannot distinguish operators, cannot be
// scoped, and cannot be revoked for one caller without revoking it for all.
type ServiceAuth struct {
	// digest holds SHA-256 of the expected token rather than the token itself,
	// so a memory disclosure yields a hash rather than a usable credential.
	digest [sha256.Size]byte
	// exempt paths answer without a credential.
	exempt map[string]bool
}

// NewServiceAuth builds middleware requiring token. Paths in exempt are served
// without a credential — health and readiness probes, which a platform must be
// able to call before it has any secret to present.
func NewServiceAuth(token string, exempt ...string) *ServiceAuth {
	a := &ServiceAuth{
		digest: sha256.Sum256([]byte(token)),
		exempt: make(map[string]bool, len(exempt)),
	}
	for _, path := range exempt {
		a.exempt[path] = true
	}
	return a
}

// Middleware enforces the credential.
func (a *ServiceAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.exempt[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		if !a.authorized(r.Header.Get("Authorization")) {
			// WWW-Authenticate names the scheme without hinting at the token's
			// shape, and the body says nothing about which part was wrong.
			w.Header().Set("WWW-Authenticate", `Bearer realm="griefer"`)
			WriteError(w, r, http.StatusUnauthorized, CodeUnauthorized,
				"Authentication is required.", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authorized compares the presented credential in constant time.
//
// Both sides are hashed first. That keeps the comparison fixed-width regardless
// of what a caller sends, so the length of the presented token does not leak
// through timing either.
func (a *ServiceAuth) authorized(header string) bool {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	presented := sha256.Sum256([]byte(strings.TrimSpace(header[len(prefix):])))
	return subtle.ConstantTimeCompare(presented[:], a.digest[:]) == 1
}
