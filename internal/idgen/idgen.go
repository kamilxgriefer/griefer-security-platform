// Package idgen produces GRIEFER's public identifiers.
//
// Identifiers are UUIDv7 values with a short type prefix. UUIDv7 is
// time-ordered, so identifiers sort chronologically — which keeps pagination
// stable and makes an audit sequence readable — while remaining unguessable
// enough that an identifier is not itself a capability.
package idgen

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/google/uuid"
)

// Type prefixes for GRIEFER identifiers.
const (
	PrefixEvent    = "evt"
	PrefixFinding  = "fnd"
	PrefixIncident = "inc"
	PrefixAction   = "act"
	PrefixAudit    = "aud"
	PrefixRequest  = "req"
	PrefixChain    = "chn"
)

// New returns a time-ordered identifier with the given type prefix, for example
// "inc-018f3a2c-....".
func New(prefix string) string {
	id, err := uuid.NewV7()
	if err != nil {
		// NewV7 only fails if the system CSPRNG fails. Fall back to raw random
		// bytes rather than returning an empty (and therefore colliding) id.
		var b [16]byte
		if _, rerr := rand.Read(b[:]); rerr != nil {
			panic("idgen: system entropy source unavailable: " + rerr.Error())
		}
		return prefix + "-" + hex.EncodeToString(b[:])
	}
	return prefix + "-" + id.String()
}
