package events

import (
	"sort"
	"strings"
)

// reservedLabelKeys are label names that name a GRIEFER control-plane concept.
//
// The threat this closes: telemetry is attacker-influenced data. A producer (or
// anyone who can forge a producer) must never be able to smuggle an executive
// instruction into GRIEFER by naming a field after one. GRIEFER therefore
// treats these keys as poisoned input — they are stripped before the event
// reaches storage or correlation, and the strip is recorded so the attempt is
// itself visible as a signal.
//
// This is a structural guarantee, not a heuristic: the response engine only
// ever reads an action type from the server-side catalog in internal/incidents,
// so even an unstripped label could not select an action. The denylist exists
// so the attempt is detected rather than silently ignored.
var reservedLabelKeys = map[string]bool{
	"action":          true,
	"actions":         true,
	"approval":        true,
	"approve":         true,
	"autonomy":        true,
	"cmd":             true,
	"command":         true,
	"exec":            true,
	"execute":         true,
	"instruction":     true,
	"instructions":    true,
	"mode":            true,
	"override":        true,
	"policy":          true,
	"policy_decision": true,
	"policy_override": true,
	"prompt":          true,
	"response_action": true,
	"role":            true,
	"system":          true,
	"tool":            true,
}

// reservedLabelPrefixes are namespaces owned by GRIEFER itself.
var reservedLabelPrefixes = []string{"griefer.", "griefer_"}

// Sanitize removes control-plane label keys from ev and records what it
// removed on ev.Quarantined. It returns the quarantined keys in sorted order so
// that callers, tests and audit entries all observe the same sequence.
//
// Sanitize is called once, at the ingest trust boundary, before an event is
// persisted or published. It never fails: a quarantined label degrades the
// event, it does not reject it, because dropping telemetry is itself a way to
// blind the platform.
func Sanitize(ev *SecurityEvent) []string {
	if ev == nil || len(ev.Labels) == 0 {
		return nil
	}
	var quarantined []string
	for key := range ev.Labels {
		if isReservedLabelKey(key) {
			delete(ev.Labels, key)
			quarantined = append(quarantined, key)
		}
	}
	if len(quarantined) == 0 {
		return nil
	}
	sort.Strings(quarantined)
	if len(ev.Labels) == 0 {
		ev.Labels = nil
	}
	ev.Quarantined = quarantined
	return quarantined
}

func isReservedLabelKey(key string) bool {
	lower := strings.ToLower(key)
	if reservedLabelKeys[lower] {
		return true
	}
	for _, prefix := range reservedLabelPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}
