package correlation

import (
	"testing"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
)

// TestCorrelationStateIsBounded.
//
// openSubjects and thresholdHits are keyed by a subject the producer chooses,
// and nothing removed from either: one batch naming distinct subjects grew both
// maps for the lifetime of the process, and the process is what eventually
// reclaimed the memory — by dying, taking every open incident with it.
//
// This is an internal test because the maps are the invariant. Asserting it
// through the public surface would mean asserting on memory, which is not
// something a test can watch.
func TestCorrelationStateIsBounded(t *testing.T) {
	base := time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)
	e := &Engine{
		window:        DefaultWindow,
		openSubjects:  make(map[string]subjectState),
		thresholdHits: make(map[string][]time.Time),
	}

	// Every subject inside the window, so none is stale: this is the case the
	// first eviction pass cannot help with, and the one an attacker choosing
	// subjects produces.
	//
	// The map is filled directly and swept once, rather than driven through the
	// write path fifteen thousand times. The invariant is the same and the test
	// does not cost fourteen seconds of every CI run under -race.
	const flood = maxTrackedSubjects + 5_000
	for i := 0; i < flood; i++ {
		e.openSubjects[subjectKeyForTest(i)] = subjectState{
			incidentID: "inc-x",
			lastSeen:   base.Add(time.Duration(i) * time.Millisecond),
		}
	}
	e.evictStaleLocked(base.Add(time.Duration(flood) * time.Millisecond))
	if got := len(e.openSubjects); got > maxTrackedSubjects {
		t.Fatalf("openSubjects holds %d entries after %d distinct subjects, above the cap of %d",
			got, flood, maxTrackedSubjects)
	}

	// The most recent subject survives: eviction takes the least recently seen,
	// which are the ones closest to expiring anyway.
	if _, ok := e.openSubjects[subjectKeyForTest(flood-1)]; !ok {
		t.Error("the most recently seen subject was evicted; eviction is not least-recently-seen")
	}
}

// TestExpiredCorrelationStateIsDroppedWithoutTouchingLiveState.
//
// The first eviction pass must be free of behaviour change: a subject outside
// the window is already treated as expired by mergeIntoIncident, so removing it
// changes nothing an operator could observe. A live subject removed by that same
// pass would silently split an incident.
func TestExpiredCorrelationStateIsDroppedWithoutTouchingLiveState(t *testing.T) {
	base := time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)
	e := &Engine{
		window:        DefaultWindow,
		openSubjects:  make(map[string]subjectState),
		thresholdHits: make(map[string][]time.Time),
	}
	e.openSubjects["stale"] = subjectState{incidentID: "inc-old", lastSeen: base.Add(-DefaultWindow - time.Hour)}
	e.openSubjects["live"] = subjectState{incidentID: "inc-new", lastSeen: base.Add(-time.Minute)}
	e.thresholdHits["empty"] = nil
	e.thresholdHits["held"] = []time.Time{base}

	e.evictStaleLocked(base)

	if _, ok := e.openSubjects["stale"]; ok {
		t.Error("a subject outside the correlation window was kept; it can never absorb another finding")
	}
	if _, ok := e.openSubjects["live"]; !ok {
		t.Error("a live subject was evicted by the stale pass; that silently splits an incident")
	}
	if _, ok := e.thresholdHits["empty"]; ok {
		t.Error("a threshold slot with no hits was kept; it can never fire")
	}
	if _, ok := e.thresholdHits["held"]; !ok {
		t.Error("a threshold slot with hits inside its window was dropped")
	}
}

func subjectKeyForTest(i int) string {
	return "identity:flood-" + string(rune('a'+i%26)) + "-" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestAFindingsEntityListIsBounded.
//
// mergeFinding capped EventIDs and, three lines below, appended to EntityIDs
// with no cap at all. recompute() rebuilds the incident's entity set from every
// finding on every event, so an uncapped list made one incident quadratic in a
// number the producer chooses.
func TestAFindingsEntityListIsBounded(t *testing.T) {
	inc := &incidents.Incident{}
	base := time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)

	for i := 0; i < maxFindingEntities*3; i++ {
		mergeFinding(inc, incidents.Finding{
			RuleID:    "GRF-CORR-0001",
			FirstSeen: base,
			LastSeen:  base,
			EventIDs:  []string{"evt-" + itoa(i)},
			EntityIDs: []string{"identity:flood-" + itoa(i)},
		})
	}

	if len(inc.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: the same rule should merge rather than duplicate", len(inc.Findings))
	}
	if got := len(inc.Findings[0].EntityIDs); got > maxFindingEntities {
		t.Errorf("EntityIDs holds %d ids, above the cap of %d", got, maxFindingEntities)
	}
	if got := len(inc.Findings[0].EventIDs); got > maxFindingEvents {
		t.Errorf("EventIDs holds %d ids, above the cap of %d", got, maxFindingEvents)
	}
}
