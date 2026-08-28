package correlation

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/graph"
	"github.com/kamilxgriefer/griefer-security-platform/internal/idgen"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
	"github.com/kamilxgriefer/griefer-security-platform/internal/risk"
)

// DefaultWindow is how long an open incident stays eligible to absorb new
// findings for the same subject.
const DefaultWindow = 6 * time.Hour

// maxFindingEvents bounds the event ids retained per finding, and
// maxIncidentEvidence bounds the rendered evidence list. Both exist so a noisy
// or hostile producer cannot grow one incident without limit.
const (
	maxFindingEvents    = 100
	maxIncidentEvidence = 200
	// maxFindingEntities bounds the entity ids retained per finding.
	//
	// EventIDs was capped and EntityIDs, three lines below it in mergeFinding,
	// was not — so one finding absorbed an entity id per event forever, and
	// recompute() rebuilds the incident's entity set from all of them on every
	// event. That is quadratic in a value a producer chooses, which is the
	// shape CONTRIBUTING.md is describing when it says an unbounded list an
	// outside party can influence is a limit that does not exist.
	maxFindingEntities = 100
)

// IncidentStore is the persistence surface the engine needs. Declaring it here
// rather than importing the storage package keeps correlation testable against
// a fake and free of storage concerns.
type IncidentStore interface {
	GetIncident(ctx context.Context, id string) (*incidents.Incident, error)
	SaveIncident(ctx context.Context, inc *incidents.Incident) error
}

// Engine correlates findings into incidents.
//
// The engine owns no goroutines and no background timers: it is driven entirely
// by calls to Process. That makes its behaviour reproducible in tests and means
// a stalled engine degrades ingestion throughput rather than silently dropping
// state.
type Engine struct {
	rules  []Rule
	graph  *graph.Graph
	store  IncidentStore
	window time.Duration
	now    func() time.Time

	mu sync.Mutex
	// openSubjects maps a correlation subject to the incident currently
	// absorbing its findings.
	openSubjects map[string]subjectState
	// thresholdHits tracks timestamps for stateful rules, per subject and rule.
	thresholdHits map[string][]time.Time
}

type subjectState struct {
	incidentID string
	lastSeen   time.Time
}

// maxTrackedSubjects bounds the correlation state.
//
// openSubjects and thresholdHits are keyed by a subject the producer chooses,
// and nothing was ever removed from either: one batch naming distinct subjects
// grew both maps for the lifetime of the process. CONTRIBUTING.md names this
// exact shape — "every field, list, map and query that an outside party can
// influence needs a limit" — and this is a map an outside party fills.
const maxTrackedSubjects = 10_000

// evictStaleLocked drops correlation state that can no longer change a
// decision, and, only if that is not enough, the oldest state that still can.
//
// The first pass is free of behaviour change by construction: a subject whose
// lastSeen is outside the window is already treated as expired by
// mergeIntoIncident, and a threshold slot whose hits have all aged out can
// never fire. Both are dead weight rather than evidence, and removing them is
// what the window already means.
//
// The second pass is not free, and is the honest trade. Dropping a live subject
// means the next event for it opens a new incident instead of joining the one
// it belongs to — evidence gets split, which is a real loss. It is the lesser
// loss: an unbounded map ends with the process killed and every open incident
// lost with it, and an attacker choosing subjects is the one who decides when.
func (e *Engine) evictStaleLocked(now time.Time) {
	cutoff := now.Add(-e.window)
	for subject, st := range e.openSubjects {
		if st.lastSeen.Before(cutoff) {
			delete(e.openSubjects, subject)
		}
	}
	for key, hits := range e.thresholdHits {
		if len(hits) == 0 {
			delete(e.thresholdHits, key)
		}
	}
	if len(e.openSubjects) <= maxTrackedSubjects {
		return
	}
	// Over the cap with nothing stale left. Drop the least recently seen first:
	// they are the ones closest to expiring anyway.
	type aged struct {
		subject string
		at      time.Time
	}
	live := make([]aged, 0, len(e.openSubjects))
	for subject, st := range e.openSubjects {
		live = append(live, aged{subject, st.lastSeen})
	}
	sort.Slice(live, func(i, j int) bool { return live[i].at.Before(live[j].at) })
	// Down to a headroom below the cap, not to the cap. At exactly the cap,
	// evicting one subject per event would sort the whole map on every event —
	// handing the same attacker a CPU cost in place of the memory one.
	target := maxTrackedSubjects - maxTrackedSubjects/20
	for _, a := range live[:len(e.openSubjects)-target] {
		delete(e.openSubjects, a.subject)
	}
}

// Options configures an Engine.
type Options struct {
	Rules  []Rule
	Graph  *graph.Graph
	Store  IncidentStore
	Window time.Duration
	Now    func() time.Time
}

// NewEngine builds a correlation engine. It fails rather than starting with an
// empty rule set, because a silently ruleless engine looks healthy and detects
// nothing.
func NewEngine(opts Options) (*Engine, error) {
	if len(opts.Rules) == 0 {
		return nil, fmt.Errorf("correlation: at least one rule is required")
	}
	if opts.Graph == nil {
		return nil, fmt.Errorf("correlation: graph is required")
	}
	if opts.Store == nil {
		return nil, fmt.Errorf("correlation: incident store is required")
	}
	window := opts.Window
	if window <= 0 {
		window = DefaultWindow
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Engine{
		rules:         opts.Rules,
		graph:         opts.Graph,
		store:         opts.Store,
		window:        window,
		now:           now,
		openSubjects:  make(map[string]subjectState),
		thresholdHits: make(map[string][]time.Time),
	}, nil
}

// Rules returns the loaded rule set.
func (e *Engine) Rules() []Rule { return e.rules }

// Process evaluates ev against every rule and folds any resulting findings into
// an incident. It returns nil when the event produced no finding — the common
// case, and not an error.
func (e *Engine) Process(ctx context.Context, ev *events.SecurityEvent) (*incidents.Incident, error) {
	if ev == nil {
		return nil, fmt.Errorf("correlation: nil event")
	}
	subject := subjectKey(ev)
	findings := e.evaluate(ev, subject)
	if len(findings) == 0 {
		return nil, nil
	}
	return e.mergeIntoIncident(ctx, ev, subject, findings)
}

// evaluate runs every rule against the event, handling stateful thresholds.
func (e *Engine) evaluate(ev *events.SecurityEvent, subject string) []incidents.Finding {
	entityIDs := graph.EntityIDsForEvent(ev)
	var out []incidents.Finding
	for i := range e.rules {
		rule := &e.rules[i]
		if !rule.Matches(ev) {
			continue
		}
		if rule.Threshold != nil && !e.thresholdMet(subject, rule, ev.Timestamp) {
			continue
		}
		out = append(out, incidents.Finding{
			ID:          idgen.New(idgen.PrefixFinding),
			RuleID:      rule.ID,
			Title:       rule.Title,
			Description: rule.Description,
			Category:    rule.Category,
			Severity:    rule.Severity,
			Confidence:  rule.Confidence,
			Techniques:  rule.Techniques,
			EntityIDs:   entityIDs,
			EventIDs:    []string{ev.ID},
			FirstSeen:   ev.Timestamp,
			LastSeen:    ev.Timestamp,
		})
	}
	return out
}

// thresholdMet records a hit and reports whether the rule's threshold is
// satisfied inside its window.
func (e *Engine) thresholdMet(subject string, rule *Rule, at time.Time) bool {
	key := subject + "|" + rule.ID
	e.mu.Lock()
	defer e.mu.Unlock()

	e.evictStaleLocked(at)

	cutoff := at.Add(-rule.Threshold.Window)
	hits := append(e.thresholdHits[key], at)
	kept := hits[:0]
	for _, t := range hits {
		if !t.Before(cutoff) {
			kept = append(kept, t)
		}
	}
	// Bound retained state: a threshold rule never needs more timestamps than
	// its own count to make a decision.
	if len(kept) > rule.Threshold.Count {
		kept = kept[len(kept)-rule.Threshold.Count:]
	}
	e.thresholdHits[key] = kept
	return len(kept) >= rule.Threshold.Count
}

// subjectKey decides what an incident is "about".
//
// v0.1 is identity-first: findings are grouped by the acting identity, because
// in the intrusions GRIEFER targets the identity is the thing that persists
// while hosts, addresses and tokens change. Events with no attributable actor
// are grouped by source so they are never silently merged into someone else's
// incident.
func subjectKey(ev *events.SecurityEvent) string {
	if key := ev.ActorKey(); key != "" {
		return key
	}
	return "unattributed:" + ev.SourceType + ":" + ev.SourceName
}

func (e *Engine) mergeIntoIncident(ctx context.Context, ev *events.SecurityEvent, subject string, findings []incidents.Finding) (*incidents.Incident, error) {
	e.mu.Lock()
	state, open := e.openSubjects[subject]
	expired := open && ev.Timestamp.Sub(state.lastSeen) > e.window
	e.mu.Unlock()

	var inc *incidents.Incident
	if open && !expired {
		existing, err := e.store.GetIncident(ctx, state.incidentID)
		if err == nil && existing != nil && existing.Status != incidents.StatusClosed {
			inc = existing
		}
	}
	if inc == nil {
		inc = &incidents.Incident{
			ID:              idgen.New(idgen.PrefixIncident),
			SchemaVersion:   incidents.SchemaVersion,
			Status:          incidents.StatusOpen,
			FirstSeen:       ev.Timestamp,
			PrimaryIdentity: subject,
		}
	}

	for _, f := range findings {
		mergeFinding(inc, f)
	}
	if ev.Timestamp.Before(inc.FirstSeen) || inc.FirstSeen.IsZero() {
		inc.FirstSeen = ev.Timestamp
	}
	if ev.Timestamp.After(inc.LastSeen) {
		inc.LastSeen = ev.Timestamp
	}
	inc.UpdatedAt = e.now().UTC()

	e.recompute(inc, ev)

	if err := e.store.SaveIncident(ctx, inc); err != nil {
		return nil, fmt.Errorf("correlation: persist incident: %w", err)
	}

	e.mu.Lock()
	e.openSubjects[subject] = subjectState{incidentID: inc.ID, lastSeen: ev.Timestamp}
	// Swept on write rather than on a timer: the map only grows here, so this is
	// the one place that can let it grow, and a background sweeper would be a
	// goroutine whose absence nobody would notice.
	e.evictStaleLocked(ev.Timestamp)
	e.mu.Unlock()

	return inc, nil
}

// mergeFinding folds a new finding into the incident. A rule that fires again
// updates the existing finding rather than appending a duplicate: an incident
// listing the same detection twenty times is noise, not evidence.
func mergeFinding(inc *incidents.Incident, f incidents.Finding) {
	for i := range inc.Findings {
		existing := &inc.Findings[i]
		if existing.RuleID != f.RuleID {
			continue
		}
		if f.LastSeen.After(existing.LastSeen) {
			existing.LastSeen = f.LastSeen
		}
		if f.FirstSeen.Before(existing.FirstSeen) {
			existing.FirstSeen = f.FirstSeen
		}
		for _, id := range f.EventIDs {
			if len(existing.EventIDs) >= maxFindingEvents {
				break
			}
			if !containsStr(existing.EventIDs, id) {
				existing.EventIDs = append(existing.EventIDs, id)
			}
		}
		for _, id := range f.EntityIDs {
			if len(existing.EntityIDs) >= maxFindingEntities {
				break
			}
			if !containsStr(existing.EntityIDs, id) {
				existing.EntityIDs = append(existing.EntityIDs, id)
			}
		}
		return
	}
	inc.Findings = append(inc.Findings, f)
}

// recompute rebuilds every derived field of the incident from its findings and
// the current graph. Derived state is never patched incrementally: recomputing
// from scratch is what guarantees the risk score is a pure function of the
// evidence, which is what makes it reproducible in an audit entry.
func (e *Engine) recompute(inc *incidents.Incident, latest *events.SecurityEvent) {
	sort.Slice(inc.Findings, func(i, j int) bool { return inc.Findings[i].RuleID < inc.Findings[j].RuleID })

	entityIDs := map[string]bool{}
	for _, f := range inc.Findings {
		for _, id := range f.EntityIDs {
			entityIDs[id] = true
		}
	}
	ids := make([]string, 0, len(entityIDs))
	for id := range entityIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	refs := make([]incidents.EntityRef, 0, len(ids))
	touchesCritical := false
	for _, id := range ids {
		ent, ok := e.graph.Entity(id)
		if !ok {
			entType, key, valid := graph.SplitEntityID(id)
			if !valid {
				continue
			}
			refs = append(refs, incidents.EntityRef{
				ID: id, Type: entType, Name: key, Criticality: graph.CriticalityMedium,
			})
			continue
		}
		if ent.Criticality == graph.CriticalityCritical {
			touchesCritical = true
		}
		refs = append(refs, incidents.EntityRef{
			ID: ent.ID, Type: ent.Type, Name: ent.Name, Criticality: ent.Criticality,
		})
	}
	inc.Entities = refs

	inc.BlastRadius = e.graph.EstimateBlastRadius(ids, graph.DefaultMaxHops)
	if inc.BlastRadius.CriticalAssets > 0 {
		touchesCritical = true
	}

	assessment := risk.Assess(risk.Input{
		Findings:        inc.Findings,
		BlastScore:      inc.BlastRadius.Score,
		TouchesCritical: touchesCritical,
	})
	inc.RiskScore = assessment.Score
	inc.Severity = assessment.Severity
	inc.Confidence = assessment.Confidence

	inc.AttackTechniques = collectTechniques(inc.Findings)
	inc.RecommendedActions = recommendActions(inc.Findings, inc.Entities)
	inc.Title = buildTitle(inc)
	appendEvidence(inc, latest)
}

func collectTechniques(findings []incidents.Finding) []incidents.Technique {
	seen := map[string]incidents.Technique{}
	for _, f := range findings {
		for _, t := range f.Techniques {
			seen[t.ID] = t
		}
	}
	out := make([]incidents.Technique, 0, len(seen))
	for _, t := range seen {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// appendEvidence records the source event behind the latest update.
func appendEvidence(inc *incidents.Incident, ev *events.SecurityEvent) {
	if ev == nil {
		return
	}
	for _, existing := range inc.Evidence {
		if existing.EventID == ev.ID {
			return
		}
	}
	if len(inc.Evidence) >= maxIncidentEvidence {
		return
	}
	inc.Evidence = append(inc.Evidence, incidents.Evidence{
		EventID:    ev.ID,
		OccurredAt: ev.Timestamp,
		Category:   ev.Category,
		Summary:    evidenceSummary(ev),
		SourceName: ev.SourceName,
	})
	sort.Slice(inc.Evidence, func(i, j int) bool {
		if !inc.Evidence[i].OccurredAt.Equal(inc.Evidence[j].OccurredAt) {
			return inc.Evidence[i].OccurredAt.Before(inc.Evidence[j].OccurredAt)
		}
		return inc.Evidence[i].EventID < inc.Evidence[j].EventID
	})
}

func evidenceSummary(ev *events.SecurityEvent) string {
	actor := "unattributed actor"
	if ev.Actor != nil {
		if ev.Actor.Name != "" {
			actor = ev.Actor.Name
		} else if ev.Actor.ID != "" {
			actor = ev.Actor.ID
		}
	}
	target := ""
	if ev.Target != nil {
		name := ev.Target.Name
		if name == "" {
			name = ev.Target.ID
		}
		target = fmt.Sprintf(" on %s", name)
	}
	return fmt.Sprintf("%s: %s%s", actor, ev.EventType, target)
}

func buildTitle(inc *incidents.Incident) string {
	identity := inc.PrimaryIdentity
	if len(inc.Entities) > 0 {
		for _, e := range inc.Entities {
			if e.Type == graph.TypeIdentity && e.Name != "" {
				identity = e.Name
				break
			}
		}
	}
	categories := inc.EvidenceCategories()
	switch len(categories) {
	case 0:
		return fmt.Sprintf("Activity involving %s", identity)
	case 1:
		return fmt.Sprintf("%s activity involving %s", humanCategory(categories[0]), identity)
	default:
		return fmt.Sprintf("Multi-stage activity involving %s (%d evidence categories)", identity, len(categories))
	}
}

func humanCategory(c events.Category) string {
	switch c {
	case events.CategoryAuthentication:
		return "Authentication"
	case events.CategorySessionAnomaly:
		return "Session"
	case events.CategoryPrivilegeEscalation:
		return "Privilege escalation"
	case events.CategoryCredentialAccess:
		return "Credential access"
	case events.CategoryCloudAccess:
		return "Cloud access"
	case events.CategoryDataAccess:
		return "Data access"
	case events.CategoryProcessExecution:
		return "Process execution"
	case events.CategoryNetworkActivity:
		return "Network"
	case events.CategoryConfigChange:
		return "Configuration change"
	default:
		return string(c)
	}
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
