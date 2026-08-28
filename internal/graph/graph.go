package graph

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// Graph is an in-memory Security Graph. It is safe for concurrent use.
//
// v0.1 keeps the graph in memory and rebuilds it from stored events on start.
// A persistent, queryable graph is milestone M2 — see docs/ROADMAP.md.
type Graph struct {
	mu       sync.RWMutex
	entities map[string]*Entity
	out      map[string]map[edgeKey]*Edge
	in       map[string]map[edgeKey]*Edge
}

type edgeKey struct {
	peer     string
	relation Relation
}

// New returns an empty Graph.
func New() *Graph {
	return &Graph{
		entities: make(map[string]*Entity),
		out:      make(map[string]map[edgeKey]*Edge),
		in:       make(map[string]map[edgeKey]*Edge),
	}
}

// MaxObservedEntities bounds the half of the graph a producer fills.
//
// Edges already carry maxEdgeEvidence and findings carry maxFindingEvents, but
// the entity map itself had no cap and no eviction anywhere in this package: a
// batch of events naming distinct keys grew g.entities, g.out and g.in for the
// lifetime of the process. CONTRIBUTING.md is explicit that a map an outside
// party fills needs a limit, and "the graph is rebuilt on restart" is not one —
// it is a description of how the memory is eventually reclaimed, by losing the
// process.
const MaxObservedEntities = 20_000

// evictObservedLocked drops the least recently seen OBSERVED entities, and
// their edges, until the graph is back under the cap.
//
// Declared inventory entities are never evicted. They are what an operator
// curated, and a producer must not be able to push them out — that would turn a
// memory bound into a way to blind the blast-radius calculation, which is worse
// than the growth it fixes.
//
// What eviction costs is reach into the oldest observed corners of the graph.
// What it buys is that the graph still exists after a hostile batch. The graph
// is already documented as in-memory and rebuilt on start (M2 persists it), so
// this moves the horizon from "everything since this process started" to "the
// most recent MaxObservedEntities", rather than introducing forgetting to
// something that promised to remember.
func (g *Graph) evictObservedLocked() {
	if len(g.entities) <= MaxObservedEntities {
		return
	}
	observed := make([]*Entity, 0, len(g.entities))
	for _, e := range g.entities {
		if e.Observed {
			observed = append(observed, e)
		}
	}
	sort.Slice(observed, func(i, j int) bool { return observed[i].LastSeen.Before(observed[j].LastSeen) })

	// Evicted in a batch down to a headroom below the cap, not one at a time.
	// At exactly the cap, evicting a single entity per insert would sort the
	// whole graph on every insert — which hands the same attacker a CPU cost
	// in place of the memory one.
	target := MaxObservedEntities - MaxObservedEntities/20
	over := len(g.entities) - target
	for _, e := range observed {
		if over <= 0 {
			return
		}
		g.removeEntityLocked(e.ID)
		over--
	}
	// Falling out of the loop means declared entities alone exceed the cap.
	// Nothing to do about that here: the inventory is the operator's, and
	// silently dropping it would be the failure this function exists to avoid.
}

// removeEntityLocked deletes an entity and every edge touching it, from both
// indexes, so no half-edge is left pointing at something that is gone.
func (g *Graph) removeEntityLocked(id string) {
	for key := range g.out[id] {
		delete(g.in[key.peer], edgeKey{peer: id, relation: key.relation})
		if len(g.in[key.peer]) == 0 {
			delete(g.in, key.peer)
		}
	}
	for key := range g.in[id] {
		delete(g.out[key.peer], edgeKey{peer: id, relation: key.relation})
		if len(g.out[key.peer]) == 0 {
			delete(g.out, key.peer)
		}
	}
	delete(g.out, id)
	delete(g.in, id)
	delete(g.entities, id)
}

// UpsertEntity merges e into the graph. Existing fields are only overwritten
// when the incoming value carries more information: a name or criticality
// already known is never downgraded by a later, sparser observation.
func (g *Graph) UpsertEntity(e Entity) *Entity {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.upsertEntityLocked(e)
}

func (g *Graph) upsertEntityLocked(e Entity) *Entity {
	if e.ID == "" {
		e.ID = EntityID(e.Type, e.Key)
	}
	if e.Criticality == "" {
		e.Criticality = CriticalityMedium
	}
	existing, ok := g.entities[e.ID]
	if !ok {
		clone := e
		if clone.Attributes != nil {
			clone.Attributes = copyMap(e.Attributes)
		}
		g.entities[e.ID] = &clone
		// Swept here because this is the only place the map grows.
		g.evictObservedLocked()
		return &clone
	}
	if e.Name != "" {
		existing.Name = e.Name
	}
	if e.Criticality.Rank() > existing.Criticality.Rank() {
		existing.Criticality = e.Criticality
	}
	if e.Observed {
		existing.Observed = true
	}
	for k, v := range e.Attributes {
		if existing.Attributes == nil {
			existing.Attributes = make(map[string]string, len(e.Attributes))
		}
		existing.Attributes[k] = v
	}
	if !e.FirstSeen.IsZero() && (existing.FirstSeen.IsZero() || e.FirstSeen.Before(existing.FirstSeen)) {
		existing.FirstSeen = e.FirstSeen
	}
	if e.LastSeen.After(existing.LastSeen) {
		existing.LastSeen = e.LastSeen
	}
	return existing
}

// UpsertEdge merges a directed relationship into the graph, accumulating the
// event identifiers that evidence it.
func (g *Graph) UpsertEdge(from, to string, rel Relation, at time.Time, eventID string) {
	if from == "" || to == "" || from == to {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	outKey := edgeKey{peer: to, relation: rel}
	bucket, ok := g.out[from]
	if !ok {
		bucket = make(map[edgeKey]*Edge)
		g.out[from] = bucket
	}
	edge, ok := bucket[outKey]
	if !ok {
		edge = &Edge{From: from, To: to, Relation: rel, FirstSeen: at, LastSeen: at}
		bucket[outKey] = edge
		inBucket, ok := g.in[to]
		if !ok {
			inBucket = make(map[edgeKey]*Edge)
			g.in[to] = inBucket
		}
		inBucket[edgeKey{peer: from, relation: rel}] = edge
	}
	if at.Before(edge.FirstSeen) || edge.FirstSeen.IsZero() {
		edge.FirstSeen = at
	}
	if at.After(edge.LastSeen) {
		edge.LastSeen = at
	}
	if eventID != "" && len(edge.EventIDs) < maxEdgeEvidence && !containsString(edge.EventIDs, eventID) {
		edge.EventIDs = append(edge.EventIDs, eventID)
	}
}

// maxEdgeEvidence bounds how many event ids a single edge accumulates. Without
// a bound, a noisy or hostile producer could grow one edge without limit.
const maxEdgeEvidence = 50

// Entity returns a copy of the entity with the given id.
func (g *Graph) Entity(id string) (Entity, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	e, ok := g.entities[id]
	if !ok {
		return Entity{}, false
	}
	clone := *e
	clone.Attributes = copyMap(e.Attributes)
	return clone, true
}

// Neighbours returns every edge incident to id, in both directions, sorted for
// deterministic output.
func (g *Graph) Neighbours(id string) []Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var edges []Edge
	for _, e := range g.out[id] {
		edges = append(edges, *e)
	}
	for _, e := range g.in[id] {
		edges = append(edges, *e)
	}
	sortEdges(edges)
	return edges
}

// Entities returns every entity, sorted by id.
func (g *Graph) Entities() []Entity {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]Entity, 0, len(g.entities))
	for _, e := range g.entities {
		clone := *e
		clone.Attributes = copyMap(e.Attributes)
		out = append(out, clone)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Size reports the number of entities and edges currently held.
func (g *Graph) Size() (entities, edges int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, bucket := range g.out {
		edges += len(bucket)
	}
	return len(g.entities), edges
}

func sortEdges(edges []Edge) {
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		if edges[i].To != edges[j].To {
			return edges[i].To < edges[j].To
		}
		return edges[i].Relation < edges[j].Relation
	})
}

func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Blast radius
// ---------------------------------------------------------------------------

// DefaultMaxHops bounds blast-radius traversal. Reachability in an identity
// graph degrades into "everything reaches everything" past a small number of
// hops, so an unbounded walk produces a number that looks precise and means
// nothing.
const DefaultMaxHops = 3

// ReachableEntity is one node found during blast-radius traversal.
type ReachableEntity struct {
	ID          string      `json:"id"`
	Type        EntityType  `json:"type"`
	Name        string      `json:"name,omitempty"`
	Criticality Criticality `json:"criticality"`
	Hops        int         `json:"hops"`
	// Via names the relationship the node was reached through, and From names
	// the entity it was reached from. Together they let a consumer redraw the
	// actual path rather than inferring one: a picture that invents edges is
	// worse than no picture.
	Via  Relation `json:"via,omitempty"`
	From string   `json:"from,omitempty"`
}

// BlastRadius is an estimate of what an incident could reach.
type BlastRadius struct {
	Score          int               `json:"score"`
	MaxHops        int               `json:"max_hops"`
	CriticalAssets int               `json:"critical_assets"`
	Summary        string            `json:"summary"`
	Reachable      []ReachableEntity `json:"reachable"`
}

// EstimateBlastRadius performs a bounded breadth-first walk from seeds and
// scores what it reaches.
//
// The score is a saturating function of criticality-weighted reachability
// discounted by distance: a critical asset one hop away dominates a dozen
// low-value nodes three hops out. It saturates rather than growing linearly
// because "worse than very bad" is not an actionable distinction.
func (g *Graph) EstimateBlastRadius(seeds []string, maxHops int) BlastRadius {
	if maxHops <= 0 {
		maxHops = DefaultMaxHops
	}
	g.mu.RLock()
	defer g.mu.RUnlock()

	type queued struct {
		id   string
		hops int
		via  Relation
		from string
	}

	visited := make(map[string]int, len(seeds))
	var queue []queued
	for _, s := range seeds {
		if _, ok := g.entities[s]; !ok {
			continue
		}
		if _, seen := visited[s]; seen {
			continue
		}
		visited[s] = 0
		queue = append(queue, queued{id: s, hops: 0})
	}
	sort.Slice(queue, func(i, j int) bool { return queue[i].id < queue[j].id })

	var reachable []ReachableEntity
	var weighted float64
	criticalCount := 0
	observedMaxHops := 0

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		ent, ok := g.entities[cur.id]
		if !ok {
			continue
		}
		if cur.hops > observedMaxHops {
			observedMaxHops = cur.hops
		}
		if cur.hops > 0 {
			// Seeds are the incident's own entities; they are already counted
			// by risk scoring, so only genuine expansion feeds the estimate.
			weighted += ent.Criticality.Weight() / float64(cur.hops)
		} else {
			weighted += ent.Criticality.Weight()
		}
		if ent.Criticality == CriticalityCritical {
			criticalCount++
		}
		reachable = append(reachable, ReachableEntity{
			ID:          ent.ID,
			Type:        ent.Type,
			Name:        ent.Name,
			Criticality: ent.Criticality,
			Hops:        cur.hops,
			Via:         cur.via,
			From:        cur.from,
		})

		if cur.hops >= maxHops {
			continue
		}
		next := g.neighbourStepsLocked(cur.id)
		for _, step := range next {
			if _, seen := visited[step.id]; seen {
				continue
			}
			visited[step.id] = cur.hops + 1
			queue = append(queue, queued{
				id: step.id, hops: cur.hops + 1, via: step.relation, from: cur.id,
			})
		}
	}

	sort.Slice(reachable, func(i, j int) bool {
		if reachable[i].Hops != reachable[j].Hops {
			return reachable[i].Hops < reachable[j].Hops
		}
		if reachable[i].Criticality.Rank() != reachable[j].Criticality.Rank() {
			return reachable[i].Criticality.Rank() > reachable[j].Criticality.Rank()
		}
		return reachable[i].ID < reachable[j].ID
	})

	score := int(math.Round(100 * (1 - math.Exp(-weighted/25))))
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	return BlastRadius{
		Score:          score,
		MaxHops:        observedMaxHops,
		CriticalAssets: criticalCount,
		Summary:        summarize(len(reachable), criticalCount, observedMaxHops),
		Reachable:      reachable,
	}
}

type neighbourStep struct {
	id       string
	relation Relation
}

// neighbourStepsLocked returns the reachable peers of id in deterministic order.
// Traversal follows edges in both directions: an attacker holding an identity
// can reach what that identity can reach, and an attacker holding a secret can
// reach whatever that secret unlocks.
func (g *Graph) neighbourStepsLocked(id string) []neighbourStep {
	var steps []neighbourStep
	for k := range g.out[id] {
		steps = append(steps, neighbourStep{id: k.peer, relation: k.relation})
	}
	for k := range g.in[id] {
		steps = append(steps, neighbourStep{id: k.peer, relation: k.relation})
	}
	sort.Slice(steps, func(i, j int) bool {
		if steps[i].id != steps[j].id {
			return steps[i].id < steps[j].id
		}
		return steps[i].relation < steps[j].relation
	})
	return steps
}

func summarize(total, critical, hops int) string {
	switch {
	case total == 0:
		return "No entities reachable — the incident has no graph context yet."
	case critical == 0:
		return fmt.Sprintf("%s reachable within %d hops; no assets classified critical.",
			plural(total, "entity", "entities"), hops)
	default:
		return fmt.Sprintf("%s reachable within %d hops, including %s classified critical.",
			plural(total, "entity", "entities"), hops, plural(critical, "asset", "assets"))
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
