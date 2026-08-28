package graph_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/graph"
)

var testTime = time.Date(2026, 8, 23, 9, 0, 0, 0, time.UTC)

func TestUpsertEntityNeverDowngradesKnownFacts(t *testing.T) {
	g := graph.New()
	g.UpsertEntity(graph.Entity{
		Type: graph.TypeSecret, Key: "sec-1", Name: "billing/api-key",
		Criticality: graph.CriticalityCritical, FirstSeen: testTime, LastSeen: testTime,
	})
	// A later, sparser observation must not erase what the inventory declared.
	g.UpsertEntity(graph.Entity{
		Type: graph.TypeSecret, Key: "sec-1",
		Criticality: graph.CriticalityLow, LastSeen: testTime.Add(time.Hour), Observed: true,
	})

	got, ok := g.Entity(graph.EntityID(graph.TypeSecret, "sec-1"))
	if !ok {
		t.Fatal("entity disappeared after upsert")
	}
	if got.Criticality != graph.CriticalityCritical {
		t.Errorf("Criticality = %v, want critical; a sparser later observation must not downgrade an asset", got.Criticality)
	}
	if got.Name != "billing/api-key" {
		t.Errorf("Name = %q, want the previously known name", got.Name)
	}
	if !got.Observed {
		t.Error("Observed should be set once telemetry mentions the entity")
	}
	if !got.LastSeen.Equal(testTime.Add(time.Hour)) {
		t.Errorf("LastSeen = %v, want it advanced", got.LastSeen)
	}
	if !got.FirstSeen.Equal(testTime) {
		t.Errorf("FirstSeen = %v, want the earliest observation", got.FirstSeen)
	}
}

func TestUpsertEdgeAccumulatesEvidenceWithinBounds(t *testing.T) {
	g := graph.New()
	g.UpsertEntity(graph.Entity{Type: graph.TypeIdentity, Key: "u-1"})
	g.UpsertEntity(graph.Entity{Type: graph.TypeEndpoint, Key: "wks-1"})
	from := graph.EntityID(graph.TypeIdentity, "u-1")
	to := graph.EntityID(graph.TypeEndpoint, "wks-1")

	for i := 0; i < 200; i++ {
		g.UpsertEdge(from, to, graph.RelUsedDevice, testTime.Add(time.Duration(i)*time.Minute), "evt-"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	edges := g.Neighbours(from)
	if len(edges) != 1 {
		t.Fatalf("Neighbours() returned %d edges, want 1 merged edge", len(edges))
	}
	if len(edges[0].EventIDs) > 50 {
		t.Errorf("edge accumulated %d event ids; an unbounded edge lets a noisy producer grow the graph without limit", len(edges[0].EventIDs))
	}
	if _, edgeCount := g.Size(); edgeCount != 1 {
		t.Errorf("Size() reported %d edges, want 1", edgeCount)
	}
}

func TestUpsertEdgeIgnoresDegenerateInput(t *testing.T) {
	g := graph.New()
	g.UpsertEntity(graph.Entity{Type: graph.TypeIdentity, Key: "u-1"})
	id := graph.EntityID(graph.TypeIdentity, "u-1")

	g.UpsertEdge("", id, graph.RelAccessed, testTime, "e1")
	g.UpsertEdge(id, "", graph.RelAccessed, testTime, "e1")
	g.UpsertEdge(id, id, graph.RelAccessed, testTime, "e1")

	if _, edges := g.Size(); edges != 0 {
		t.Errorf("Size() reported %d edges, want 0 for empty and self-referential input", edges)
	}
}

func TestApplyInventoryValidatesReferences(t *testing.T) {
	tests := []struct {
		name    string
		inv     graph.Inventory
		wantErr string
	}{
		{
			name: "unknown entity type",
			inv: graph.Inventory{Entities: []graph.InventoryEntity{
				{Type: "wormhole", Key: "x"},
			}},
			wantErr: "unsupported type",
		},
		{
			name: "entity without a key",
			inv: graph.Inventory{Entities: []graph.InventoryEntity{
				{Type: graph.TypeIdentity},
			}},
			wantErr: "key is required",
		},
		{
			name: "edge referencing a missing entity",
			inv: graph.Inventory{
				Entities: []graph.InventoryEntity{{Type: graph.TypeIdentity, Key: "u-1"}},
				Edges:    []graph.InventoryEdge{{From: "identity:u-1", To: "secret:nope", Relation: graph.RelAccessed}},
			},
			wantErr: "unknown destination entity",
		},
		{
			name: "edge without a relation",
			inv: graph.Inventory{
				Entities: []graph.InventoryEntity{{Type: graph.TypeIdentity, Key: "u-1"}, {Type: graph.TypeEndpoint, Key: "w-1"}},
				Edges:    []graph.InventoryEdge{{From: "identity:u-1", To: "endpoint:w-1"}},
			},
			wantErr: "relation is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := graph.New().ApplyInventory(tt.inv, testTime)
			if err == nil {
				t.Fatal("ApplyInventory() accepted an invalid inventory; a typo would become a silently missing edge")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func buildChainGraph(t *testing.T) *graph.Graph {
	t.Helper()
	g := graph.New()
	inv := graph.Inventory{
		Entities: []graph.InventoryEntity{
			{Type: graph.TypeIdentity, Key: "u-1", Name: "u-1", Criticality: graph.CriticalityHigh},
			{Type: graph.TypeApplication, Key: "app-1", Name: "app-1", Criticality: graph.CriticalityHigh},
			{Type: graph.TypeSecret, Key: "sec-1", Name: "sec-1", Criticality: graph.CriticalityCritical},
			{Type: graph.TypeCloudResource, Key: "bucket-1", Name: "bucket-1", Criticality: graph.CriticalityCritical},
			{Type: graph.TypeEndpoint, Key: "wks-1", Name: "wks-1", Criticality: graph.CriticalityLow},
		},
		Edges: []graph.InventoryEdge{
			{From: "identity:u-1", To: "application:app-1", Relation: graph.RelGrantedRoleOn},
			{From: "application:app-1", To: "secret:sec-1", Relation: graph.RelOwns},
			{From: "secret:sec-1", To: "cloud_resource:bucket-1", Relation: graph.RelGrantsAccessTo},
		},
	}
	if err := g.ApplyInventory(inv, testTime); err != nil {
		t.Fatalf("ApplyInventory() error = %v", err)
	}
	return g
}

func TestEstimateBlastRadius(t *testing.T) {
	g := buildChainGraph(t)

	t.Run("reaches what the compromised identity unlocks", func(t *testing.T) {
		got := g.EstimateBlastRadius([]string{"identity:u-1"}, graph.DefaultMaxHops)
		if got.CriticalAssets != 2 {
			t.Errorf("CriticalAssets = %d, want 2 (the secret and the bucket it unlocks)", got.CriticalAssets)
		}
		if len(got.Reachable) != 4 {
			t.Errorf("Reachable = %d entities, want 4", len(got.Reachable))
		}
		if got.Score <= 0 || got.Score > 100 {
			t.Errorf("Score = %d, want 0..100", got.Score)
		}
		if got.Summary == "" {
			t.Error("Summary is empty; the number needs a sentence an analyst can read")
		}
		byID := map[string]graph.ReachableEntity{}
		for _, r := range got.Reachable {
			byID[r.ID] = r
		}
		bucket, ok := byID["cloud_resource:bucket-1"]
		if !ok {
			t.Fatal("the bucket the secret unlocks was not reached")
		}
		if bucket.Hops != 3 {
			t.Errorf("bucket hops = %d, want 3", bucket.Hops)
		}
		// Provenance must describe a real path, so a consumer can redraw it
		// rather than inventing edges.
		if bucket.From != "secret:sec-1" {
			t.Errorf("bucket reached From = %q, want secret:sec-1", bucket.From)
		}
		if bucket.Via != graph.RelGrantsAccessTo {
			t.Errorf("bucket reached Via = %q, want grants_access_to", bucket.Via)
		}
		for _, r := range got.Reachable {
			if r.Hops == 0 && r.From != "" {
				t.Errorf("seed %s has a From value; seeds are not reached from anywhere", r.ID)
			}
			if r.Hops > 0 {
				if r.From == "" {
					t.Errorf("%s was reached at %d hops with no provenance", r.ID, r.Hops)
				}
				if _, present := byID[r.From]; !present {
					t.Errorf("%s claims to be reached from %s, which is not in the result", r.ID, r.From)
				}
			}
		}
	})

	t.Run("hop limit bounds the walk", func(t *testing.T) {
		got := g.EstimateBlastRadius([]string{"identity:u-1"}, 1)
		if got.MaxHops > 1 {
			t.Errorf("MaxHops = %d, want at most 1", got.MaxHops)
		}
		for _, r := range got.Reachable {
			if r.ID == "cloud_resource:bucket-1" {
				t.Error("a one-hop walk must not reach a three-hop asset")
			}
		}
	})

	t.Run("an isolated entity has a small radius", func(t *testing.T) {
		lonely := g.EstimateBlastRadius([]string{"endpoint:wks-1"}, graph.DefaultMaxHops)
		full := g.EstimateBlastRadius([]string{"identity:u-1"}, graph.DefaultMaxHops)
		if lonely.Score >= full.Score {
			t.Errorf("isolated endpoint scored %d, identity scored %d; reachability must matter", lonely.Score, full.Score)
		}
		if lonely.CriticalAssets != 0 {
			t.Errorf("CriticalAssets = %d, want 0", lonely.CriticalAssets)
		}
	})

	t.Run("unknown seeds produce an empty result rather than an error", func(t *testing.T) {
		got := g.EstimateBlastRadius([]string{"identity:does-not-exist"}, graph.DefaultMaxHops)
		if got.Score != 0 || len(got.Reachable) != 0 {
			t.Errorf("got %+v, want an empty estimate", got)
		}
		if got.Summary == "" {
			t.Error("even an empty estimate needs a summary")
		}
	})

	t.Run("results are deterministic", func(t *testing.T) {
		first := g.EstimateBlastRadius([]string{"identity:u-1"}, graph.DefaultMaxHops)
		for i := 0; i < 20; i++ {
			again := g.EstimateBlastRadius([]string{"identity:u-1"}, graph.DefaultMaxHops)
			if again.Score != first.Score || len(again.Reachable) != len(first.Reachable) {
				t.Fatalf("run %d differed: %+v vs %+v", i, again, first)
			}
			for j := range again.Reachable {
				if again.Reachable[j].ID != first.Reachable[j].ID {
					t.Fatalf("run %d ordering differed at %d", i, j)
				}
			}
		}
	})
}

func TestProjectRecordsAttemptsSeparatelyFromAccess(t *testing.T) {
	managed := true
	base := func(outcome string) *events.SecurityEvent {
		return &events.SecurityEvent{
			ID: "evt-1", Timestamp: testTime,
			Category: events.CategoryCloudAccess, Severity: events.SeverityHigh,
			Actor:  &events.Actor{Type: "identity", ID: "u-1", Privileged: true},
			Target: &events.Target{Type: "cloud_resource", ID: "bucket-1", Criticality: "critical"},
			Device: &events.Device{ID: "wks-1", Hostname: "WKS-1.example", Managed: &managed},
			Labels: map[string]string{"outcome": outcome},
		}
	}

	t.Run("denied activity records an attempt", func(t *testing.T) {
		g := graph.New()
		g.Project(base("denied"))
		edges := g.Neighbours(graph.EntityID(graph.TypeIdentity, "u-1"))
		found := false
		for _, e := range edges {
			if e.To == "cloud_resource:bucket-1" {
				found = true
				if e.Relation != graph.RelAttemptedAccess {
					t.Errorf("relation = %v, want attempted_access; a blocked attacker must not inflate their apparent reach", e.Relation)
				}
			}
		}
		if !found {
			t.Fatal("no edge to the target was projected")
		}
	})

	t.Run("successful activity records access", func(t *testing.T) {
		g := graph.New()
		g.Project(base("success"))
		for _, e := range g.Neighbours(graph.EntityID(graph.TypeIdentity, "u-1")) {
			if e.To == "cloud_resource:bucket-1" && e.Relation != graph.RelAccessed {
				t.Errorf("relation = %v, want accessed", e.Relation)
			}
		}
	})

	t.Run("entities are created from every mentioned facet", func(t *testing.T) {
		g := graph.New()
		ev := base("success")
		ev.Actor.SessionID = "sess-1"
		ev.Network = &events.Network{SourceIP: "203.0.113.5", Country: "NL"}
		g.Project(ev)

		for _, want := range []string{
			"identity:u-1", "endpoint:wks-1", "session:sess-1",
			"ip_address:203.0.113.5", "cloud_resource:bucket-1",
		} {
			if _, ok := g.Entity(want); !ok {
				t.Errorf("entity %q was not projected", want)
			}
		}
	})
}

func TestEntityIDsForEventIsDeterministicAndDeduplicated(t *testing.T) {
	ev := &events.SecurityEvent{
		Actor:   &events.Actor{Type: "identity", ID: "u-1", SessionID: "sess-1"},
		Target:  &events.Target{Type: "identity", ID: "u-1"},
		Network: &events.Network{SourceIP: "203.0.113.5"},
		Cloud:   &events.Cloud{ResourceID: "bucket-1"},
	}
	first := graph.EntityIDsForEvent(ev)
	seen := map[string]bool{}
	for _, id := range first {
		if seen[id] {
			t.Errorf("duplicate entity id %q", id)
		}
		seen[id] = true
	}
	for i := 0; i < 10; i++ {
		again := graph.EntityIDsForEvent(ev)
		if len(again) != len(first) {
			t.Fatal("EntityIDsForEvent is not deterministic")
		}
		for j := range again {
			if again[j] != first[j] {
				t.Fatalf("ordering differed at %d: %q vs %q", j, again[j], first[j])
			}
		}
	}
	if graph.EntityIDsForEvent(nil) != nil {
		t.Error("EntityIDsForEvent(nil) should return nil")
	}
}

func TestSplitEntityID(t *testing.T) {
	tests := []struct {
		id      string
		wantOK  bool
		wantKey string
	}{
		{"identity:u-1042", true, "u-1042"},
		{"cloud_resource:arn:aws:s3:::bucket", true, "arn:aws:s3:::bucket"},
		{"wormhole:x", false, ""},
		{"noseparator", false, ""},
		{":leading", false, ""},
		{"identity:", false, ""},
	}
	for _, tt := range tests {
		_, key, ok := graph.SplitEntityID(tt.id)
		if ok != tt.wantOK {
			t.Errorf("SplitEntityID(%q) ok = %v, want %v", tt.id, ok, tt.wantOK)
		}
		if ok && key != tt.wantKey {
			t.Errorf("SplitEntityID(%q) key = %q, want %q", tt.id, key, tt.wantKey)
		}
	}
}

func TestGraphIsSafeForConcurrentUse(t *testing.T) {
	g := buildChainGraph(t)
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				g.UpsertEntity(graph.Entity{Type: graph.TypeIdentity, Key: "concurrent", LastSeen: testTime})
				g.UpsertEdge("identity:u-1", "identity:concurrent", graph.RelMemberOf, testTime, "e")
				g.EstimateBlastRadius([]string{"identity:u-1"}, 2)
				g.Neighbours("identity:u-1")
				g.Entities()
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

// TestTheGraphIsBoundedAndKeepsTheInventory.
//
// g.entities, g.out and g.in had no cap and no eviction: a batch of events
// naming distinct keys grew all three for the lifetime of the process.
//
// The bound must not become a way to blind the platform, so the entities an
// operator declared are never the ones evicted — otherwise a producer could
// push the asset inventory out of the graph and flatten every blast-radius
// calculation that depends on it.
func TestTheGraphIsBoundedAndKeepsTheInventory(t *testing.T) {
	g := graph.New()
	base := time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)

	// The operator's inventory: declared, not observed.
	declared := []string{"crown-jewels", "payroll", "prod-db"}
	for i, key := range declared {
		g.UpsertEntity(graph.Entity{
			Type: graph.TypeCloudResource, Key: key,
			Criticality: graph.CriticalityCritical,
			FirstSeen:   base, LastSeen: base.Add(time.Duration(i) * time.Second),
		})
	}

	// A hostile batch: every event names a key nobody has seen before.
	const flood = graph.MaxObservedEntities + 2_000
	for i := 0; i < flood; i++ {
		g.UpsertEntity(graph.Entity{
			Type: graph.TypeIdentity, Key: fmt.Sprintf("flood-%06d", i),
			Observed: true, FirstSeen: base, LastSeen: base.Add(time.Duration(i) * time.Millisecond),
		})
	}

	entities, _ := g.Size()
	if entities > graph.MaxObservedEntities {
		t.Fatalf("graph holds %d entities after a flood of %d, above the cap of %d",
			entities, flood, graph.MaxObservedEntities)
	}

	// Everything the operator declared is still there.
	for _, key := range declared {
		if _, ok := g.Entity(graph.EntityID(graph.TypeCloudResource, key)); !ok {
			t.Errorf("declared entity %q was evicted; a producer must not be able to push the "+
				"asset inventory out of the graph", key)
		}
	}

	// And the most recent observations survived: eviction is least-recently-seen.
	newest := graph.EntityID(graph.TypeIdentity, fmt.Sprintf("flood-%06d", flood-1))
	if _, ok := g.Entity(newest); !ok {
		t.Error("the most recently seen observed entity was evicted; eviction is not least-recently-seen")
	}
}

// TestEvictingAnEntityLeavesNoHalfEdges. An edge index still naming a removed
// entity is both a leak and a neighbour lookup that returns something gone.
func TestEvictingAnEntityLeavesNoHalfEdges(t *testing.T) {
	g := graph.New()
	base := time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)

	survivor := graph.EntityID(graph.TypeCloudResource, "survivor")
	g.UpsertEntity(graph.Entity{
		Type: graph.TypeCloudResource, Key: "survivor",
		Criticality: graph.CriticalityCritical, FirstSeen: base, LastSeen: base,
	})

	const flood = graph.MaxObservedEntities + 500
	for i := 0; i < flood; i++ {
		id := graph.EntityID(graph.TypeIdentity, fmt.Sprintf("e-%06d", i))
		g.UpsertEntity(graph.Entity{
			Type: graph.TypeIdentity, Key: fmt.Sprintf("e-%06d", i),
			Observed: true, FirstSeen: base, LastSeen: base.Add(time.Duration(i) * time.Millisecond),
		})
		g.UpsertEntity(graph.Entity{Type: graph.TypeCloudResource, Key: "survivor", Criticality: graph.CriticalityCritical})
		g.UpsertEdge(id, survivor, graph.RelAccessed, base, "")
	}

	for _, edge := range g.Neighbours(survivor) {
		peer := edge.From
		if peer == survivor {
			peer = edge.To
		}
		if _, ok := g.Entity(peer); !ok {
			t.Fatalf("an edge still names %q, which is no longer in the graph", peer)
		}
	}
}
