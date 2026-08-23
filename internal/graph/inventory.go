package graph

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Inventory is a declared baseline of the environment: assets and the
// relationships between them that exist independently of any telemetry.
//
// Without a baseline, blast radius can only describe what an attacker has
// already touched. The baseline is what lets GRIEFER answer the more useful
// question: what does the compromised thing *unlock*?
type Inventory struct {
	Entities []InventoryEntity `json:"entities"`
	Edges    []InventoryEdge   `json:"edges"`
}

// InventoryEntity is a declared asset.
type InventoryEntity struct {
	Type        EntityType        `json:"type"`
	Key         string            `json:"key"`
	Name        string            `json:"name"`
	Criticality Criticality       `json:"criticality"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

// InventoryEdge is a declared relationship between two assets.
type InventoryEdge struct {
	From     string   `json:"from"`
	To       string   `json:"to"`
	Relation Relation `json:"relation"`
}

// LoadInventory decodes an inventory document and merges it into g.
// Declared assets are marked unobserved until telemetry mentions them.
func (g *Graph) LoadInventory(r io.Reader, at time.Time) error {
	var inv Inventory
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&inv); err != nil {
		return fmt.Errorf("decode inventory: %w", err)
	}
	return g.ApplyInventory(inv, at)
}

// ApplyInventory merges a decoded inventory into g, validating every reference
// so a typo in the fixture surfaces as an error rather than a silently missing
// edge.
func (g *Graph) ApplyInventory(inv Inventory, at time.Time) error {
	ids := make(map[string]bool, len(inv.Entities))
	for i, e := range inv.Entities {
		if !e.Type.Valid() {
			return fmt.Errorf("inventory entity %d: unsupported type %q", i, e.Type)
		}
		if e.Key == "" {
			return fmt.Errorf("inventory entity %d: key is required", i)
		}
		id := EntityID(e.Type, e.Key)
		ids[id] = true
		g.UpsertEntity(Entity{
			ID: id, Type: e.Type, Key: e.Key, Name: e.Name,
			Criticality: e.Criticality, Attributes: e.Attributes,
			FirstSeen: at, LastSeen: at, Observed: false,
		})
	}
	for i, edge := range inv.Edges {
		if !ids[edge.From] {
			return fmt.Errorf("inventory edge %d: unknown source entity %q", i, edge.From)
		}
		if !ids[edge.To] {
			return fmt.Errorf("inventory edge %d: unknown destination entity %q", i, edge.To)
		}
		if edge.Relation == "" {
			return fmt.Errorf("inventory edge %d: relation is required", i)
		}
		g.UpsertEdge(edge.From, edge.To, edge.Relation, at, "")
	}
	return nil
}
