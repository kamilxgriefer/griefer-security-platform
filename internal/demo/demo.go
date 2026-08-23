// Package demo loads GRIEFER's synthetic fixtures: the baseline asset
// inventory that seeds the Security Graph, and the scenario replayed through
// the real ingest API.
package demo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/fixtures"
	"github.com/kamilxgriefer/griefer-security-platform/internal/graph"
)

// Scenario is a replayable sequence of synthetic events.
type Scenario struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Synthetic   bool              `json:"synthetic"`
	Events      []json.RawMessage `json:"events"`
}

// LoadInventory decodes the embedded baseline asset inventory.
func LoadInventory() (graph.Inventory, error) {
	return loadInventoryFS(fixtures.FS, fixtures.InventoryPath)
}

func loadInventoryFS(fsys fs.FS, path string) (graph.Inventory, error) {
	raw, err := fs.ReadFile(fsys, path)
	if err != nil {
		return graph.Inventory{}, fmt.Errorf("demo: read inventory: %w", err)
	}
	var inv graph.Inventory
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&inv); err != nil {
		return graph.Inventory{}, fmt.Errorf("demo: decode inventory: %w", err)
	}
	if len(inv.Entities) == 0 {
		return graph.Inventory{}, fmt.Errorf("demo: inventory contains no entities")
	}
	return inv, nil
}

// LoadScenario decodes the named embedded scenario.
func LoadScenario(path string) (*Scenario, error) {
	raw, err := fs.ReadFile(fixtures.FS, path)
	if err != nil {
		return nil, fmt.Errorf("demo: read scenario %q: %w", path, err)
	}
	var sc Scenario
	if err := json.Unmarshal(raw, &sc); err != nil {
		return nil, fmt.Errorf("demo: decode scenario %q: %w", path, err)
	}
	if !sc.Synthetic {
		// A scenario that does not declare itself synthetic is refused. GRIEFER
		// ships no real telemetry, and this is the check that keeps it that way
		// if someone drops a capture into the fixtures directory.
		return nil, fmt.Errorf("demo: scenario %q is not marked synthetic and will not be loaded", path)
	}
	if len(sc.Events) == 0 {
		return nil, fmt.Errorf("demo: scenario %q contains no events", path)
	}
	return &sc, nil
}

// Rebase shifts every event so the last one lands at endingAt, preserving the
// relative spacing between steps.
//
// Fixtures carry absolute timestamps because a reader should be able to see the
// timeline of the scenario in the file. Replaying those absolute timestamps
// would eventually push the scenario outside the ingest window and turn the
// demo into a wall of rejections, so the replay path rebases instead.
func (s *Scenario) Rebase(endingAt time.Time) ([]json.RawMessage, error) {
	if len(s.Events) == 0 {
		return nil, fmt.Errorf("demo: scenario has no events to rebase")
	}
	type timed struct {
		doc map[string]json.RawMessage
		at  time.Time
	}
	parsed := make([]timed, 0, len(s.Events))
	var latest time.Time

	for i, raw := range s.Events {
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("demo: event %d is not a JSON object: %w", i, err)
		}
		rawTS, ok := doc["timestamp"]
		if !ok {
			return nil, fmt.Errorf("demo: event %d has no timestamp", i)
		}
		var ts string
		if err := json.Unmarshal(rawTS, &ts); err != nil {
			return nil, fmt.Errorf("demo: event %d timestamp is not a string: %w", i, err)
		}
		at, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return nil, fmt.Errorf("demo: event %d timestamp %q is not RFC 3339: %w", i, ts, err)
		}
		if at.After(latest) {
			latest = at
		}
		parsed = append(parsed, timed{doc: doc, at: at})
	}

	delta := endingAt.UTC().Sub(latest)
	out := make([]json.RawMessage, 0, len(parsed))
	for i, item := range parsed {
		shifted := item.at.Add(delta).UTC().Format(time.RFC3339)
		encoded, err := json.Marshal(shifted)
		if err != nil {
			return nil, fmt.Errorf("demo: encode rebased timestamp for event %d: %w", i, err)
		}
		item.doc["timestamp"] = encoded
		doc, err := json.Marshal(item.doc)
		if err != nil {
			return nil, fmt.Errorf("demo: re-encode event %d: %w", i, err)
		}
		out = append(out, doc)
	}
	return out, nil
}
