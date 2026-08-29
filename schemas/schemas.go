// Package schemas embeds the JSON Schema documents that define GRIEFER's wire
// format so that validation never depends on files being present on disk at
// runtime.
package schemas

import (
	"embed"
	"encoding/json"
	"fmt"
)

// FS holds every published schema, keyed by its path relative to this package
// (for example "events/security-event.v0.1.schema.json").
//
//go:embed events/*.json incidents/*.json
var FS embed.FS

// EventSchemaPath is the schema applied to every event accepted by the v0.1
// ingest API.
const EventSchemaPath = "events/security-event.v0.1.schema.json"

// EventSchemaVersion is the only event schema version the v0.1 API accepts.
const EventSchemaVersion = "0.1"

// SourceTypes returns the source_type values the event schema accepts.
//
// Read from the embedded schema rather than restated in Go, because a second
// copy of an enum is a second thing to forget. Configuration uses it to refuse
// a producer entitlement naming a source type no event could ever carry, which
// would otherwise be a typo that silently never matches.
func SourceTypes() ([]string, error) {
	body, err := FS.ReadFile(EventSchemaPath)
	if err != nil {
		return nil, fmt.Errorf("schemas: read %s: %w", EventSchemaPath, err)
	}
	var doc struct {
		Properties struct {
			SourceType struct {
				Enum []string `json:"enum"`
			} `json:"source_type"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("schemas: parse %s: %w", EventSchemaPath, err)
	}
	if len(doc.Properties.SourceType.Enum) == 0 {
		return nil, fmt.Errorf("schemas: %s declares no source_type enum", EventSchemaPath)
	}
	return doc.Properties.SourceType.Enum, nil
}
