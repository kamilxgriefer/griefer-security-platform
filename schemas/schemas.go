// Package schemas embeds the JSON Schema documents that define GRIEFER's wire
// format so that validation never depends on files being present on disk at
// runtime.
package schemas

import "embed"

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
