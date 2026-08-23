// Package graph maintains GRIEFER's Security Graph: the entities observed in
// telemetry, the baseline relationships imported from an asset inventory, and
// the reachability analysis used to estimate an incident's blast radius.
package graph

import (
	"strings"
	"time"
)

// EntityType enumerates the node kinds the v0.1 graph understands.
type EntityType string

// Entity types supported in v0.1.
const (
	TypeIdentity      EntityType = "identity"
	TypeAccount       EntityType = "account"
	TypeSession       EntityType = "session"
	TypeEndpoint      EntityType = "endpoint"
	TypeIPAddress     EntityType = "ip_address"
	TypeApplication   EntityType = "application"
	TypeSecret        EntityType = "secret"
	TypeCloudResource EntityType = "cloud_resource"
	TypeRepository    EntityType = "repository"
	TypeService       EntityType = "service"
)

var knownEntityTypes = map[EntityType]bool{
	TypeIdentity: true, TypeAccount: true, TypeSession: true,
	TypeEndpoint: true, TypeIPAddress: true, TypeApplication: true,
	TypeSecret: true, TypeCloudResource: true, TypeRepository: true,
	TypeService: true,
}

// Valid reports whether t is a supported entity type.
func (t EntityType) Valid() bool { return knownEntityTypes[t] }

// Criticality expresses how much an entity matters to the organisation. It is
// an input to both risk scoring and the Policy Kernel, which requires human
// approval before acting on a critical asset.
type Criticality string

// Criticality levels.
const (
	CriticalityLow      Criticality = "low"
	CriticalityMedium   Criticality = "medium"
	CriticalityHigh     Criticality = "high"
	CriticalityCritical Criticality = "critical"
)

var criticalityWeight = map[Criticality]float64{
	CriticalityLow:      1,
	CriticalityMedium:   3,
	CriticalityHigh:     8,
	CriticalityCritical: 20,
}

// Weight returns the blast-radius weight of c. Unknown values fall back to the
// medium weight rather than zero, so an unclassified asset is never treated as
// worthless.
func (c Criticality) Weight() float64 {
	if w, ok := criticalityWeight[c]; ok {
		return w
	}
	return criticalityWeight[CriticalityMedium]
}

// Rank orders criticality levels for comparison.
func (c Criticality) Rank() int {
	switch c {
	case CriticalityCritical:
		return 3
	case CriticalityHigh:
		return 2
	case CriticalityLow:
		return 0
	default:
		return 1
	}
}

// Entity is a node in the Security Graph.
type Entity struct {
	ID          string            `json:"id"`
	Type        EntityType        `json:"type"`
	Key         string            `json:"key"`
	Name        string            `json:"name,omitempty"`
	Criticality Criticality       `json:"criticality"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	FirstSeen   time.Time         `json:"first_seen"`
	LastSeen    time.Time         `json:"last_seen"`
	// Observed is true when the entity was seen in telemetry rather than only
	// declared by the asset inventory.
	Observed bool `json:"observed"`
}

// Relation names the meaning of an edge.
type Relation string

// Relations emitted by the v0.1 projector and inventory loader.
const (
	RelAuthenticatedFrom Relation = "authenticated_from"
	RelOpenedSession     Relation = "opened_session"
	RelUsedDevice        Relation = "used_device"
	RelGrantedRoleOn     Relation = "granted_role_on"
	RelAccessed          Relation = "accessed"
	RelAttemptedAccess   Relation = "attempted_access"
	RelOwns              Relation = "owns"
	RelGrantsAccessTo    Relation = "grants_access_to"
	RelRunsOn            Relation = "runs_on"
	RelMemberOf          Relation = "member_of"
)

// Edge is a directed relationship between two entities.
type Edge struct {
	From      string    `json:"from"`
	To        string    `json:"to"`
	Relation  Relation  `json:"relation"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	EventIDs  []string  `json:"event_ids,omitempty"`
}

// EntityID builds the canonical graph identifier for a typed natural key.
func EntityID(t EntityType, key string) string {
	return string(t) + ":" + strings.ToLower(strings.TrimSpace(key))
}

// SplitEntityID reverses EntityID. ok is false when id is not a canonical
// entity identifier.
func SplitEntityID(id string) (t EntityType, key string, ok bool) {
	idx := strings.Index(id, ":")
	if idx <= 0 || idx == len(id)-1 {
		return "", "", false
	}
	t = EntityType(id[:idx])
	if !t.Valid() {
		return "", "", false
	}
	return t, id[idx+1:], true
}
