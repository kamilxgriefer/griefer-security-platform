// Package events defines GRIEFER's normalized security event, the schema
// validation applied at the trust boundary, and the guard that stops telemetry
// from carrying control-plane instructions.
package events

import (
	"strings"
	"time"
)

// SchemaVersion is the event schema version produced and accepted by this build.
const SchemaVersion = "0.1"

// Severity is the ordered severity scale shared by events, findings and
// incidents.
type Severity string

// Severity levels, ordered from least to most severe.
const (
	SeverityInformational Severity = "informational"
	SeverityLow           Severity = "low"
	SeverityMedium        Severity = "medium"
	SeverityHigh          Severity = "high"
	SeverityCritical      Severity = "critical"
)

var severityRank = map[Severity]int{
	SeverityInformational: 0,
	SeverityLow:           1,
	SeverityMedium:        2,
	SeverityHigh:          3,
	SeverityCritical:      4,
}

// Rank returns the ordinal position of s. Unknown values rank lowest so that an
// unrecognised severity can never be treated as an escalation.
func (s Severity) Rank() int { return severityRank[s] }

// Valid reports whether s is one of the defined severity levels.
func (s Severity) Valid() bool {
	_, ok := severityRank[s]
	return ok
}

// Max returns the more severe of s and other.
func (s Severity) Max(other Severity) Severity {
	if other.Rank() > s.Rank() {
		return other
	}
	return s
}

// Category is an evidence class. Categories matter beyond labelling: the Policy
// Kernel counts DISTINCT categories to decide whether a response may be taken
// without a human, so two findings from the same category are deliberately not
// treated as independent corroboration.
type Category string

// Evidence categories accepted by the v0.1 schema.
const (
	CategoryAuthentication      Category = "authentication"
	CategorySessionAnomaly      Category = "session_anomaly"
	CategoryPrivilegeEscalation Category = "privilege_escalation"
	// #nosec G101 -- this names an evidence category, not a credential.
	CategoryCredentialAccess Category = "credential_access"
	CategoryCloudAccess      Category = "cloud_access"
	CategoryDataAccess       Category = "data_access"
	CategoryProcessExecution Category = "process_execution"
	CategoryNetworkActivity  Category = "network_activity"
	CategoryConfigChange     Category = "configuration_change"
)

// Actor is the principal that performed the activity.
type Actor struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	Domain     string `json:"domain,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	Privileged bool   `json:"privileged,omitempty"`
}

// Target is the object the activity was performed against.
type Target struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Criticality string `json:"criticality,omitempty"`
}

// Device describes the endpoint the activity originated from.
type Device struct {
	ID        string `json:"id,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	OS        string `json:"os,omitempty"`
	Managed   *bool  `json:"managed,omitempty"`
	Compliant *bool  `json:"compliant,omitempty"`
}

// Network carries the addressing context of the activity.
type Network struct {
	SourceIP          string `json:"source_ip,omitempty"`
	DestinationIP     string `json:"destination_ip,omitempty"`
	ASN               string `json:"asn,omitempty"`
	Country           string `json:"country,omitempty"`
	FirstSeenForActor bool   `json:"first_seen_for_actor,omitempty"`
}

// Cloud carries cloud control-plane context.
type Cloud struct {
	Provider     string `json:"provider,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
}

// RawReference points at the original payload in the producer's own store.
// GRIEFER stores a reference rather than an unbounded blob: accepting arbitrary
// raw payloads inline is both a storage-exhaustion and a parser-attack surface.
type RawReference struct {
	URI       string `json:"uri"`
	Digest    string `json:"digest,omitempty"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
}

// SecurityEvent is the normalized unit of telemetry. Timestamps are always UTC
// after normalization.
type SecurityEvent struct {
	ID            string            `json:"id"`
	SchemaVersion string            `json:"schema_version"`
	Timestamp     time.Time         `json:"timestamp"`
	ReceivedAt    time.Time         `json:"received_at"`
	SourceType    string            `json:"source_type"`
	SourceName    string            `json:"source_name"`
	EventType     string            `json:"event_type"`
	Category      Category          `json:"category"`
	Severity      Severity          `json:"severity"`
	Actor         *Actor            `json:"actor,omitempty"`
	Target        *Target           `json:"target,omitempty"`
	Device        *Device           `json:"device,omitempty"`
	Network       *Network          `json:"network,omitempty"`
	Cloud         *Cloud            `json:"cloud,omitempty"`
	RawReference  *RawReference     `json:"raw_reference,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	CorrelationID string            `json:"correlation_id,omitempty"`

	// ProducerID names the authenticated producer that supplied this event.
	//
	// Server-assigned, exactly as ReceivedAt is: Normalize zeroes whatever a
	// sender wrote here and Ingest fills it from the verified credential. A
	// producer id a producer could set would attribute telemetry to whoever
	// asked to be attributed, which is the opposite of the point.
	//
	// Empty on an event ingested before producers were enrolled, and on every
	// event in a deployment that has enrolled none.
	ProducerID string `json:"producer_id,omitempty"`

	// Quarantined records label keys that were stripped by the control-plane
	// guard before the event entered the pipeline. It is populated by GRIEFER,
	// never by a producer.
	Quarantined []string `json:"quarantined,omitempty"`
}

// ActorKey returns the stable identity key for the event's actor, or "" when
// the event has no attributable actor.
func (e *SecurityEvent) ActorKey() string {
	if e.Actor == nil || e.Actor.ID == "" {
		return ""
	}
	return strings.ToLower(e.Actor.Type + ":" + e.Actor.ID)
}
