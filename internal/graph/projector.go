package graph

import (
	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
)

// Project folds a normalized event into the graph, creating or updating the
// entities it mentions and the relationships it evidences.
//
// Projection is deliberately conservative: it records only relationships the
// event actually attests to. Inferring extra edges here would inflate blast
// radius with links nobody observed.
func (g *Graph) Project(ev *events.SecurityEvent) {
	if ev == nil {
		return
	}
	at := ev.Timestamp

	actorID := ""
	if ev.Actor != nil && ev.Actor.ID != "" {
		actorType := TypeIdentity
		switch ev.Actor.Type {
		case "account":
			actorType = TypeAccount
		case "service":
			actorType = TypeService
		case "application":
			actorType = TypeApplication
		}
		actorID = EntityID(actorType, ev.Actor.ID)
		g.UpsertEntity(Entity{
			ID:          actorID,
			Type:        actorType,
			Key:         ev.Actor.ID,
			Name:        ev.Actor.Name,
			Criticality: criticalityForActor(ev.Actor),
			Attributes:  actorAttributes(ev.Actor),
			FirstSeen:   at,
			LastSeen:    at,
			Observed:    true,
		})
	}

	if ev.Network != nil && ev.Network.SourceIP != "" {
		ipID := EntityID(TypeIPAddress, ev.Network.SourceIP)
		attrs := map[string]string{}
		if ev.Network.Country != "" {
			attrs["country"] = ev.Network.Country
		}
		if ev.Network.ASN != "" {
			attrs["asn"] = ev.Network.ASN
		}
		g.UpsertEntity(Entity{
			ID: ipID, Type: TypeIPAddress, Key: ev.Network.SourceIP,
			Name: ev.Network.SourceIP, Criticality: CriticalityLow,
			Attributes: attrs, FirstSeen: at, LastSeen: at, Observed: true,
		})
		g.UpsertEdge(actorID, ipID, RelAuthenticatedFrom, at, ev.ID)
	}

	if ev.Device != nil && (ev.Device.ID != "" || ev.Device.Hostname != "") {
		key := ev.Device.ID
		if key == "" {
			key = ev.Device.Hostname
		}
		devID := EntityID(TypeEndpoint, key)
		g.UpsertEntity(Entity{
			ID: devID, Type: TypeEndpoint, Key: key,
			Name: ev.Device.Hostname, Criticality: CriticalityMedium,
			Attributes: deviceAttributes(ev.Device),
			FirstSeen:  at, LastSeen: at, Observed: true,
		})
		g.UpsertEdge(actorID, devID, RelUsedDevice, at, ev.ID)
	}

	if ev.Actor != nil && ev.Actor.SessionID != "" {
		sessID := EntityID(TypeSession, ev.Actor.SessionID)
		g.UpsertEntity(Entity{
			ID: sessID, Type: TypeSession, Key: ev.Actor.SessionID,
			Name: ev.Actor.SessionID, Criticality: CriticalityMedium,
			Attributes: map[string]string{"privileged": boolString(ev.Actor.Privileged)},
			FirstSeen:  at, LastSeen: at, Observed: true,
		})
		g.UpsertEdge(actorID, sessID, RelOpenedSession, at, ev.ID)
	}

	if ev.Target != nil && ev.Target.ID != "" {
		targetType := EntityType(ev.Target.Type)
		if !targetType.Valid() {
			targetType = TypeService
		}
		targetID := EntityID(targetType, ev.Target.ID)
		// The producer's criticality is RECORDED, not believed.
		//
		// Criticality is the asset inventory's vocabulary: docs/THREAT_MODEL.md
		// T6 lists "the asset inventory is operator-supplied and not learned
		// from telemetry" among the things that make data poisoning hard. This
		// line was learning it from telemetry. A producer could declare any
		// target critical, upsertEntityLocked ratchets criticality upward and
		// never down, and the claim then fired the critical-resource detection
		// rule and inflated every blast radius that entity appeared in — which
		// is risk score, which is the automation floor.
		//
		// Keeping it as an attribute loses nothing an analyst wants: the claim
		// is still visible beside the entity, labelled as the producer's.
		attrs := map[string]string{}
		if ev.Target.Criticality != "" {
			attrs["claimed_criticality"] = ev.Target.Criticality
		}
		g.UpsertEntity(Entity{
			ID: targetID, Type: targetType, Key: ev.Target.ID,
			Name:      ev.Target.Name,
			FirstSeen: at, LastSeen: at, Observed: true,
			Attributes: attrs,
		})
		g.UpsertEdge(actorID, targetID, relationForEvent(ev), at, ev.ID)
	}

	if ev.Cloud != nil && ev.Cloud.ResourceID != "" {
		resID := EntityID(TypeCloudResource, ev.Cloud.ResourceID)
		g.UpsertEntity(Entity{
			ID: resID, Type: TypeCloudResource, Key: ev.Cloud.ResourceID,
			Name:       ev.Cloud.ResourceID,
			Attributes: cloudAttributes(ev.Cloud),
			FirstSeen:  at, LastSeen: at, Observed: true,
		})
		g.UpsertEdge(actorID, resID, relationForEvent(ev), at, ev.ID)
	}
}

// relationForEvent maps an event to the relation it evidences. Denied or
// failed activity records an attempt, not access — conflating the two would
// let a blocked attacker inflate their own apparent reach.
func relationForEvent(ev *events.SecurityEvent) Relation {
	switch ev.Category {
	case events.CategoryPrivilegeEscalation:
		return RelGrantedRoleOn
	case events.CategoryCredentialAccess, events.CategoryDataAccess, events.CategoryCloudAccess:
		if outcomeDenied(ev) {
			return RelAttemptedAccess
		}
		return RelAccessed
	default:
		if outcomeDenied(ev) {
			return RelAttemptedAccess
		}
		return RelAccessed
	}
}

func outcomeDenied(ev *events.SecurityEvent) bool {
	if ev.Labels == nil {
		return false
	}
	switch ev.Labels["outcome"] {
	case "denied", "failure", "blocked":
		return true
	default:
		return false
	}
}

func criticalityForActor(a *events.Actor) Criticality {
	if a.Privileged {
		return CriticalityHigh
	}
	return CriticalityMedium
}

func actorAttributes(a *events.Actor) map[string]string {
	attrs := map[string]string{"privileged": boolString(a.Privileged)}
	if a.Domain != "" {
		attrs["domain"] = a.Domain
	}
	return attrs
}

func deviceAttributes(d *events.Device) map[string]string {
	attrs := map[string]string{}
	if d.OS != "" {
		attrs["os"] = d.OS
	}
	if d.Managed != nil {
		attrs["managed"] = boolString(*d.Managed)
	}
	if d.Compliant != nil {
		attrs["compliant"] = boolString(*d.Compliant)
	}
	return attrs
}

func cloudAttributes(c *events.Cloud) map[string]string {
	attrs := map[string]string{}
	if c.Provider != "" {
		attrs["provider"] = c.Provider
	}
	if c.Region != "" {
		attrs["region"] = c.Region
	}
	if c.ResourceType != "" {
		attrs["resource_type"] = c.ResourceType
	}
	if c.AccountID != "" {
		attrs["account_id"] = c.AccountID
	}
	return attrs
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// EntityIDsForEvent returns the canonical graph identifiers an event refers to,
// in deterministic order. It is a pure function of the event: callers use it to
// link findings to entities without needing the graph itself.
func EntityIDsForEvent(ev *events.SecurityEvent) []string {
	if ev == nil {
		return nil
	}
	var ids []string
	add := func(id string) {
		if id == "" {
			return
		}
		for _, existing := range ids {
			if existing == id {
				return
			}
		}
		ids = append(ids, id)
	}

	if ev.Actor != nil && ev.Actor.ID != "" {
		actorType := TypeIdentity
		switch ev.Actor.Type {
		case "account":
			actorType = TypeAccount
		case "service":
			actorType = TypeService
		case "application":
			actorType = TypeApplication
		}
		add(EntityID(actorType, ev.Actor.ID))
		if ev.Actor.SessionID != "" {
			add(EntityID(TypeSession, ev.Actor.SessionID))
		}
	}
	if ev.Network != nil && ev.Network.SourceIP != "" {
		add(EntityID(TypeIPAddress, ev.Network.SourceIP))
	}
	if ev.Device != nil {
		key := ev.Device.ID
		if key == "" {
			key = ev.Device.Hostname
		}
		if key != "" {
			add(EntityID(TypeEndpoint, key))
		}
	}
	if ev.Target != nil && ev.Target.ID != "" {
		t := EntityType(ev.Target.Type)
		if !t.Valid() {
			t = TypeService
		}
		add(EntityID(t, ev.Target.ID))
	}
	if ev.Cloud != nil && ev.Cloud.ResourceID != "" {
		add(EntityID(TypeCloudResource, ev.Cloud.ResourceID))
	}
	return ids
}
