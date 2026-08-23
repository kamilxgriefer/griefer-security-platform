package correlation

import (
	"sort"

	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/graph"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
)

// categoryActions maps an evidence category to the containment steps that
// address it.
//
// The correlation engine only ever PROPOSES. Whether a proposal may be carried
// out — and whether a human must approve it first — is decided exclusively by
// the Policy Kernel. Keeping the two apart is what makes the safety argument
// checkable: no amount of detection logic can talk itself into an action.
var categoryActions = map[events.Category][]string{
	events.CategoryAuthentication:      {"require_mfa"},
	events.CategorySessionAnomaly:      {"revoke_sessions"},
	events.CategoryPrivilegeEscalation: {"temporarily_suspend_privileges"},
	events.CategoryCredentialAccess:    {"rotate_exposed_secret"},
	events.CategoryCloudAccess:         {"preserve_evidence"},
	events.CategoryDataAccess:          {"preserve_evidence"},
	events.CategoryProcessExecution:    {"isolate_endpoint"},
	events.CategoryNetworkActivity:     {"isolate_endpoint"},
	events.CategoryConfigChange:        {"preserve_evidence"},
}

// actionTargetTypes says which entity type each action acts upon, in preference
// order. An action with no resolvable target is still proposed — the incident
// itself is the target — but it carries no target entity id.
var actionTargetTypes = map[string][]graph.EntityType{
	"require_mfa":                    {graph.TypeIdentity, graph.TypeAccount},
	"revoke_sessions":                {graph.TypeIdentity, graph.TypeAccount},
	"temporarily_suspend_privileges": {graph.TypeIdentity, graph.TypeAccount},
	"isolate_endpoint":               {graph.TypeEndpoint},
	"rotate_exposed_secret":          {graph.TypeSecret},
	"preserve_evidence":              {graph.TypeIdentity, graph.TypeAccount},
}

// actionRationale explains, in analyst language, why the action is on the list.
var actionRationale = map[string]string{
	"require_mfa":                    "Authentication evidence is present; a step-up challenge tests whether the session is still under the legitimate user's control.",
	"revoke_sessions":                "Session evidence suggests an established foothold; invalidating tokens forces re-authentication.",
	"temporarily_suspend_privileges": "Privilege change was observed; suspending elevated roles removes the durable access the change created.",
	"rotate_exposed_secret":          "A stored secret was read; rotation retires the value the attacker may now hold.",
	"isolate_endpoint":               "An endpoint is implicated; isolation limits further lateral movement while the investigation runs.",
	"preserve_evidence":              "Evidence should be held before any containment step changes the state an investigation depends on.",
}

// recommendActions builds the incident's recommended action list from its
// findings and the entities it touches. Output is deterministic.
func recommendActions(findings []incidents.Finding, entities []incidents.EntityRef) []incidents.RecommendedAction {
	wanted := map[string]bool{
		// Evidence preservation is always proposed: it is non-destructive,
		// reversible, and every containment step below degrades the evidence an
		// investigation would otherwise rely on.
		"preserve_evidence": true,
	}
	for _, f := range findings {
		for _, actionType := range categoryActions[f.Category] {
			wanted[actionType] = true
		}
	}
	// Endpoint containment becomes relevant as soon as an endpoint is in scope,
	// regardless of which category surfaced it.
	for _, e := range entities {
		if e.Type == graph.TypeEndpoint {
			wanted["isolate_endpoint"] = true
			break
		}
	}

	types := make([]string, 0, len(wanted))
	for t := range wanted {
		types = append(types, t)
	}
	sort.Strings(types)

	out := make([]incidents.RecommendedAction, 0, len(types))
	for _, actionType := range types {
		spec, err := incidents.Lookup(actionType)
		if err != nil || spec.Destructive {
			// Unknown or destructive actions are never recommended. Destructive
			// actions exist in the catalog only so the deny path is exercised
			// by real input.
			continue
		}
		target := resolveTarget(actionType, entities)
		action := incidents.RecommendedAction{
			ActionType:     spec.Type,
			Title:          spec.Title,
			Rationale:      actionRationale[actionType],
			Reversible:     spec.Reversible,
			Destructive:    spec.Destructive,
			RollbackAction: spec.RollbackAction,
		}
		if target != nil {
			action.TargetEntityID = target.ID
			action.TargetsCriticalAsset = target.Criticality == graph.CriticalityCritical
		}
		out = append(out, action)
	}
	return out
}

// resolveTarget picks the highest-criticality entity of an acceptable type,
// breaking ties by id so the choice is stable across runs.
func resolveTarget(actionType string, entities []incidents.EntityRef) *incidents.EntityRef {
	preferred, ok := actionTargetTypes[actionType]
	if !ok {
		return nil
	}
	for _, wantType := range preferred {
		var best *incidents.EntityRef
		for i := range entities {
			e := &entities[i]
			if e.Type != wantType {
				continue
			}
			if best == nil ||
				e.Criticality.Rank() > best.Criticality.Rank() ||
				(e.Criticality.Rank() == best.Criticality.Rank() && e.ID < best.ID) {
				best = e
			}
		}
		if best != nil {
			return best
		}
	}
	return nil
}
