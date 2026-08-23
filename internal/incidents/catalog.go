package incidents

import (
	"errors"
	"fmt"
	"sort"
)

// ErrUnknownActionType is returned when a caller asks for an action GRIEFER
// does not define.
var ErrUnknownActionType = errors.New("unknown response action type")

// ActionSpec is the server-owned definition of a response action.
//
// Every safety-relevant property of an action — is it destructive, can it be
// undone, what undoes it — lives here and nowhere else. Clients and telemetry
// supply an action *name*; they never supply its properties. That inversion is
// what stops "reversible: true" from being something an attacker can assert.
type ActionSpec struct {
	Type string
	// Title is the analyst-facing label.
	Title string
	// Description explains what the action would do in a real deployment.
	Description string
	// Destructive marks an action that irreversibly destroys data or access.
	// Destructive actions are denied by policy unconditionally in every mode.
	Destructive bool
	// Reversible marks an action that a defined rollback can undo.
	Reversible bool
	// RollbackAction names the action that reverses this one. Empty means no
	// rollback exists, which forces human approval.
	RollbackAction string
	// Isolation marks containment actions that cut a subject off from the
	// environment. These carry the highest false-positive cost and are held to
	// the corroboration requirement.
	Isolation bool
	// SimulationTemplate renders the simulated effect description.
	SimulationTemplate string
}

// catalog is the complete set of actions GRIEFER v0.1 will consider. Anything
// not listed here is rejected before it reaches the Policy Kernel.
var catalog = map[string]ActionSpec{
	"preserve_evidence": {
		Type:               "preserve_evidence",
		Title:              "Preserve evidence",
		Description:        "Place a retention hold on the events, sessions and audit records linked to this incident.",
		Destructive:        false,
		Reversible:         true,
		RollbackAction:     "release_evidence_hold",
		SimulationTemplate: "Would place a retention hold on %d linked entities; no access is changed.",
	},
	"require_mfa": {
		Type:               "require_mfa",
		Title:              "Require step-up MFA",
		Description:        "Force a step-up authentication challenge on the identity's next sign-in.",
		Destructive:        false,
		Reversible:         true,
		RollbackAction:     "remove_mfa_requirement",
		SimulationTemplate: "Would require step-up authentication for %d identity-linked entities on next sign-in.",
	},
	"temporarily_suspend_privileges": {
		Type:               "temporarily_suspend_privileges",
		Title:              "Temporarily suspend elevated privileges",
		Description:        "Remove the identity's elevated role assignments for a bounded period.",
		Destructive:        false,
		Reversible:         true,
		RollbackAction:     "restore_privileges",
		SimulationTemplate: "Would suspend elevated role assignments affecting %d entities until an analyst restores them.",
	},
	"isolate_endpoint": {
		Type:               "isolate_endpoint",
		Title:              "Isolate endpoint",
		Description:        "Cut the endpoint's network access except for the management channel.",
		Destructive:        false,
		Reversible:         true,
		RollbackAction:     "release_endpoint_isolation",
		Isolation:          true,
		SimulationTemplate: "Would place %d endpoint-linked entities into network isolation, management channel retained.",
	},
	"revoke_sessions": {
		Type:        "revoke_sessions",
		Title:       "Revoke active sessions",
		Description: "Invalidate the identity's refresh and access tokens, forcing re-authentication.",
		Destructive: false,
		// A revoked token cannot be un-revoked. The user simply signs in again,
		// so the action is low-harm — but it is genuinely not reversible, and
		// saying otherwise would let it bypass the approval gate.
		Reversible:         false,
		RollbackAction:     "",
		Isolation:          true,
		SimulationTemplate: "Would invalidate active sessions across %d entities; affected users must re-authenticate.",
	},
	"rotate_exposed_secret": {
		Type:        "rotate_exposed_secret",
		Title:       "Rotate exposed secret",
		Description: "Generate a new value for the exposed secret and retire the current one.",
		Destructive: false,
		// The previous secret value is gone once rotated; consumers still
		// holding it break until they refresh.
		Reversible:         false,
		RollbackAction:     "",
		SimulationTemplate: "Would rotate the exposed secret and invalidate the current value for %d dependent entities.",
	},

	// --- Destructive actions -------------------------------------------------
	// These are defined so that the platform has a name for them and so the
	// deny path is exercised by real inputs rather than by a synthetic test
	// double. They are never recommended and always denied.
	"delete_identity": {
		Type:        "delete_identity",
		Title:       "Delete identity",
		Description: "Permanently delete the identity object and its history.",
		Destructive: true,
		Reversible:  false,
	},
	"wipe_endpoint": {
		Type:        "wipe_endpoint",
		Title:       "Wipe endpoint",
		Description: "Remotely erase the endpoint's storage.",
		Destructive: true,
		Reversible:  false,
	},
	"purge_audit_records": {
		Type:        "purge_audit_records",
		Title:       "Purge audit records",
		Description: "Permanently delete audit records associated with the incident.",
		Destructive: true,
		Reversible:  false,
	},
}

// Lookup returns the specification for an action type.
func Lookup(actionType string) (ActionSpec, error) {
	spec, ok := catalog[actionType]
	if !ok {
		return ActionSpec{}, fmt.Errorf("%w: %q", ErrUnknownActionType, actionType)
	}
	return spec, nil
}

// KnownActionTypes returns every defined action type, sorted. Used by the API
// to render a stable allowlist in error responses and by the OpenAPI document.
func KnownActionTypes() []string {
	out := make([]string, 0, len(catalog))
	for k := range catalog {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// RecommendableActionTypes returns the non-destructive actions the correlation
// engine is permitted to propose.
func RecommendableActionTypes() []string {
	out := make([]string, 0, len(catalog))
	for k, spec := range catalog {
		if !spec.Destructive {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
