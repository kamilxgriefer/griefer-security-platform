# Unit tests for the GRIEFER Policy Kernel, written in Rego and run by `opa test`.
#
# The Go test suite in internal/policy already exercises this policy through the
# kernel. These tests exist in addition because they run without Go, which means
# a policy author can iterate on Rego alone, and because they pin the decision
# document's SHAPE — not just its effect — so a refactor cannot quietly drop a
# field the platform stores in its audit trail.

package griefer.response_test

import data.griefer.response
import rego.v1

# A well-formed request for a safe action on a well-evidenced incident. Every
# case below deviates from this baseline by exactly one field.
baseline := {
	"action": {
		"type": "preserve_evidence",
		"mode": "simulate",
		"known": true,
		"destructive": false,
		"reversible": true,
		"rollback_action": "release_evidence_hold",
		"targets_critical_asset": false,
		"isolation": false,
	},
	"incident": {
		"id": "inc-test",
		"risk_score": 81,
		"confidence": 0.95,
		"severity": "critical",
		"evidence_categories": ["authentication", "privilege_escalation", "credential_access"],
		"finding_count": 3,
	},
	"request": {"automated": true, "requested_by": "correlation-engine"},
}

# with_action returns the baseline with action fields overridden.
with_action(overrides) := object.union(baseline, {"action": object.union(baseline.action, overrides)})

with_incident(overrides) := object.union(baseline, {"incident": object.union(baseline.incident, overrides)})

with_request(overrides) := object.union(baseline, {"request": object.union(baseline.request, overrides)})

# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

test_corroborated_reversible_simulation_is_allowed if {
	decision := response.decision with input as baseline
	decision.effect == "allow"
	decision.allow == true
	count(decision.reasons) > 0
}

test_decision_document_carries_provenance if {
	decision := response.decision with input as baseline
	decision.policy_package == "griefer.response"
	decision.policy_version == "0.1.0"
	decision.evidence_category_count == 3
}

# ---------------------------------------------------------------------------
# Rule 3 — destructive actions are denied unconditionally
# ---------------------------------------------------------------------------

test_destructive_action_is_denied if {
	decision := response.decision with input as with_action({"type": "wipe_endpoint", "destructive": true, "reversible": false})
	decision.effect == "deny"
	decision.allow == false
}

test_destructive_action_is_denied_even_for_a_human if {
	request := object.union(
		with_action({"destructive": true}),
		{"request": {"automated": false, "requested_by": "analyst:senior"}},
	)
	decision := response.decision with input as request
	decision.effect == "deny"
}

test_destructive_action_is_denied_in_execute_mode if {
	decision := response.decision with input as with_action({"destructive": true, "mode": "execute"})
	decision.effect == "deny"
}

# ---------------------------------------------------------------------------
# Catalog and mode validation
# ---------------------------------------------------------------------------

test_action_outside_the_catalog_is_denied if {
	decision := response.decision with input as with_action({"type": "launch_missiles", "known": false})
	decision.effect == "deny"
}

test_unrecognised_mode_is_denied if {
	decision := response.decision with input as with_action({"mode": "yolo"})
	decision.effect == "deny"
}

# ---------------------------------------------------------------------------
# Rule 4 — no way back means a human decides
# ---------------------------------------------------------------------------

test_irreversible_action_requires_approval if {
	decision := response.decision with input as with_action({
		"type": "revoke_sessions",
		"reversible": false,
		"rollback_action": "",
	})
	decision.effect == "require_approval"
	decision.allow == false
}

test_reversible_action_without_a_rollback_requires_approval if {
	decision := response.decision with input as with_action({"rollback_action": ""})
	decision.effect == "require_approval"
}

# ---------------------------------------------------------------------------
# Rule 5 — critical assets always involve a human
# ---------------------------------------------------------------------------

test_critical_asset_requires_approval if {
	decision := response.decision with input as with_action({"targets_critical_asset": true})
	decision.effect == "require_approval"
}

# ---------------------------------------------------------------------------
# Rules 1 and 2 — corroboration before automation
# ---------------------------------------------------------------------------

test_single_evidence_category_requires_approval if {
	decision := response.decision with input as with_incident({"evidence_categories": ["authentication"]})
	decision.effect == "require_approval"
}

test_repeating_one_category_is_not_corroboration if {
	decision := response.decision with input as with_incident({"evidence_categories": [
		"authentication", "authentication", "authentication",
	]})
	decision.effect == "require_approval"
	decision.evidence_category_count == 1
}

test_single_weak_signal_cannot_trigger_isolation if {
	request := object.union(
		with_action({"type": "isolate_endpoint", "isolation": true, "rollback_action": "release_endpoint_isolation"}),
		{"incident": object.union(baseline.incident, {
			"evidence_categories": ["authentication"],
			"risk_score": 11,
		})},
	)
	decision := response.decision with input as request
	decision.effect == "require_approval"
}

# The isolation rule's conditions are a superset of the general corroboration
# rule's, so it can never change an effect: delete it and every existing test
# still passes. What it contributes is a REASON that names the action class, so
# that an operator reading the trail sees which safety property stopped the
# action instead of a generic message.
#
# This test asserts the reason rather than the verdict. Without it the rule has
# nothing guarding it, and docs/SAFETY_MODEL.md would be citing a control that
# could be removed silently.
test_isolation_refusal_names_the_action_class if {
	request := object.union(
		with_action({"type": "isolate_endpoint", "isolation": true, "rollback_action": "release_endpoint_isolation"}),
		{"incident": object.union(baseline.incident, {
			"evidence_categories": ["authentication"],
			"risk_score": 11,
		})},
	)
	decision := response.decision with input as request
	some reason in decision.reasons
	contains(reason, "Isolation-class action")
}

test_corroborated_isolation_may_be_simulated if {
	decision := response.decision with input as with_action({
		"type": "isolate_endpoint",
		"isolation": true,
		"rollback_action": "release_endpoint_isolation",
	})
	decision.effect == "allow"
}

test_low_risk_incident_does_not_authorise_automation if {
	decision := response.decision with input as with_incident({"risk_score": 12})
	decision.effect == "require_approval"
}

test_human_request_is_not_held_to_the_automation_bar if {
	request := object.union(
		with_request({"automated": false}),
		{"incident": object.union(baseline.incident, {
			"evidence_categories": ["authentication"],
			"risk_score": 10,
		})},
	)
	decision := response.decision with input as request
	decision.effect == "allow"
}

# ---------------------------------------------------------------------------
# Autonomy level — execution is never automatic
# ---------------------------------------------------------------------------

test_execute_mode_always_requires_approval if {
	decision := response.decision with input as with_action({"mode": "execute"})
	decision.effect == "require_approval"
}

# ---------------------------------------------------------------------------
# Fail closed
# ---------------------------------------------------------------------------

test_incomplete_input_is_denied if {
	decision := response.decision with input as {"action": {"type": "require_mfa"}}
	decision.effect == "deny"
	count(decision.reasons) > 0
}

test_empty_input_is_denied if {
	decision := response.decision with input as {}
	decision.effect == "deny"
}

# object.union merges recursively, so removing a field needs json.remove
# rather than an override.
test_missing_evidence_categories_is_denied if {
	request := json.remove(baseline, ["/incident/evidence_categories"])
	decision := response.decision with input as request
	decision.effect == "deny"
}

test_missing_risk_score_is_denied if {
	request := json.remove(baseline, ["/incident/risk_score"])
	decision := response.decision with input as request
	decision.effect == "deny"
}

test_missing_automated_flag_is_denied if {
	request := json.remove(baseline, ["/request/automated"])
	decision := response.decision with input as request
	decision.effect == "deny"
}

test_non_boolean_destructive_flag_is_denied if {
	decision := response.decision with input as with_action({"destructive": "false"})
	decision.effect == "deny"
}

# ---------------------------------------------------------------------------
# Requirement 7 — every decision is explained
# ---------------------------------------------------------------------------

test_every_decision_carries_a_reason if {
	every request in [
		baseline,
		with_action({"destructive": true}),
		with_action({"reversible": false}),
		with_action({"targets_critical_asset": true}),
		with_action({"mode": "execute"}),
		with_incident({"evidence_categories": []}),
		{},
	] {
		decision := response.decision with input as request
		count(decision.reasons) > 0
	}
}

test_allow_and_effect_never_disagree if {
	every request in [
		baseline,
		with_action({"destructive": true}),
		with_action({"reversible": false}),
		with_action({"targets_critical_asset": true}),
		with_action({"mode": "execute"}),
		{},
	] {
		decision := response.decision with input as request
		allow_agrees_with_effect(decision)
	}
}

# allow is a convenience field on the decision document; it must never say
# something different from effect, because a consumer may read either one.
allow_agrees_with_effect(decision) if {
	decision.effect == "allow"
	decision.allow == true
}

allow_agrees_with_effect(decision) if {
	decision.effect != "allow"
	decision.allow == false
}
