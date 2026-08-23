# GRIEFER Policy Kernel — response authorization.
#
# This policy is the single gate every proposed response action passes through.
# Neither the correlation engine nor (in a later milestone) any AI component can
# reach an actuator without a decision from here.
#
# Design rules that this file exists to enforce:
#
#   1. A single weak signal must never trigger automated isolation.
#   2. Automated response requires at least two INDEPENDENT evidence categories.
#   3. Destructive actions are denied unconditionally, in every mode.
#   4. An action with no defined rollback requires human approval.
#   5. An action touching a critical asset requires human approval.
#   6. Simulation (dry-run) may proceed automatically when nothing above fires.
#   7. Every decision carries at least one human-readable reason.
#
# The default is deny. Any input this policy does not fully understand produces
# a denial rather than an absence of opinion.

package griefer.response

import rego.v1

# ---------------------------------------------------------------------------
# Policy metadata
# ---------------------------------------------------------------------------

policy_version := "0.1.0"

# Minimum number of distinct evidence categories required before GRIEFER may
# act without a human. Two categories is the smallest number that can express
# "corroborated": one detection firing twice is still one point of view.
min_evidence_categories := 2

# Risk score below which no action is taken automatically, regardless of
# corroboration.
min_automated_risk_score := 40

# ---------------------------------------------------------------------------
# Input validation — fail closed on anything malformed
# ---------------------------------------------------------------------------

input_complete if {
	is_string(input.action.type)
	is_string(input.action.mode)
	is_boolean(input.action.known)
	is_boolean(input.action.destructive)
	is_boolean(input.action.reversible)
	is_boolean(input.action.targets_critical_asset)
	is_boolean(input.action.isolation)
	is_boolean(input.request.automated)
	is_array(input.incident.evidence_categories)
	is_number(input.incident.risk_score)
}

evidence_categories := {c | some c in input.incident.evidence_categories}

evidence_category_count := count(evidence_categories)

known_modes := {"simulate", "execute"}

# ---------------------------------------------------------------------------
# Denials
# ---------------------------------------------------------------------------

deny_reasons contains reason if {
	not input_complete
	reason := "Policy input is incomplete or malformed; GRIEFER fails closed on decision requests it cannot fully evaluate."
}

deny_reasons contains reason if {
	input.action.destructive == true
	reason := sprintf("Action %q is classified destructive. Destructive actions are denied unconditionally in every mode and cannot be approved through this path.", [input.action.type])
}

deny_reasons contains reason if {
	input.action.known == false
	reason := sprintf("Action type %q is not defined in the GRIEFER action catalog. Only catalog actions may be evaluated.", [input.action.type])
}

deny_reasons contains reason if {
	not input.action.mode in known_modes
	reason := sprintf("Response mode %q is not recognised.", [input.action.mode])
}

# ---------------------------------------------------------------------------
# Human approval requirements
# ---------------------------------------------------------------------------

approval_reasons contains reason if {
	input.action.reversible == false
	reason := sprintf("Action %q is not reversible. An action that cannot be undone requires an explicit human decision.", [input.action.type])
}

approval_reasons contains reason if {
	input.action.reversible == true
	input.action.rollback_action == ""
	reason := sprintf("Action %q declares no rollback action. Without a defined way back, a human must approve it.", [input.action.type])
}

approval_reasons contains reason if {
	input.action.targets_critical_asset == true
	reason := "Action targets an asset classified critical. Critical assets always require human approval."
}

approval_reasons contains reason if {
	input.request.automated == true
	evidence_category_count < min_evidence_categories
	reason := sprintf("Automated response requires at least %d independent evidence categories; this incident has %d.", [min_evidence_categories, evidence_category_count])
}

approval_reasons contains reason if {
	input.action.isolation == true
	input.request.automated == true
	evidence_category_count < min_evidence_categories
	reason := sprintf("Isolation-class action %q cannot be triggered automatically by a single weak signal.", [input.action.type])
}

approval_reasons contains reason if {
	input.request.automated == true
	input.incident.risk_score < min_automated_risk_score
	reason := sprintf("Incident risk score %v is below the automation threshold of %d.", [input.incident.risk_score, min_automated_risk_score])
}

# Execution against real systems is not an autonomy level GRIEFER grants in
# v0.1. The rule lives in policy rather than in application code so that the
# constraint is auditable in the same place as every other safety rule.
approval_reasons contains reason if {
	input.action.mode == "execute"
	reason := "Mode 'execute' performs changes in external systems and always requires human approval at the current autonomy level."
}

# ---------------------------------------------------------------------------
# Effect
# ---------------------------------------------------------------------------

# Default deny: if none of the rules below manage to produce an effect, the
# answer is no.
default effect := "deny"

effect := "deny" if {
	count(deny_reasons) > 0
}

effect := "require_approval" if {
	count(deny_reasons) == 0
	count(approval_reasons) > 0
}

effect := "allow" if {
	count(deny_reasons) == 0
	count(approval_reasons) == 0
	input_complete
}

allow_reasons contains reason if {
	effect == "allow"
	reason := sprintf(
		"Action %q is non-destructive and reversible via %q, corroborated by %d independent evidence categories at risk score %v, and runs in %q mode.",
		[input.action.type, input.action.rollback_action, evidence_category_count, input.incident.risk_score, input.action.mode],
	)
}

reasons := rs if {
	effect == "deny"
	rs := sort([r | some r in deny_reasons])
}

reasons := rs if {
	effect == "require_approval"
	rs := sort([r | some r in approval_reasons])
}

reasons := rs if {
	effect == "allow"
	rs := sort([r | some r in allow_reasons])
}

# ---------------------------------------------------------------------------
# Decision document
# ---------------------------------------------------------------------------

decision := {
	"effect": effect,
	"allow": effect == "allow",
	"reasons": non_empty_reasons,
	"policy_package": "griefer.response",
	"policy_version": policy_version,
	"evidence_category_count": evidence_category_count,
}

# Requirement 7: a decision without a reason is not a decision. If reason
# derivation ever fails, substitute an explicit fallback rather than emitting an
# empty list.
non_empty_reasons := rs if {
	count(reasons) > 0
	rs := reasons
}

non_empty_reasons := ["Denied by default: the Policy Kernel produced no applicable rule for this request."] if {
	count(reasons) == 0
}
