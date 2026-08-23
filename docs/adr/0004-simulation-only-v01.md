# 0004 — Ship v0.1 with no actuator

**Status:** Accepted · v0.1

## Context

A cyber defence platform that cannot respond is, in an obvious sense, incomplete.
The pressure to ship *something* that acts — even one action, even against one
system — is strong, and it is how most of these platforms get their first
dangerous bug.

Automated response acts on real people's access. Getting it wrong locks out an
employee, breaks a production service, or destroys evidence mid-incident. The
machinery that makes it safe — approval workflow, rollback, break-glass, rate
limits, protected identity classes — is more work than the actuator itself.

## Decision

v0.1 ships **no actuator at all**. Not a disabled one, not one behind a flag: the
code does not exist.

Three independent barriers:

1. `GRIEFER_RESPONSE_MODE=execute` is rejected at startup with an explicit message
   saying no actuator exists.
2. The Rego policy resolves every `execute` request to `require_approval`.
3. `applyDecision` has a hard stop even on `allow`:

```go
case policy.EffectAllow:
    if action.Mode != incidents.ModeSimulate {
        // Unreachable while the policy requires approval for every execute
        // request. Kept as a hard stop: GRIEFER v0.1 ships no actuator, and a
        // future policy change must not silently turn this into execution.
        action.Status = incidents.ActionRequiresApproval
        return
    }
```

The third is unreachable given the second. It exists so that a future policy edit
alone cannot promote the platform to a capability it has no implementation for.

`mode: execute` is still *accepted* by the API, so the policy contract is
exercised end to end rather than being theoretical until the day it matters.

## Consequences

**Good.** The safety machinery gets built and tested before anything can act.
`TestSafetyContract_NothingIsEverExecuted` iterates every action × every mode and
asserts nothing is executed. The claim in the README is a property of the control
flow, not a promise.

**Bad.** GRIEFER cannot yet do the thing it exists to do. Evaluating whether the
policy model is right in practice requires real actions, which is a chicken-and-egg
problem M3 has to break — deliberately, against a lab tenant first.

## Alternatives considered

**One safe action, e.g. `preserve_evidence`.** Rejected: needs the same
credentials, error handling, retry and audit machinery as any other. "Just one
action" is how the actuator gets built without the safety work.

**A pluggable actuator interface with no implementation.** Rejected as unnecessary
in v0.1 and actively risky: an interface invites an implementation before the
approval and rollback machinery exists.

**Execute against a mock system.** Rejected: a mock proves the code path works,
not that the safety model is right, and it creates a code path that a
configuration change turns real.
