# 0003 — Fail closed on policy unavailability

**Status:** Accepted · v0.1

## Context

The Policy Kernel is a network dependency in the deployed configuration. It will
sometimes be unreachable — restart, network partition, misconfiguration.

Two options: fail open (permit and log) or fail closed (deny).

Fail-open has a genuine argument. During an incident, an unreachable policy engine
blocking containment could mean the difference between a contained breach and a
bad one.

Fail-closed has a better one: an attacker who can reach the policy engine can
usually also make it unreachable. A fail-open system hands its safety property to
whoever can send a SYN flood.

## Decision

Fail closed, and make it impossible to ignore.

`Kernel.Evaluate` returns **both** a valid deny decision and an error:

```go
Evaluate(ctx context.Context, in Input) (incidents.PolicyDecision, error)
```

A caller that forgets to check `err` still gets a denial. The error is returned
too, because a degraded kernel is an operational signal — but safety does not
depend on anyone reading it.

`GRIEFER_OPA_FAIL_CLOSED` exists as configuration and `Validate` **rejects any
attempt to set it false**. It is surfaced only so the guarantee is visible in
`griefer-api -print-config`.

The denial is a `200` with `fail_closed: true` and an `X-Griefer-Policy-Degraded`
header, not a `503`. The evaluation reached a definitive answer; the answer is no.

Malformed input is also denied, explicitly. In Rego, rules that simply fail to
fire leave a decision undefined — and undefined is indistinguishable from
permission, so `input_complete` denies anything the policy cannot fully evaluate.

## Consequences

**Good.** No configuration, deployment mistake or attack turns GRIEFER permissive.
The contract is checkable at the type level.

**Bad.** A policy outage stops all response. Detection and recording continue —
that asymmetry is deliberate: blinding the recorder is an attack, refusing to act
is a delay. Break-glass (M3) exists partly to give a human a path when the
platform will not act.

## Alternatives considered

**Fail open with alerting.** Rejected: the alert arrives after the wrong action.

**Cache the last decision.** Rejected: a cached allow is exactly what an attacker
wants to induce before knocking the kernel over.

**Fail open only for reversible non-critical actions.** Tempting, and still
rejected: it makes the safety property depend on metadata correctness at the
moment the authority is absent. Revisit if operational experience shows outages
are common and the delay causes real harm.
