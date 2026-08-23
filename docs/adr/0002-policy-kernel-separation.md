# 0002 — Separate the Policy Kernel from detection

**Status:** Accepted · v0.1

## Context

A detection engine that finds something dangerous is the component best placed to
know how dangerous it is. It is tempting to let it decide what to do about it —
the information is right there, and an extra hop adds latency and complexity.

That temptation is exactly the problem. A component that both decides *what
happened* and *what may be done* can talk itself into acting. Its own confidence
is the input to its own authorisation.

Every serious incident involving automated response has the same shape: the system
was confident, the confidence was wrong, and there was nothing between the
confidence and the effect.

## Decision

The correlation engine may only **recommend**. All authority lives in the Policy
Kernel, expressed in Rego and evaluated by OPA.

Enforced structurally: `internal/correlation` does not import `internal/policy`,
has no reference to any actuator, and produces `incidents.RecommendedAction`
values that describe an action without being able to perform one. It could not act
if it wanted to.

Policy is written in Rego rather than Go so that it can be read, reviewed and
tested by someone who does not read Go — and so it can be changed without
rebuilding the platform.

## Consequences

**Good.** The safety argument is auditable in one file. `opa test` verifies the
rules with no Go involved. Policy can be reloaded independently in the Compose
deployment. A future AI component gets the same treatment for free, because there
is nowhere else for it to go.

**Bad.** Two languages. A Rego error is a class of bug Go's compiler cannot catch —
mitigated by 25 policy unit tests, `opa check` in CI, and a startup health check
that refuses to serve with an unusable kernel. Every action costs a policy
evaluation. The action catalog must be kept in step with the policy's expectations.

## Alternatives considered

**Policy in Go.** Rejected: the safety argument would be spread across the codebase
and reviewable only by Go programmers, and changing it would require a release.

**Policy in YAML.** Rejected: the rules need boolean composition, set operations
and negation. A YAML policy language becomes a bad programming language.

**A permission bit per action.** Rejected: cannot express "requires two
independent evidence categories", which is the rule that actually matters.
