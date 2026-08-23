# 0005 — Gate automation on independent evidence categories

**Status:** Accepted · v0.1

## Context

Automated response needs a threshold. The obvious candidate is confidence: act
when the system is confident enough.

Confidence is the wrong quantity. A single detection that fires ten times can
produce high confidence from one point of view — and one point of view is exactly
what a compromised sensor gives an attacker. The failure mode is not "the system
was uncertain and acted anyway". It is "the system was certain, and wrong, because
all its evidence came from the same place".

## Decision

Automation is gated on the number of **distinct evidence categories** backing an
incident. The bar is two.

Every detection rule declares a category. The Policy Kernel counts distinct
values:

```rego
evidence_categories := {c | some c in input.incident.evidence_categories}
```

Risk scoring applies the same principle independently: within one category,
repetition contributes at most **+50%** beyond that category's strongest finding.

```go
func repetitionFactor(count int) float64 {
    if count <= 1 { return 1 }
    return 1 + repetitionCeiling*(1-math.Exp(-float64(count-1)/repetitionHalfLife))
}
```

Both mechanisms exist because they protect different things. The policy rule stops
an under-corroborated action. The scoring cap stops a flood of one signal type
from pushing an incident past the risk threshold in the first place. Without the
second, the first can be defeated by volume.

This was found by a test, not by design review:
`TestAssessDoesNotManufactureConfidenceFromRepetition` originally failed — ten
repeats of one category scored 53 while two independent categories scored 16,
which inverts the entire model. The cap is the fix.

Confidence aggregation follows the same rule: a noisy-OR over the strongest
finding per category, capped at 0.95.

## Consequences

**Good.** Compromising one sensor is not enough to drive an action. The bar is
explainable to an analyst in one sentence: *two different kinds of evidence, not
two alerts.* It is checkable in the audit trail, which records the categories
behind every decision.

**Bad.** A genuinely dangerous single-category incident cannot be automated. That
is accepted — it becomes `require_approval`, not `deny`. Category assignment
becomes safety-relevant: a rule that declares the wrong category weakens the
guarantee, which is why adding a category requires an ADR. Two rules that are
genuinely independent but share a category do not corroborate each other, which is
conservative in the right direction.

## Alternatives considered

**Confidence threshold alone.** Rejected: the failure mode described above.

**Distinct *sources* rather than categories.** Tempting — different products are
harder to compromise together. Rejected because one source legitimately produces
different kinds of evidence (an IdP reports both sign-ins and role changes), and
counting sources would refuse to corroborate genuinely independent observations.
Worth revisiting as an *additional* dimension in M5, when endpoint telemetry makes
multi-source corroboration common.

**Analyst-tunable threshold.** Deferred. Configuration is where safety properties
go to be misconfigured. It becomes reasonable once operational experience shows
what a sensible range is.
