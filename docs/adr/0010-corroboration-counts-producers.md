# 0010 — Count distinct producers, where producers exist

**Status:** Accepted · v0.1 (M4)

## Context

[ADR 0005](0005-evidence-categories.md) gates automation on two distinct
evidence *categories*. It rejected distinct *sources* as the bar, for a reason
that still holds — one source legitimately produces several kinds of evidence,
and counting sources would refuse to corroborate genuinely independent
observations — and then said, in the same paragraph, that the idea was worth
revisiting as an additional dimension.

[ADR 0009](0009-authenticated-event-producers.md) made that possible and did not
take it. It authenticated producers and bound each to an entitled source
identity, and recorded in terms that the gate still counted independent
CATEGORY and never independent SOURCE. A live test made the point: one entitled
producer posting four schema-valid events for one identity still reached three
categories and still cleared the risk floor.

`TestSafetyContract_OneCredentialSatisfiesTheCorroborationGate` states that
residual in executable form, and this record is what makes half of it false.

## Decision

**Automated response additionally requires evidence from two distinct
authenticated producers — in deployments that authenticate producers at all.**

ANDed with the category bar, never replacing it. 0005's reasoning is untouched
and it stays Accepted: categories still answer "how many kinds of evidence", and
producers now answer "how many sensors said so".

### How the policy knows whether to apply it

From the evidence, not from a flag:

```rego
producers := object.get(input.incident, "evidence_producers", [])
count(producers) > 0
count(producers) < min_evidence_producers
```

A non-empty producer list *is* the deployment saying it attributes telemetry.
Once one producer is enrolled, ingest refuses unattributed events, so every
finding carries one — an incident with zero producers is a deployment that has
enrolled none.

That derivation is worth more than the flag it replaces. A field asserting
"producers are enrolled" would be one more input to keep true, and a policy
reading it would be trusting a claim rather than counting evidence.

**It also removes a deployment hazard.** The alternative was to add
`is_array(input.incident.evidence_producers)` to `input_complete`, which an
older binary would fail — and this policy's default is `deny`, so a bundle
deployed ahead of the binary would refuse every action until they matched.
`object.get` with a default degrades to today's behaviour instead, so the two
halves may be deployed in either order.

### What an unenrolled deployment gets

Today's gate, unchanged, and that is the cost of this shape. A deployment with
no producers is held to categories alone, which one caller can satisfy — the
residual 0009 documented, now scoped to deployments that have not enrolled
anybody rather than to all of them.

The alternative was to apply the bar unconditionally, which is the more honest
position on its face: without authenticated producers GRIEFER cannot establish
independent corroboration, so it should not act alone. It was rejected because
every current deployment, the demonstration stack and three policy tests enrol
nobody, so the bar would disable automation everywhere and teach operators that
the gate is something to be worked around. A control that arrives as an
obstacle before it arrives as a capability gets configured away.

The honest half is kept by saying it plainly rather than by enforcing it:
docs/SAFETY_MODEL.md and T1 both state that a deployment without producers is
held to the weaker bar, and the residual test keeps asserting it.

## Failure modes

**A partially attributed incident.** Old events carry no producer and new ones
do, so the count reflects only the attributed half and can sit at one. The rule
then fires and asks for a human, which is the safe direction.

**One producer, many source identities.** Entitlement makes this a
misconfiguration rather than an attack: a credential claims only the pairs its
operator listed. Two entitled pairs on one credential still count as one
producer, because the count is over credentials.

**Two credentials, one compromise.** Not addressed, and not addressable here.
Two keys in one CI secret store, on one collector host or in one deployment
manifest count as two. The Security Graph has no producer entity, so nothing can
place them behind a shared root. "Two distinct producer credentials" is what the
documentation must say; "two independent sensors" is what it must not.

## Consequences

`min_evidence_producers := 2`, compiled rather than configured. 0005 rejected a
configurable corroboration bar for a reason that applies unchanged: a safety
threshold an operator can lower under pressure is a safety threshold that will
be lowered under pressure, and the incident that lowers it is the one it exists
for.

Isolation-class actions get their own producer rule for the same reason they
have their own category rule: so that a refusal names the action class rather
than arriving as a generic message.

The decision document records `evidence_producer_count`, so a reader of the
trail can tell a two-producer allow from a five-producer one — the gap that
`evidence_category_count` had until it was plumbed through.

`TestSafetyContract_OneCredentialSatisfiesTheCorroborationGate` keeps passing
and its comment now says what it documents: the unenrolled case. When the bar
becomes unconditional, that test fails, and its failure is the signal.

## Alternatives considered

**Replace categories with producers.** Rejected. It would supersede 0005 rather
than extend it, and 0005's objection is correct: an identity provider reporting
a sign-in and a role change is two kinds of evidence from one honest sensor, and
refusing to corroborate them would make the platform worse at its job.

**A configured minimum.** Rejected, per 0005 and above.

**A `producers_enrolled` flag in the policy input.** Rejected in favour of
deriving it. One more field to keep true, and a policy that reads a claim rather
than counting evidence.

**`is_array` in `input_complete`.** Rejected. It makes the bundle and the binary
order-dependent, with `default deny` as the failure, in exchange for catching a
malformed input that `object.get` already handles safely.
