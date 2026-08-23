# Data model

GRIEFER normalises everything at the trust boundary. The internal model belongs
to GRIEFER; a connector's job is to translate into it. No detection logic is ever
written against a vendor's field names.

---

## SecurityEvent

The unit of telemetry. Normative definition:
[`schemas/events/security-event.v0.1.schema.json`](../schemas/events/security-event.v0.1.schema.json).
That schema — not this document — is what the API enforces.

| Field | Required | Notes |
|---|---|---|
| `id` | server-assigned | UUIDv7 with an `evt-` prefix. Time-ordered, so pagination is stable. |
| `schema_version` | ✓ | Only `"0.1"` is accepted by the v0.1 API. |
| `timestamp` | ✓ | When it happened at the source. RFC 3339 **with a timezone**; normalized to UTC. |
| `received_at` | server-owned | Anything a producer supplies is discarded. |
| `source_type` | ✓ | Closed enum: `identity_provider`, `endpoint_agent`, `cloud_audit`, `application`, `network`, `secret_manager`, `source_control`, `synthetic_fixture`. |
| `source_name` | ✓ | Which instance. |
| `event_type` | ✓ | Producer-neutral verb, `lower_snake_case`. |
| `category` | ✓ | **Evidence category** — see below. |
| `severity` | ✓ | `informational` … `critical`. |
| `actor` | | Who did it. |
| `target` | | What it was done to. |
| `device` | | Where it came from. |
| `network` | | Addressing context. |
| `cloud` | | Cloud control-plane context. |
| `raw_reference` | | **Pointer** to the original payload, never the payload. |
| `labels` | | Bounded annotations. Data only. |
| `correlation_id` | | Producer-side trace id. Defaults to the event id. |

### Why `category` is not just a label

Categories are the unit of corroboration. The Policy Kernel counts **distinct**
categories when deciding whether automation is permitted, so the category a rule
declares directly determines what GRIEFER may do without a human.

Two rules sharing a category do not corroborate each other. That is the point:

```
authentication  session_anomaly  privilege_escalation
credential_access  cloud_access  data_access
process_execution  network_activity  configuration_change
```

A new category is a safety-relevant change, because it changes what counts as
independent evidence. It needs an ADR.

### Why raw payloads are excluded

`raw_reference` holds a URI, an optional digest and a size — never the payload.

Accepting arbitrary raw blobs inline would make GRIEFER a storage-exhaustion
target and would drag every producer's parser quirks across the trust boundary.
The original stays in the producer's own store, where it already is, and GRIEFER
holds a pointer an investigator can follow.

### Bounds

Every field is bounded, because "unbounded field on an attacker-influenced object"
is a denial-of-service primitive:

| Bound | Value |
|---|---|
| Labels | 32 keys, key ≤ 48 chars, value ≤ 256 chars |
| String fields | 64–512 chars depending on field |
| `raw_reference.size_bytes` | ≤ 1 GiB (a claim about the remote object) |
| Request body | `GRIEFER_MAX_REQUEST_BYTES`, default 1 MiB |
| Batch | `GRIEFER_MAX_BATCH_EVENTS`, default 500 |

### The ingest window

Producer timestamps are bounded on both sides:

- **Future:** more than 5 minutes ahead → rejected. A far-future timestamp would
  keep an incident's `last_seen` artificially current forever.
- **Past:** older than 30 days → rejected. Stale telemetry cannot be replayed into
  a live incident.

Both limits are ingest policy, not clock correction. GRIEFER never rewrites a
source timestamp.

## Entity

A node in the Security Graph. Canonical id is `type:key`, lowercased —
`identity:u-1042`, `cloud_resource:arn:aws:s3:::halberd-finance-archive`.

```
identity  account  session  endpoint  ip_address
application  secret  cloud_resource  repository  service
```

### Criticality drives policy

`low` · `medium` · `high` · `critical`

Criticality is not decoration. It feeds blast-radius weighting **and** the
Policy Kernel's critical-asset rule, so a mislabelled asset weakens a control.

It comes from the operator's asset inventory, and merge semantics never downgrade
it: a later, sparser observation cannot turn a critical asset into a low one.
Unknown criticality defaults to `medium` — unclassified is not worthless.

### Observed vs declared

`observed: false` means the inventory declared it; `true` means telemetry has
mentioned it. The distinction matters for blast radius: the estimate is only as
good as the baseline, and a graph built purely from telemetry can only describe
what an attacker already touched, never what it unlocks.

## Finding

One detection rule firing over one or more events.

A rule that fires again **updates** its finding rather than appending a duplicate.
An incident listing the same detection twenty times is noise, not evidence.

Findings carry the rule id, the category, a confidence in `(0,1]`, ATT&CK
techniques, and the entity and event ids they rest on.

## Incident

A correlated set of findings attributed to one subject.

**The subject is the acting identity.** Hosts get rebuilt, addresses rotate,
tokens expire; the identity persists and is the thing being abused. Events with no
attributable actor are grouped by source, never merged into someone else's
incident.

Every derived field — entities, blast radius, risk, severity, confidence,
techniques, recommended actions, title — is **recomputed from scratch** whenever
evidence changes. Derived state is never patched incrementally, which is what
makes the risk score a pure function of the evidence and therefore reproducible
from an audit entry.

### Risk scoring

Two properties are requirements, not implementation details:

**Monotonic.** Adding evidence never lowers the score. An analyst who watches a
score drop while an attack progresses stops trusting the number.

**Saturating.** The score approaches but never reaches 100. Beyond a point,
"worse" is not an actionable distinction, and a linear score would let a flood of
low-value findings outrank a single critical one.

```
evidence   = Σ over categories: bestWeighted(category) × repetitionFactor(count)
factor     = 1 + 0.18 × (categories − 1) + 0.15 if a critical asset is touched
raw        = evidence × factor + 0.12 × blastScore
score      = round(100 × (1 − e^(−raw / 55)))
```

`repetitionFactor` approaches but never exceeds 1.5. Within one category,
repetition adds at most 50% — ten sign-in anomalies for one identity are one
observation restated. Without that cap, a single noisy rule outscores a genuinely
corroborated incident, which inverts the entire safety model.

Confidence is a noisy-OR over the strongest finding per category, capped at
**0.95**. GRIEFER is never certain, and a displayed 100% invites an analyst to
stop thinking.

### Blast radius

A bounded breadth-first walk from the incident's entities, in both edge
directions — an attacker holding an identity can reach what it can reach, and an
attacker holding a secret can reach whatever it unlocks.

```
weighted = Σ criticality_weight(node) / max(hops, 1)
score    = round(100 × (1 − e^(−weighted / 25)))
```

Bounded at **3 hops** by default. Reachability in an identity graph degrades into
"everything reaches everything" past a small number of hops, and an unbounded walk
produces a number that looks precise and means nothing.

Every reachable node carries `from` and `via` — the entity it was reached through
and the relationship used. That lets a consumer redraw the actual path. A diagram
that infers plausible-looking edges presents invented evidence as observation.

## ResponseAction

A proposed containment step and everything GRIEFER decided about it.

**What the client cannot supply:** whether the action is destructive, whether it
is reversible, or what would roll it back. Those are resolved server-side from the
action catalog. A caller that could assert them could talk the Policy Kernel into
anything.

Statuses: `simulated` · `requires_approval` · `denied` · `rejected`.

`simulated` means policy allowed it and GRIEFER computed the effect it *would*
have had. Nothing outside GRIEFER changed. `executed_at` is always absent in v0.1.

## AuditEntry

Append-only. `sequence` is assigned by the store, so ordering is decided by
PostgreSQL rather than by whichever process happened to write.

Entries must never carry secret material. `details` is for identifiers, verdicts
and counts — the things needed to reconstruct a decision.

## Schema versioning

`schema_version` is on the wire object, not in the URL. A producer states which
contract it is speaking; GRIEFER decides whether it still accepts it.

| Change | Version impact |
|---|---|
| New optional field | None — additive |
| New enum value in `category` or `severity` | **Minor bump.** New categories change what counts as independent evidence, so this is safety-relevant. |
| New `source_type` | Minor bump |
| Field becomes required | **Major bump** |
| Field removed or retyped | **Major bump** |
| Bound tightened | **Major bump** — previously valid events would start failing |

**Policy for M2 onward:** the API accepts the current major version and one
previous minor version. Producers get one release cycle to move. Stored events
keep the version they arrived with; readers must handle every version still on
disk.

v0.1 accepts `"0.1"` only, because there is nothing to be compatible with yet.

## The OCSF relationship

GRIEFER's event schema is **inspired by** the Open Cybersecurity Schema
Framework's layout — the activity + actor + target + metadata separation, and the
idea of a normalised class hierarchy.

**GRIEFER v0.1 does not claim OCSF conformance.** No conformance testing has been
done, the field names differ, and the class hierarchy is far smaller. Claiming
conformance without testing it would be exactly the kind of unverified assertion
this project exists to avoid.

What GRIEFER borrowed:

- Separating who acted from what was acted upon, rather than a flat bag.
- A normalised category taxonomy instead of vendor event codes.
- Metadata about the observation held apart from the observation itself.

What GRIEFER deliberately did not:

- The full OCSF class hierarchy. v0.1 needs nine categories, not hundreds of
  classes, and a schema nobody can hold in their head is a schema nobody validates
  against.
- OCSF field naming. Aligning names without aligning semantics produces something
  that looks interoperable and is not.
- OCSF profiles and extensions.

**M6** adds a conformance test suite and an OCSF export mapping. Until that
passes, this document says "inspired by" and the schema description says the same.

## Storage shape

Each table stores the indexed scalar columns GRIEFER filters and orders by, plus
the full domain object as JSONB.

That is a deliberate v0.1 trade-off. It keeps the Go model and the database in
step while the model is still moving, at the cost of query flexibility and index
efficiency. It will not survive real volume.

**M2** normalises entities and edges into relational tables — that is where the
graph needs to live for querying anyway. Time-partitioning `security_events`
comes with the first deployment that has enough of them to need it.
