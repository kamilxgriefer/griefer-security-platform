# GRIEFER audit model

**Scope:** v0.1, as implemented on `security/m1-1-audit-dependency-hardening`.
This document describes what the audit trail records, who is allowed to read it,
what guarantees it makes, and — at least as importantly — what it does not.

The trail exists to answer one question after the fact: *why did GRIEFER do
that, and on whose behalf?* Every design decision below follows from that
question. Where a decision is a compromise, it is written down as one rather
than dressed up.

Related reading: [`docs/SAFETY_MODEL.md`](../SAFETY_MODEL.md) for the failure
philosophy and the M4 tamper-evidence plan;
[`docs/ACCESS_CONTROL.md`](../ACCESS_CONTROL.md) for the console's role model.

---

## 1. What is audited

Every entry is written by one of two places: `internal/api/service.go` (the
service layer) or `cmd/griefer-api/main.go` (process lifecycle). Nothing else in
the platform writes to the trail.

### 1.1 Ingest path — `Service.Ingest`

| Action | Outcome | Subject | Recorded in `Details` |
|---|---|---|---|
| `event.rejected` | `denied` | `event`, no id | `error_kind: "schema_validation"` |
| `event.rejected` | `denied` | `event`, event id | `error_kind: "normalization"` |
| `event.label_quarantined` | `denied` | `event`, event id | `quarantined_keys`, `source_name` |
| `correlation.failed` | `failure` | `event`, event id | — |
| `incident.updated` | `success` | `incident`, incident id | `event_id`, `risk_score`, `severity`, `finding_count`, `evidence_types`, `blast_radius`, `critical_assets` |
| `event.ingested` | `success` | `event`, event id | `category`, `severity`, `event_type`, `degraded` |

Two things about this table are deliberate and easy to misread.

**A schema rejection carries no subject id.** The event never decoded, so there
is no id to name. Recording a fabricated one would be worse than recording none.

**`event.ingested` is written last**, after the quarantine, correlation and
incident entries for the same event. Sequence numbers are the trail's ordering,
so a reader walking the sequence sees the analysis before the acceptance. That
reads oddly until you notice the alternative: writing the acceptance first means
that a crash mid-ingest leaves a trail claiming a clean acceptance that never
finished.

**A quarantine is recorded as `denied`, not as a failure.** A producer trying to
put a reserved control-plane label key into telemetry is not a malfunction; it
is an attempt to name a control-plane concept from the data plane, and it is
kept because it is a signal. Only the stripped **keys** are recorded, never
their values.

### 1.2 Response-action evaluation — `Service.EvaluateAction`

Every path out of `EvaluateAction` leaves a trail, including the paths that
reject the request before any policy is consulted. An evaluation that produced
no record is indistinguishable, later, from one that never happened.

| Situation | Entries written | Policy consulted |
|---|---|---|
| Action type not in the catalog | `response.rejected` | no |
| Unrecognised mode | `response.rejected` | no |
| Incident does not exist | `response.rejected` | no |
| Incident could not be loaded | `response.rejected` | no |
| Policy allowed a simulation | `policy.evaluated` + `response.simulated` | yes |
| Policy required approval | `policy.evaluated` + `response.requires_approval` | yes |
| Policy denied | `policy.evaluated` + `response.denied` | yes |
| Policy Kernel unreachable or timed out | `policy.evaluated` + `response.denied` | attempted |

The split into two entries is not redundancy. `policy.evaluated` records *what
the Policy Kernel was asked and what it answered*; the second entry records
*what GRIEFER then did about it*. They are separable because they can disagree —
`applyDecision` downgrades an `allow` on a non-simulate mode to
`requires_approval`, because v0.1 ships no actuator. If one entry carried both,
that downgrade would be invisible.

`internal/api/audit_taxonomy_test.go` pins the exact set of actions each branch
must leave behind, so a new branch that forgets its entry fails the suite rather
than quietly shipping.

### 1.3 Process lifecycle — `cmd/griefer-api/main.go`

`system.started` records the version, storage kind, policy engine, event bus,
loaded rule count and configured response mode. `system.stopped` records the
shutdown. Startup is the one audit write that is **fatal**: if the trail cannot
be written at boot, the process refuses to start rather than serve without one.

---

## 2. What is *not* audited

Stating this plainly matters more than the table above, because an operator who
believes the trail is complete will draw conclusions from its silence.

- **Reads are not audited.** No handler in `internal/api/handlers.go` writes an
  entry. Listing incidents, fetching an entity, and *reading the audit trail
  itself* leave no trace in the trail. Read access appears only in the access
  log, which is not append-only and is not part of this model.
- **Authentication failures are not audited.** A request rejected by
  `ServiceAuth` or by `PrincipalMiddleware` never reaches the service layer, so
  no entry is written. Those show up in the access log with their status code.
- **Batch envelope rejections are not audited.** A malformed `events` array, an
  empty one, or one over `MaxBatchEvents` is refused in `handleIngestBatch`
  before `Ingest` runs. Individual events *inside* an accepted batch are audited
  exactly as single submissions are.
- **A failed event write is not audited.** If `SaveEvent` fails, `Ingest`
  returns the error and logs it; there is no `event.rejected` entry, because
  nothing was rejected — the platform failed. The `/ready` store check is what
  surfaces this.
- **Console sign-in and sign-out are not audited.** The console keeps its own
  session; it writes nothing to the platform trail. An administrator can see
  *that* `console:alice` evaluated an action, not *when she signed in*.
- **Ingest is never attributed to an operator.** Ingest entries set no actor, so
  they default to `system:griefer` even when the request carried an actor
  assertion. Telemetry producers are machines; attributing an event to whichever
  operator's session happened to relay it would be a fiction.
- **`incident.created` is declared and never emitted.** The correlator returns
  one incident whether it created or merged, so every correlation records
  `incident.updated`. The constant is reserved, not live. Likewise
  `insufficient_permission` and `persistence_failed` are declared results with
  no production emitter yet — nothing in v0.1 reaches them.

---

## 3. Outcome and result are different questions

`Outcome` answers *did it succeed*. `Result` — in `Details["result"]` — answers
*what happened*.

They are not the same question, and collapsing them loses the distinction the
platform most needs to preserve. GRIEFER fails closed: an unreachable Policy
Kernel refuses an action exactly as a deliberate refusal does. Read by outcome
alone, a considered denial and a broken dependency are both `denied`, and a
platform that cannot tell those apart cannot be operated — an operator staring
at a wall of denials has no way to know whether the rules are working or the
kernel is down.

| Outcome | Meaning |
|---|---|
| `success` | The operation completed |
| `denied` | Refused — by policy, by validation, or by the fail-closed path |
| `failure` | A component failed |
| `pending` | Awaiting a human decision (`require_approval`) |

| Result | Written when | Outcome it accompanies |
|---|---|---|
| `allowed` | Policy allowed and the action was simulated | `success` |
| `requires_approval` | Policy required a human | `pending` |
| `denied` | Policy refused on the rules | `denied` |
| `invalid_action` | Action type is not in the catalog | `denied` |
| `validation_failed` | Unrecognised mode, or unknown incident | `denied` |
| `policy_unavailable` | Kernel returned an error | `denied` |
| `policy_timeout` | Kernel error wrapping `context.DeadlineExceeded` | `denied` |
| `internal_error` | Incident could not be loaded | `failure` |
| `insufficient_permission` | *Reserved; no emitter in v0.1* | — |
| `persistence_failed` | *Reserved; no emitter in v0.1* | — |

`policy_timeout` is separated from `policy_unavailable` because the two send an
operator to different places: one is a slow or overloaded kernel, the other is a
kernel that is not there at all.

---

## 4. What each evaluation entry records

Every entry from `EvaluateAction` is built by one shared `base` closure, so no
branch can quietly omit the actor, the request id or the subject. All of them
carry:

```
result, incident_id, action_type, mode, response_action_id, policy_revision
```

`response_action_id` is stamped even when no response action row is written — an
unknown action type or a missing incident still allocates an id, so the two
audit entries for a rejected evaluation refer to the same thing and can be
joined later.

The `policy.evaluated` entry adds the decision metadata:

```
effect, fail_closed, engine, policy_version,
reversible, destructive, rollback_action, targets_critical,
risk_score, evidence_types
```

Both `policy_version` and `policy_revision` appear, and they are not duplicates.
`policy_version` is what the kernel *declared* about itself; `policy_revision` is
a hash of what was actually loaded (§6). When they disagree, the second one is
the truth.

`reversible`, `destructive`, `rollback_action` and `targets_critical` come from
the server-side action catalog and the graph — never from the request. A client
that could assert them could talk the Policy Kernel into anything, so they are
recorded as the values the decision was actually made on.

### By verdict

- **Allowed** (`response.simulated`, outcome `success`): the entry above, with
  `effect: "allow"`, and `Reason` set to the policy's own reasons. The action row
  written in the same transaction carries the simulated effect.
- **Requires approval** (`response.requires_approval`, outcome `pending`): the
  same shape, `effect: "require_approval"`. Note that a policy `allow` on a
  non-simulate mode also lands here, with a `Reason` naming the missing actuator
  rather than a policy rule.
- **Denied** (`response.denied`, outcome `denied`): the same shape with
  `effect: "deny"`. `fail_closed` distinguishes a rules-based refusal from the
  fail-closed default — this is the field that makes `denied` readable.
- **Rejected before policy** (`response.rejected`): one entry only, no decision
  metadata, because there was no decision. `Reason` is the operator-facing
  sentence, and `result` says which of the three rejections it was.

---

## 5. The actor trust boundary

### Why a service credential cannot answer "who"

GRIEFER's API is not reached by people. Only the console's server-side gateway
and the seeder hold the internal service token, and `ServiceAuth` compares a
SHA-256 of the presented bearer token in constant time. That check answers
exactly one question: *is this a component we deployed?*

It cannot answer *which person is behind this request*, because one shared
secret cannot distinguish operators, cannot be scoped, and cannot be revoked for
one caller without revoking it for all. Real per-user authentication at the API
is M8. Until then the audit trail still has to name a person, so the platform
uses a trusted-subsystem assertion and is honest about it being one: **the
console authenticates the person, and the API trusts the console because the
console proved it is the console.**

### How the assertion travels

`internal/httpx/principal.go` defines `Principal{Subject, Role}`, carried in two
headers:

- `X-Griefer-Actor` — e.g. `console:alice`
- `X-Griefer-Actor-Role` — `admin` or `analyst`

`PrincipalMiddleware` is mounted **inside** `ServiceAuth` in
`internal/api/router.go`. The ordering is load-bearing: in front of the
credential check, anyone who could reach the API could name themselves in the
audit trail without presenting anything at all.

The console builds these headers from the signed session cookie in
`console/lib/principal.ts` and never forwards what the browser sent. A browser
cannot set them, because a browser cannot reach the API at all — and if it could
set them on the gateway, the gateway would discard them.

Both values are bounded by `^[A-Za-z0-9._:@-]{1,128}$`. The constraint is not
tidiness: the value reaches the audit trail and the Policy Kernel, so it must not
carry a newline that forges a second log line, an unbounded length that bloats a
row, or a control character that breaks whatever later renders it.

### Absent, present, malformed

- **Absent** means "no operator", and it passes. The caller is a trusted
  component acting on nobody's behalf — the seeder, a migration, a probe. The
  entry is attributed to `system:griefer`.
- **Present and well-formed** is used as given.
- **Present but malformed is a 400.** Dropping it instead would leave the request
  looking exactly like the absent case — and `RequireRole` admits the absent
  case. A caller could then walk past the administrator-only gate simply by
  making its own identity header unparseable. Sending a header the API cannot
  read is a bug in a trusted component either way, and it should be visible
  rather than silently downgraded into more access than the caller asked for.

### The body cannot name the actor

`EvaluateAction` ignores `req.RequestedBy` entirely and takes the actor from the
request context. A body is written by whoever made the call; attributing an
action to a value the caller chose makes the trail look authoritative while
saying nothing, which is worse than leaving it empty.

The console gateway **strips** `requested_by` and `automated` from the body
rather than rewriting them, so a console and an API deployed at different
versions cannot end up disagreeing about which of the two decided who the
operator was.

`automated` is derived, not accepted: the policy input is
`principal.Zero() && req.Automated`. The flag selects which corroboration bar the
policy applies, so a caller able to set it could choose the bar it is judged
against. A request carrying an operator is a person pressing a button, by
definition.

### The role is stored, not looked up

`Entry.ActorRole` records the role held **at the time of the entry**. It is
stored beside the actor rather than resolved when the trail is read, because
roles change: an account demoted next week must not retroactively appear to have
been an analyst when it acted as an administrator. Rows written before the
column existed keep `NULL`, which reads as "unknown" rather than as a false
claim.

---

## 6. Policy revision

`policies.Revision()` returns `"sha256:"` followed by a hex digest over every
non-test `.rego` file in the embedded policy tree, visited in **sorted** path
order, with each path length-prefixed alongside its contents.

Each choice closes a specific hole:

- **A content hash rather than the `Version` constant.** `Version` is a string
  somebody has to remember to change, and it has read `"0.1.0"` through every
  edit the policy has ever had. An audit entry stamped with it cannot tell you
  which rules were in force. A content hash cannot be forgotten.
- **Paths mixed in, length-prefixed.** Renaming a file changes the revision even
  when its bytes do not, and two different file layouts cannot hash the same way
  by running their names and contents together.
- **Explicitly sorted.** `embed.FS` happens to iterate in sorted order today; a
  revision that silently depended on that would change when the standard library
  did.
- **Test files excluded.** They are not evaluated, and including them would move
  the revision when nothing about the rules changed — which trains people to
  ignore the field.

If the embedded tree cannot be read, the function returns
`"sha256:unavailable"` rather than panicking. An entry saying the revision is
unknown is far better than a platform that will not start.

---

## 7. The transaction boundary

`storage.Store` carries two methods for this, on the interface rather than as an
optional capability a caller type-asserts for:

```go
SaveActionWithAudit(ctx, action *incidents.ResponseAction, entries []*audit.Entry) error
AppendAudit(ctx, entries []*audit.Entry) error
```

They are mandatory because an optional guarantee is one a caller silently loses
when a store does not implement it, and "the audit trail is complete unless you
happened to configure the other store" is not a guarantee worth stating. A `nil`
action writes only the entries — the shape of an evaluation rejected before any
action exists.

**What is inside the transaction:** the response action and every audit entry
describing its evaluation. A response action with no audit entry is a change
nobody can account for; an audit entry naming an action that was never written
points at nothing.

**What is outside it, deliberately: the policy evaluation.** Holding a database
transaction open across a call to another service ties this database's
connection budget to that service's latency — a slow Policy Kernel becomes an
exhausted connection pool, and then an outage in a system that was working.
`s.kernel.Evaluate` is called, the verdict is turned into a status, and only then
is a transaction opened.

**PostgreSQL:** a small `querier` interface (`Exec`/`Query`/`QueryRow`) is
satisfied by both `pgxpool.Pool` and `pgx.Tx`, so each statement is written once
and can run standalone or inside a transaction. The alternative — a second copy
of every statement for the transactional path — is how two copies end up
disagreeing about what a column means. `inTx` rolls back using
`context.WithoutCancel`, because when the failure *is* a cancelled or timed-out
request, a rollback issued on that same dead context cannot be delivered and the
transaction is left for the server to reap.

**In-memory:** no transactions exist, so atomicity is provided by validating
everything before mutating anything and then performing all writes under a single
lock. That is genuinely equivalent here: no goroutine can observe a half-applied
state, and nothing can fail midway because the only failures are the validation
done up front. `internal/storage/atomicity_test.go` runs the same suite against
both stores, so a rule that held only in PostgreSQL would be caught rather than
discovered in production.

**Recorder.Prepare** exists for this boundary. It validates and stamps an entry —
id, UTC timestamp, default actor — *without* writing it, so an atomic caller
gets identical validation to a direct `Record` call. Without it, atomic callers
would have to duplicate the rules, and the copy would drift.

**Ingest is not atomic.** `Ingest` saves the event, then records its entries
separately through `Recorder.Record`. This is a real asymmetry, not an oversight
to gloss over: only the evaluation path writes its subject and its trail as one
unit.

---

## 8. What an entry must never contain

`Details` is for identifiers, verdicts and counts — the things needed to
reconstruct a decision. Never:

1. **Passwords, tokens, API keys or the internal service credential.**
2. **Session cookies or any bearer material**, including partial or truncated
   forms.
3. **Database connection strings**, which carry a password.
4. **Raw telemetry payloads.** The event id is recorded; the event body is not.
5. **Private hostnames or internal network addresses** that would hand out part
   of the network map.
6. **The values of quarantined labels.** Only the stripped keys are kept.
7. **Personal data beyond the operator identifier** already asserted by the
   console.
8. **Free-form text from a request body.** Rejection reasons are constructed
   server-side from a fixed sentence plus a bounded, validated value.

The test for whether an entry is worth writing is whether it is enough to
reconstruct the decision without access to the original incident. The test for
whether a field belongs in it is whether an administrator reading the whole trail
would learn a secret they did not already hold.

---

## 9. Who may read the trail

**Administrators only, enforced in two places.**

**Layer one — the console.** `console/lib/roles.ts` reserves `/audit` and
`/admin` for administrators, and `console/middleware.ts` enforces it in front of
every route rather than page by page. The same module also reserves the upstream
paths `/api/griefer/audit` and `/api/griefer/identity`, because gating the pages
alone would be theatre: the console reaches the platform through
`/api/griefer/*`, so an analyst session could otherwise request the audit
endpoint directly and read the answer as JSON.

**Layer two — the API.** `GET /api/v1/audit` is wrapped in
`httpx.RequireRole(RoleAdmin)` in `internal/api/router.go`. It is the only route
that carries a role gate, which `TestTheRoleGateGuardsOnlyTheAuditTrail` pins.

**Why two.** One layer is one bug away from being none. If the console's route
table and its API allowlist ever disagree, or a new page forgets its gate, the
API still refuses. The role constants are duplicated across Go and TypeScript
rather than shared, because the two run in different languages on opposite sides
of a network boundary; what keeps them honest is that a disagreement surfaces as
a 403 in the RBAC tests rather than as a silent grant.

**The limit, stated plainly.** `RequireRole` admits a request with **no** actor
assertion, so anything holding the service credential can read the trail by
simply not asserting an identity. That is deliberate — refusing unattributed
requests would break the platform's own internals to guard against a caller who
already holds the strongest secret there is — but it means the role gate binds
the console, not the credential. The credential is the trust boundary; the role
refines attribution inside it. Closing this properly needs per-caller
credentials, which is M8.

**A second limit follows from the wiring.** `PrincipalMiddleware` is only mounted
when `InternalAPIToken` is set. With no token configured there is no principal to
gate on, `RequireRole` sees the zero principal, and the audit route answers
anyone who can reach it — which is why `config.Validate` permits an empty token
only on a loopback bind. Conversely, an actor header presented *without* the
credential buys nothing at all: the request is refused with 401 before the header
is ever read, which `TestActorHeadersAreIgnoredWithoutTheServiceCredential`
pins.

Reading the trail is itself unaudited (§2).

---

## 10. No update, no delete — enforced at three levels

**1. The Go type system.** `audit.Sink` has exactly two methods, `Append` and
`List`. `storage.Store` embeds it rather than exposing generic audit CRUD, so
there is no method anywhere in the platform that can modify an entry. This is the
level that matters most, because it makes the guarantee a property of what can be
written rather than of what people remember not to write.

**2. A reflection test.** `TestSinkExposesNoMutationMethods` in
`internal/audit/audit_test.go` walks `audit.Sink`'s method set and fails if it
contains anything other than `Append` and `List`, or if the count changes. Adding
an `Update` breaks the build's tests, not just a review convention.

**3. A PostgreSQL trigger.** `audit_log_append_only` fires `BEFORE UPDATE OR
DELETE ON audit_log FOR EACH ROW`, executing
`griefer_audit_log_is_append_only()`, which raises with `ERRCODE =
'restrict_violation'`. This predates M1.1 and is defence in depth against a
future code path — or a careless `psql` session — that tries anyway.
`TestPostgresAuditLogRejectsUpdateAndDelete` proves it against a real database
(skipped without `GRIEFER_TEST_POSTGRES_DSN`), covering a rewritten verdict, a
deleted row, and an attempt to clear the whole table.

A fourth, weaker property supports these: `sequence` is `BIGSERIAL`, assigned by
the database, so a removed row leaves a visible gap.

The in-memory store needs one extra precaution the database gets for free.
PostgreSQL marshals `Details` to JSON at write time, so a caller's map is copied
by definition; the memory store deep-copies `Details` on the way in *and* on the
way out. Without that, `clone := *entry` would leave the stored entry sharing the
caller's map header, and anyone keeping their pointer could turn a denial into an
approval without calling the store at all.
`TestACommittedEntryCannotBeChangedByMutatingTheCallersCopy` covers this.

---

## 11. Honest limits

**The trail is tamper-resistant, not tamper-evident.** Nothing above detects a
change made by someone with database access; it only stops changes made through
the platform. A role with DDL rights can drop the trigger and rewrite history,
and nothing in v0.1 would show it. Hash-chaining each entry to its predecessor
and anchoring the chain externally is M4 — the plan is in
[`docs/SAFETY_MODEL.md`](../SAFETY_MODEL.md). Chaining alone would not be enough;
an attacker who can rewrite the table can rewrite the chain, so external
anchoring is what turns resistance into evidence.

**`TRUNCATE` bypasses the row trigger.** The trigger is `FOR EACH ROW`, and
`TRUNCATE` is a table-level operation that fires no row triggers. The test
suite's own reset helper uses `TRUNCATE ... RESTART IDENTITY` for exactly this
reason, and the asymmetry is left visible rather than worked around: it is an
honest demonstration of where the boundary is. `RESTART IDENTITY` also resets the
sequence, so even the gap-detection property does not survive it.

**A persistence failure does not fail the request.** `persistEvaluation` logs the
failure with the request id and returns; the client still receives its answer.
This is a deliberate and uncomfortable choice. The alternative — failing the
request — means an unreachable audit table takes the entire evaluation path down.
Since v0.1 executes nothing, an evaluation that is not durably recorded has
changed nothing in the world, so refusing to answer buys no safety. What the code
must never do is look successful *while being invisible*, so the failure is loud
in the log and the store's health is what `/ready` reports.

**This is the first decision to revisit when an actuator exists.** At that point
an unrecorded action *has* changed something, and the request must fail instead.
The code says so at the point of the compromise, not only here.

**Ingest audit failures behave the same way**, via `recordAudit`: logged at ERROR
and surfaced through `/ready`, never converted into a client-visible 500 for an
operation that already completed safely.

**Reads leave no trace** (§2), so the trail cannot answer who *looked at* an
incident — only who acted on one.

**One shared credential** means the actor field is only as trustworthy as the
console's session handling. A compromise of the console's session secret is a
compromise of every attribution in the trail written after it.
