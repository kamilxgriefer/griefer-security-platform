# 0006 — Evaluate policy outside the transaction, persist the decision inside one

**Status:** Accepted · v0.1 (M1.1)

## Context

Evaluating a proposed response action produces two things that must both survive
and must agree with each other: a `ResponseAction` recording what was decided,
and the audit entries recording why. Neither is meaningful alone.

Before M1.1 they were separate writes with nothing binding them. A crash, a
cancelled request or a failing insert between the two left one of two states,
both worse than no record at all:

- **Action without trail.** A response action nobody can account for. Read back
  later, it is indistinguishable from one that was never authorised.
- **Trail without action.** An audit entry naming a `response_action_id` that
  points at nothing.

Under ADR 0004 the platform ships no actuator, so the record *is* the product.
A defence platform whose only output is an explanation cannot have a lossy
explanation.

The obvious fix — one transaction spanning the whole request — puts a network
call to the Policy Kernel inside a database transaction. ADR 0002 made the
kernel a separate process on purpose; that separation is what this decision has
to work around rather than undo.

## Decision

Two phases, strictly ordered, with the boundary between them chosen so that no
external call ever happens with a transaction open.

**Phase 1 — decide. No transaction is held.** The incident is read, the policy
input is assembled and `Kernel.Evaluate` is called:

```go
// The Policy Kernel is consulted OUTSIDE any database transaction. Holding
// one open across a call to another service ties this database's connection
// budget to that service's latency, and a slow policy engine becomes a
// exhausted connection pool.
decision, kernelErr := s.kernel.Evaluate(ctx, input)
```

**Phase 2 — persist. One short transaction.** The action and every entry
describing its evaluation are written together:

```go
SaveActionWithAudit(ctx context.Context, action *incidents.ResponseAction, entries []*audit.Entry) error
```

This sits on `storage.Store` itself, not on an optional interface a caller
type-asserts for. An optional guarantee is one a caller silently loses against a
store that does not implement it, and *"the trail is complete unless you
configured the other backend"* is not a guarantee worth stating. A `nil` action
writes only the entries — the shape of an evaluation rejected before any action
exists, such as an unknown incident.

Three details make the guarantee hold rather than merely be claimed:

- **One writer per row shape.** A `querier` interface (`Exec`/`Query`/`QueryRow`)
  is satisfied by both the pool and a `pgx.Tx`, so `saveAction` and `appendAudit`
  have exactly one implementation each. The transactional and non-transactional
  paths cannot drift in what they write.
- **Rollback survives a dead context.** `inTx` rolls back on
  `context.WithoutCancel(ctx)`. When the failure *is* a cancelled or timed-out
  request, a rollback issued on that same context cannot be delivered and the
  transaction would be left for the server to reap.
- **Validation is not duplicated.** `Recorder.Prepare` validates and stamps an
  entry without writing it, and `Recorder.Record` is implemented in terms of it.
  An atomic caller therefore gets byte-identical validation to a plain one
  instead of a copy that drifts.

`MemoryStore` reaches the same guarantee differently: it validates every entry
and the action first, then performs all writes under a single lock. It is
exercised by the same suite as the PostgreSQL store, so it cannot quietly become
a more forgiving fake.

The transaction can only ever *add*. The `griefer_audit_log_is_append_only`
trigger (which predates M1.1) raises `restrict_violation` on `UPDATE` and
`DELETE`, and `audit.Sink` exposes only `Append` and `List` —
`TestSinkExposesNoMutationMethods` fails if anyone adds a third method.

Each entry carries `policy_revision` from `policies.Revision()`, a SHA-256 over
the embedded `.rego` sources. The decision and the identity of the rules that
produced it commit in the same transaction, so a trail read months later can
tell whether the rules have since changed.

## Failure modes

**Policy Kernel unreachable.** `Evaluate` returns both a fail-closed deny and an
error (ADR 0003). `evaluationResult` records `policy_unavailable`; the outcome is
`denied`; the client gets `200` with `X-Griefer-Policy-Degraded`. Nothing is
half-written, because no transaction had begun.

**Policy Kernel timeout.** Same shape, but `errors.Is(kernelErr,
context.DeadlineExceeded)` records `policy_timeout` instead. The distinction
exists because fail-closed makes both `OutcomeDenied` — the outcome alone cannot
separate a saturated kernel from an absent one, and the two are fixed
differently. Honest limit: this relies on the error chain preserving
`context.DeadlineExceeded`, so a proxy that converts a timeout into a `504` is
classified as *unavailable*, not as a timeout.

**Database unavailable.** `inTx` fails at `Begin`; nothing is written. The
failure is logged at error level with the request id, `/ready` reports storage
unhealthy via `Ping`, and the request still returns its decision — see below.

**Audit insert fails.** The error aborts `fn`, so the action row is rolled back
with it. There is no path that keeps the action and drops the entry: the
guarantee is symmetric by construction, not by care at each call site.

**Process dies between decision and persist.** The evaluation is lost entirely —
no action row, no entry, no response. This is the correct loss for v0.1 because
nothing was executed, so nothing in the world disagrees with the empty trail.
The client may retry. Note that each call mints a fresh `ResponseAction` id and
there is no idempotency key, so a retry is a new evaluation rather than a
resumption of the old one.

**A persistence failure does not currently fail the request.** This is deliberate
and uncomfortable. Failing the request would let an unreachable audit table take
the entire evaluation path down; and because v0.1 executes nothing, an evaluation
that was not durably recorded changed nothing, so refusing to answer buys no
safety. What it must never do is look successful while being invisible, hence the
error log carrying the request id and the store's health on `/ready`.

**This must change the moment any code path can reach an actuator.** Concretely:
when the `ModeSimulate` guard in `applyDecision` is relaxed so an `execute` action
can produce a real effect (M3). At that point an unrecorded action *has* changed
something, and the requirement inverts — the transaction must commit *before* the
actuator is called, and a commit failure must abort the action rather than be
logged. `audit.ResultPersistenceFailed` and `audit.OutcomePending` already exist
for that shape; neither has a production caller yet. They are reserved, not
wired, and this ADR is the note saying so.

## Consequences

**Good.** The trail and the record it describes cannot disagree — a property the
atomicity suite asserts in both directions, including that nothing at all is
written when any single entry is invalid. The database's connection budget is no
longer tied to the Policy Kernel's latency: a slow kernel produces slow responses
rather than an exhausted pool that also stops ingestion and incident reads. The
transaction touches two tables, contains no network call, and so has a hold time
bounded by local work.

**Bad.** The incident is read outside the transaction, so the decision is made
against a snapshot that nothing prevents changing before the commit. This is
tolerable only because v0.1 executes nothing and the entry records the risk score
and evidence categories the decision actually saw; it needs revisiting alongside
the actuator. A persistence failure is invisible to the client, which receives a
`200` describing a decision that is not durable. Every evaluation costs a
transaction, which is accepted — evaluation is not a throughput path.
`AppendAudit` is on the interface with no production caller today; every
evaluation path uses `SaveActionWithAudit`, passing `nil` where there is no
action. Stating that is better than hiding it.

## Alternatives considered

**One transaction spanning the policy call.** Rejected. It ties the lifetime of a
database connection to a remote service's p99. A hung kernel holds connections
open, enough concurrent evaluations exhaust the pool, and a policy outage becomes
a total database outage affecting paths with no interest in policy at all.
Fail-closed already means a degraded kernel refuses actions; it must not also
take the recorder down, because blinding the recorder is the more attacker-shaped
failure of the two.

**Audit written after the fact, best-effort.** Rejected — this is the pre-M1.1
behaviour, and it fails in the direction that matters. The action record survives
and its justification does not, which is precisely the state that cannot be
audited. The asymmetry is the point: best-effort for the *whole unit* is
defensible today, because a failure loses both halves together and leaves a
consistent absence. Best-effort for *one half* is not.

**A separate audit service.** Rejected for v0.1. Either it is called
synchronously — reintroducing exactly the remote-dependency coupling this ADR
exists to remove, and adding a second service whose outage stops recording — or
it is queued, which trades away the atomicity being bought. Neither can share a
transaction with the action, so the two-wrong-states problem returns by
construction. ADR 0001 applies: the boundary is not yet known. Worth reopening at
M4, when hash chaining and anchoring give the trail a reason to outlive this
database and to have more than one producer.
