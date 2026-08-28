# Roadmap

Milestones, and what has to be true before each is done.

No dates. This is a research project developed in the open; committing to
timelines it cannot keep would be the first dishonest thing in the repository.

---

## Where things stand

| | Milestone | State |
|---|---|---|
| **M0** | Foundation | ✅ Complete |
| **M1** | Event ingestion and normalization | ✅ Complete |
| **M2** | Correlation and Security Graph | ◐ Correlation done; graph is in-memory |
| **M3** | Policy-governed response | ◐ Policy done; response is simulation-only |
| **M4** | Identity integration and tamper-evident audit | ◐ Chain shipped; anchoring and Entra ID open |
| **M5** | Endpoint telemetry | ○ |
| **M6** | Continuous defense validation | ○ |
| **M7** | AI-assisted investigation | ○ |
| **M8** | Production hardening | ○ |

---

## ✅ M0 — Foundation

Schema, storage, API, audit trail, container stack, CI.

- [x] Versioned event schema, enforced at the trust boundary
- [x] `Store` interface with in-memory and PostgreSQL implementations, both run
      against the same conformance suite
- [x] Append-only audit trail, by interface and by database trigger
- [x] REST API with OpenAPI 3.0.3, bounded errors, pagination, rate limiting
- [x] Prometheus metrics, structured logging, graceful shutdown
- [x] Compose stack with health checks, loopback-only ports
- [x] CI: format, vet, policy tests, Go tests, integration tests, lint,
      typecheck, console tests, container build, dependency/secret/image scans,
      SBOM, CodeQL

## ✅ M1 — Event ingestion and normalization

- [x] JSON Schema validation with `additionalProperties: false`
- [x] UTC normalization and a bounded ingest window
- [x] Control-plane label guard, with the attempt audited
- [x] Idempotent ingestion keyed on event id
- [x] Batch endpoint with independent per-item outcomes and multi-status
- [x] NATS JetStream publishing that degrades without blocking capture

## ◐ M2 — Correlation and Security Graph

**Done:** declarative rules over a closed field allowlist; identity-first
correlation with a time window; stateful threshold rules; monotonic saturating
risk scoring; bounded blast-radius traversal with real provenance.

**Remaining:**

- [ ] **Persist the graph.** Relational `entities` and `edges` tables replace the
      in-memory graph, which becomes a read-through cache.
- [ ] **Distribute correlation state.** Subject leases and threshold counters move
      into the database so a subject is correlated by exactly one instance.
- [ ] Time-partition `security_events`.
- [ ] Graph query API — paths between entities, not just neighbours.
- [ ] Reprocessing: replay stored events through a changed rule set.

**Done when:** two API instances correlate the same subject into one incident, and
the graph survives a restart.

## ◐ M3 — Policy-governed response

**Done:** Rego policy enforcing all seven safety rules; embedded and remote
kernels evaluating identical policy; fail-closed contract; simulated effects with
rollback plans; every decision audited.

**Remaining — this is where the platform first touches something real:**

- [ ] **Approval workflow (L2).** `requires_approval` becomes actionable, and the
      approver must be a different identity than the requester.
- [ ] **Actuator interface**, with the first implementation read-write against a
      lab tenant only.
- [ ] **Rollback execution.** Prior state recorded precisely enough to restore;
      rollback is itself policy-evaluated and audited; rollback of a reversible
      action never requires approval — undoing a mistake must be faster than
      making one.
- [ ] **Break-glass.** A single control that stops all automated response, works
      when the Policy Kernel is down, works from outside the console, and never
      times out back on by itself.
- [ ] **Action rate limits** per identity per hour, plus a global ceiling.
- [ ] **Delayed execution with veto (L3).**

**Done when:** an action executes against a lab tenant, is rolled back, and both
are in the audit trail with their reasoning — and break-glass stops it mid-flight.

## ◐ M4 — Identity integration and tamper-evident audit

In progress. Two things, because the first is what makes GRIEFER useful on real
data and the second is what makes its record trustworthy.

The chain and its verification endpoint have shipped; anchoring has not, and
without it the chain detects alteration without proving authenticity. The
milestone does not close on a half — see
[ADR 0007](adr/0007-hash-chained-audit-without-anchor.md).

**Read-only Microsoft Entra ID connector**

- [ ] Sign-in and audit log ingestion, normalised to the GRIEFER event schema
- [ ] Directory objects — users, groups, roles, service principals — into the
      graph as declared entities
- [ ] Role assignments and group membership as edges
- [ ] Read-only Graph API permissions, requested at minimum scope
- [ ] Delta-query incremental sync with a durable cursor
- [ ] Rate-limit and throttling handling that degrades rather than dropping data
- [ ] Connector health as a first-class signal, so a silent connector is visible
      (this is the mitigation for **T2 sensor suppression**)

**Tamper-evident audit**

- [x] `prev_hash` and `entry_hash` chaining over canonical serialisation
- [ ] Periodic chain-head anchoring to append-only external storage — chaining
      alone is insufficient, since whoever can rewrite the table can rewrite the
      chain
- [x] `GET /api/v1/audit/verify` returning the first broken link
- [ ] Producer authentication (mTLS or signed tokens), closing **T1**

**Done when:** GRIEFER correlates real Entra ID telemetry from a lab tenant, and
`audit/verify` detects a row deleted directly in PostgreSQL.

## ○ M5 — Endpoint telemetry

- [ ] Endpoint event normalization — process, file, network, persistence
- [ ] Native Sigma rule evaluation, replacing export-only publication
- [ ] Process-tree reconstruction in the graph
- [ ] Endpoint entities enriched with posture and compliance state
- [ ] Cross-domain correlation: identity evidence plus endpoint evidence in one
      incident

**Done when:** a scenario spanning identity and endpoint telemetry produces one
incident whose evidence categories come from both, and a Sigma rule in this
repository fires natively.

## ○ M6 — Continuous defense validation

The most ambitious milestone, and the one with the sharpest safety constraints.

- [ ] A validation catalog of safe, bounded, reversible checks
- [ ] Explicit authorisation scoping — a validation names its target and cannot
      run outside it
- [ ] Every validation is policy-evaluated, exactly like a response action
- [ ] Detection-coverage reporting: which techniques produce a finding, which do
      not
- [ ] Regression detection — a control that used to work and stopped
- [ ] OCSF conformance test suite and export mapping

**Safety constraints, non-negotiable:**

1. A validation targets only assets the operator has explicitly registered as
   in-scope.
2. Nothing destructive. Nothing persistent. Nothing that leaves state behind.
3. A validation is cancellable mid-run.
4. Every run is audited with its authorisation.
5. The catalog contains no technique that would be useful to an attacker beyond
   confirming whether a specific control fires.

**Done when:** a validation run reports coverage across a lab estate, is fully
audited, and a deliberately disabled control shows up as a regression.

## ○ M7 — AI-assisted investigation

- [ ] Evidence summarisation and incident narratives
- [ ] Hypothesis generation for a human to test
- [ ] Natural-language graph query
- [ ] Investigation-priority ranking

**Structural requirements, decided now:**

| Requirement | Why |
|---|---|
| AI is a **client** of the Policy Kernel, with the same standing as a human operator | So its proposals go through the same gate |
| It cannot approve its own proposals | Self-approval is not approval |
| It holds no credential an actuator accepts | Capability, not just permission |
| It cannot modify policy or audit entries | The record must outrank the reasoner |
| Its inputs are treated as attacker-influenced | Incident data contains attacker-controlled strings |
| Every AI-originated proposal is labelled as such in the audit trail | An analyst must know what suggested a thing |

Value-level prompt-injection defence must land **before** this milestone, not
alongside it. See **T5** in [THREAT_MODEL.md](THREAT_MODEL.md).

**Done when:** an AI-generated proposal is denied by policy, and the denial and the
proposal's origin are both in the audit trail.

## ○ M8 — Production hardening

Everything that makes the difference between "runs" and "may be relied upon".

- [ ] **Authentication** — OIDC, with sessions and MFA
- [ ] **RBAC** — at minimum viewer, analyst, responder, administrator
- [ ] **Dual control** for approvals
- [ ] Multi-tenancy with hard data isolation
- [ ] High availability and PostgreSQL failover
- [ ] Signed releases (Sigstore) and SLSA provenance
- [ ] Signed policy bundles verified at load
- [ ] Backup, restore and disaster-recovery runbooks
- [ ] Performance targets under sustained load
- [ ] **An independent security review**, by people who did not write this

**Done when:** the independent review completes and its findings are addressed or
publicly accepted as known limitations.

---

## What is deliberately not planned

Saying no is part of a roadmap.

- **Becoming a SIEM.** GRIEFER should not want to be the system of record for all
  logs. It reasons over security-relevant telemetry.
- **A managed SaaS offering.** Local-first is a commitment, not a stage.
- **Full autonomy (L5).** L4 — reversible, non-critical actions on corroborated
  evidence — is the destination. There is no plan to go further.
- **An agent fleet.** GRIEFER consumes telemetry from tools that already have
  agents. Adding another is a decade of endpoint engineering, not a feature.
- **Compliance reporting as a product.** Evidence GRIEFER produces may be useful
  for an audit; building for auditors would change what it optimises for.

## Contributing to a milestone

Pick an issue labelled with its milestone. Before starting anything in M3 or M6,
read [SAFETY_MODEL.md](SAFETY_MODEL.md) — those milestones give the platform the
ability to affect real systems, and a change that weakens a safety guarantee needs
an ADR, not just a passing build.
