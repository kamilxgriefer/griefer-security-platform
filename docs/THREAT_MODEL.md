# Threat model

This document is about attacks against **GRIEFER itself**, not about the attacks
GRIEFER detects.

A defence platform is a high-value target twice over: it holds a map of the
environment, and — as it gains autonomy — it holds the ability to act on that
environment. A compromised GRIEFER is worse than no GRIEFER, because it is a
trusted map that lies and a trusted hand that acts.

**Scope note.** v0.1 has no authentication and no actuator. Several threats below
are therefore *not currently mitigated* and are marked as such. Saying so is the
point of the document.

---

## Assets, ranked

| # | Asset | Why an attacker wants it |
|---|---|---|
| 1 | **The Policy Kernel's authority** | Whoever controls policy controls whether anything may be done — and, later, what is done to real accounts and hosts |
| 2 | **The audit trail** | Erasing the record turns an attack into an unexplained anomaly |
| 3 | **The Security Graph** | A pre-built map of identities, secrets and what they unlock: reconnaissance, already done |
| 4 | **Telemetry integrity** | If evidence can be forged or suppressed, every conclusion downstream is attacker-chosen |
| 5 | **Availability** | A blind defender is the cheapest defender to beat |

## Adversaries

| Adversary | Capability | Primary goal |
|---|---|---|
| **External attacker, pre-foothold** | Network reach to exposed surfaces | Reconnaissance; suppress detection |
| **Compromised producer** | Full control of one sensor or its credentials | Forge or suppress evidence; drive GRIEFER to act wrongly |
| **Compromised operator account** | Console and API access | Disable detection; erase the trail; weaponise response |
| **Malicious insider** | Legitimate access, knows the design | Quiet blind spots; deniable actions |
| **Supply-chain attacker** | Can influence a dependency or a build | Code execution inside the trust boundary |
| **Curious/careless user** | Console access, no ill intent | Accidental containment of a colleague |

---

## T1 — Forged telemetry

**An attacker submits fabricated events** to hide activity, manufacture an
incident against a colleague, or steer GRIEFER's conclusions.

*Mitigated in v0.1*

- Schema validation with `additionalProperties: false` — a forged event cannot
  carry a field GRIEFER did not design for.
- The timestamp window rejects events more than 5 minutes in the future or older
  than 30 days: neither "keep this incident permanently fresh" nor "replay stale
  telemetry into a live incident" works.
- `received_at` is server-owned and overwrites anything a producer supplies.
- Automated response requires **two independent evidence categories**, so
  compromising a single sensor is not enough to drive an action.
- Per-client rate limiting bounds how much a producer can inject.

*Not mitigated*

- **No producer authentication.** Anyone who can reach the API can submit events.
  → M4 (mTLS or signed producer tokens).
- **No cross-source verification.** GRIEFER cannot yet ask a second source
  whether a claimed sign-in really happened.

*Residual.* An attacker with network reach to the API can inject events today.
The corroboration requirement limits the damage to *noise and misdirection*
rather than *automated action against a target of their choosing* — which is why
that rule exists before authentication does.

## T2 — Sensor suppression

**An attacker silences a sensor** so their activity is never reported. This is
the most effective attack on any detection platform and the hardest to catch,
because absence looks like quiet.

*Mitigated in v0.1*

- Ingestion survives correlation and bus failure, so partial degradation cannot be
  used to make the recorder drop events.
- `griefer_events_ingested_total{category}` makes a source going quiet visible to
  anyone alerting on it.

*Not mitigated*

- **No expected-source inventory.** GRIEFER does not know which producers *should*
  be reporting, so it cannot notice one stopping. → M4/M5: register producers with
  an expected heartbeat interval and alert on silence.
- **No sensor health telemetry.**

*Residual.* Significant, and honestly the largest detection gap in v0.1.

## T3 — Compromised operator account

**An attacker with console or API access** disables detection, closes incidents,
or drives response against legitimate users.

*Mitigated in v0.1*

- No response action can be executed — there is no actuator.
- Destructive actions are denied unconditionally, to everyone, in every mode. An
  operator account cannot approve `purge_audit_records`.
- The audit trail is append-only by interface and by database trigger.
- Every evaluation is audited with its requester.

*Not mitigated*

- **No authentication, no RBAC, no MFA, no session management.** → M8.
- **No approval workflow yet.** `requires_approval` is a terminal state in v0.1;
  there is no path for a human to grant approval, which is safe but incomplete.
  When that path is built it must require a *different* identity than the
  requester — dual control is the whole point.

*Residual.* Total, within the API's reach. This is why the API refuses to bind a
non-loopback interface without an explicit override, and why the override logs a
warning every start.

## T4 — Policy tampering

**An attacker modifies the Rego** to permit what should be denied. This is the
highest-value attack in the design: policy *is* the safety property.

*Mitigated in v0.1*

- Policy is embedded in the binary at build time for the embedded kernel — changing
  it requires changing the build.
- The Compose stack mounts `policies/rego` **read-only** into OPA. GRIEFER cannot
  write to its own policy.
- `default effect := "deny"`, and malformed input is denied explicitly rather than
  producing an undefined decision.
- Every decision records `policy_package` and `policy_version`, so a swap is
  visible in the audit trail afterwards.
- `rawDecision.toDecision` rejects a decision with an unrecognised effect, an
  `allow` that disagrees with its effect, or no reasons — a subverted policy
  returning nonsense produces a denial, not permission.
- `opa test` runs 25 policy unit tests in CI, and the Go suite independently
  asserts the same rules through the kernel.

*Not mitigated*

- **No signature verification** on the policy bundle. → M8: signed bundles, verified
  at load.
- **No runtime alerting on policy version change.** Currently visible only by
  reading audit entries.

*Residual.* Requires build-system or host access. Detectable after the fact, not
prevented at load.

## T5 — Prompt injection

**Attacker-controlled text inside telemetry reaches a language model** and is
treated as instruction rather than data.

There is no AI in v0.1. The defence exists anyway, because a boundary is far
easier to hold if it was never crossed.

*Mitigated in v0.1*

- Label keys naming a control-plane concept (`action`, `command`, `policy`,
  `execute`, `role`, anything under `griefer.`) are stripped at ingest, and the
  attempt is audited as `event.label_quarantined` — the attempt becomes a signal.
- Unknown top-level fields are rejected by schema, so a `"response_action"` object
  never enters the system at all.
- Action properties come from the server-side catalog. Even an unstripped label
  could not select an action, because nothing reads an action type from event data.
- Detection rules may *compare* a label but can never derive severity, category or
  an action from one.

*Structural commitment for M7*

An AI component will be a **client** of the Policy Kernel, subject to the same
rules as a human operator, and will hold no credential an actuator accepts. It
will not be able to approve its own proposals, alter policy, or write audit
entries.

*Residual.* Value-level injection ("ignore previous instructions…" inside a free
text field) is not stripped, because in v0.1 nothing interprets it. This must be
revisited before M7, not after.

## T6 — Data poisoning

**Slow, deliberate feeding of benign-looking events** to shift GRIEFER's sense of
normal, so that genuinely anomalous activity later reads as expected.

*Mitigated in v0.1*

- Risk scoring uses **no learned baseline**. It is a pure function of the current
  incident's evidence — there is nothing to poison over time.
- Within-category repetition is capped at +50%, so flooding one signal type
  cannot inflate a score past a genuinely corroborated incident. This is asserted
  by `TestAssessDoesNotManufactureConfidenceFromRepetition`.
- Findings deduplicate by rule, so a rule firing a thousand times is one finding
  with more evidence, not a thousand.
- The asset inventory is operator-supplied and not learned from telemetry.

*Not mitigated*

- **The graph does learn from telemetry.** An attacker can create entities and
  relationships by generating events, which could inflate a future blast-radius
  estimate. Bounded by `maxEdgeEvidence` and the 3-hop traversal limit, but real.
- **`first_seen_for_actor` is a producer assertion** GRIEFER cannot verify.

*Residual.* Moderate. The absence of learned baselines removes the classic
poisoning surface; the graph remains partly attacker-influenceable. Verifying
graph facts against the inventory rather than trusting telemetry is → M2.

## T7 — Audit destruction

**An attacker erases the record** to make an incident unexplainable.

*Partially mitigated in v0.1*

- `audit.Sink` exposes only `Append` and `List`. There is no update and no delete
  in the type system, and `TestSinkExposesNoMutationMethods` fails if anyone adds
  one.
- A PostgreSQL trigger raises on `UPDATE` and `DELETE` against `audit_log`.
  `TestPostgresAuditLogRejectsUpdateAndDelete` proves it against a real database.
- Sequence numbers are assigned by the database, so a removed row leaves a visible
  gap.
- `purge_audit_records` exists in the catalog *specifically* so that the deny path
  is exercised by a real request. It is denied unconditionally.

- Entries are hash-chained: each carries `prev_hash` and `entry_hash` over its
  canonical serialisation, so an alteration or a removal that got past the
  trigger is visible. `GET /api/v1/audit/verify` reports the first break. Its
  linkage check is full-scope on every call; its content check — the one that
  catches an edit that leaves the stored hashes alone — covers a bounded
  window, and the response warns when that was less than the whole chain.
  Detection is proven against a real database by `TestEditingAnEntryIsDetected`,
  `TestDeletingAnEntryFromTheMiddleIsDetected` and
  `TestDeletingThePrefixOfTheTrailIsDetected`.

*Not mitigated*

- **The chain is stored beside the entries.** No secret enters the computation,
  so a role that can rewrite `audit_log` can recompute every hash after an edit
  and `verify` will report the result intact. This raises the cost of the attack
  from one statement to a full-table rewrite; it does not make it detectable.
- **Truncation to empty.** An empty chain is a valid chain. `verify` reports
  `empty` rather than `consistent`, which is a distinction an operator can act on
  and not a mitigation.
- **Tail truncation.** A trail with its tail removed is a shorter chain whose
  every link checks out. `audit_chain_head` catches it, and whoever deleted the
  rows can rewrite that row too — so it is a tripwire against accident and
  partial restore, not against an adversary.
- **No off-host replication.**

*Planned — M4.* Periodic anchoring of the chain head to append-only external
storage, under a different authority than the database. Comparing the head
against a value the database role cannot reach is what turns *consistent* into
*unaltered*.

*Residual.* Reduced but still significant with database admin access: an
adversary who rewrites the whole suffix is undetectable from inside this
database. Any `entry_hash` kept outside it would disagree with the rewrite,
which is a real property and one that depends on someone having kept a copy.

## T8 — Malicious update

**A backdoored GRIEFER release**, or a build produced from tampered source.

*Mitigated in v0.1*

- Reproducible builds: `-trimpath`, no CGO, pinned base images.
- Distroless non-root runtime — no shell, no package manager, nothing to pivot into.
- Container filesystems are read-only with all capabilities dropped.
- CI runs with minimal GitHub Actions permissions and no `write-all`.
- SBOM generated per build.
- Every dependency is pinned by `go.sum` and `pnpm-lock.yaml`.
- npm build scripts are **opt-out by default** (`pnpm-workspace.yaml`): a
  postinstall script is the shortest path from a compromised dependency to a
  compromised developer machine, so each one is an explicit decision.

*Not mitigated*

- **No release signing, no provenance attestation.** → M8: Sigstore/cosign and
  SLSA provenance.
- **No reproducible-build verification** by a third party.

*Residual.* Standard for a project at this stage, and stated rather than implied.

## T9 — Dependency compromise

**A compromised upstream package** executes inside GRIEFER's trust boundary.

*Mitigated in v0.1*

- Small direct dependency surface: five Go modules, three npm runtime packages.
- Lockfiles pin every transitive version by hash.
- `govulncheck` and CodeQL run in CI.
- Dependabot proposes updates weekly, grouped so a security bump is not lost in
  noise.
- `trivy` scans the filesystem and the built images.

*Not mitigated*

- **No vendoring**, so builds depend on module proxy availability and integrity.
- **No allowlist** of permitted licences or maintainer identities.

*Residual.* The OPA Go library is the largest single dependency and pulls the
widest transitive tree. That is a deliberate trade: a hand-written policy
evaluator would be a smaller dependency and a much larger correctness risk in the
one component where being wrong is unacceptable.

## T10 — Denial of service

**Resource exhaustion** to blind the defender.

*Mitigated in v0.1*

| Vector | Bound |
|---|---|
| Large body | `GRIEFER_MAX_REQUEST_BYTES`, enforced by the server, not by trusting `Content-Length` |
| Many tiny events in one body | `GRIEFER_MAX_BATCH_EVENTS`, checked before any event is processed |
| Request flood | Token bucket per client address; `X-Forwarded-For` is deliberately ignored so rotating a header cannot reset a bucket |
| Rate-limiter memory | Tracked clients capped at 10 000 with TTL eviction |
| Unbounded queries | `limit` clamped to 200 |
| Graph growth | 50 event ids per edge; 3-hop traversal limit |
| Incident growth | 100 event ids per finding; 200 evidence entries per incident |
| Validation error amplification | Field errors capped at 20 |
| Slow clients | Read, write and idle timeouts on every connection |
| In-memory store growth | Bounded retention with FIFO eviction |
| Policy evaluation | Bounded by `GRIEFER_OPA_TIMEOUT`; a slow kernel fails closed |

*Not mitigated*

- **No global concurrency limit** beyond per-client rate limiting.
- **PostgreSQL is a single point of failure.** → M8.

*Residual.* An attacker with many source addresses can still generate load.

## T11 — Weaponised response

**Turning GRIEFER's own response capability against legitimate users** — the
attack that makes automated response dangerous in the first place. Trigger a
detection against a target, let the platform lock them out.

This is the threat the entire safe-automation model exists to address.

*Mitigated in v0.1*

- **No actuator exists.** Nothing can be executed.
- Automated response requires **two independent evidence categories**, so one
  forged signal is not enough.
- Isolation-class actions have an explicit rule against being triggered by a
  single weak signal.
- A risk floor of 40 blocks automation on low-confidence incidents.
- Irreversible actions require a human.
- Critical-asset actions require a human.
- Destructive actions are denied outright.
- Every decision is auditable, so a wrongful containment is at least explicable
  and reversible.

*Planned*

- **M3:** rate limits on actions per identity per hour, and a global kill switch.
- **M4:** protected-identity classes (break-glass accounts, executives, incident
  responders) that can never be automatically contained.
- **M8:** dual control — the approver must be a different identity than the
  requester.

*Residual.* None in v0.1, because there is nothing to weaponise. Every mitigation
above must be verified again before any actuator ships.

---

## Trust assumptions

Stated explicitly, because an unstated assumption is an unexamined one.

1. The **host** running GRIEFER is not compromised.
2. The **Rego policy** in the repository is what the operator intends. Review it.
3. The **asset inventory** is accurate. Criticality drives approval requirements;
   a mislabelled asset weakens a control.
4. **Detection rules** are reviewed. They cannot escape their field allowlist, but
   a wrong rule produces wrong findings.
5. The **network between producers and GRIEFER** is trusted, because v0.1 has no
   producer authentication. This assumption is unreasonable outside a lab, which
   is why the API refuses to bind a public interface.
6. **Operators are authorised.** There is no authentication in v0.1.

Assumptions 5 and 6 are the reason this is a prototype rather than a product.

## Testing the model

Threats without tests are wishes. Where each is exercised:

| Threat | Test |
|---|---|
| T1 forged telemetry | `TestNormalizeRejectsTimestampsOutsideTheIngestWindow`, `TestValidatorRejectsMalformedEvents` |
| T2 sensor suppression | `TestTelemetryCaptureSurvivesADegradedCorrelationEngine` |
| T3 operator compromise | `TestSafetyContract_DestructiveActionsAreAlwaysDenied` |
| T4 policy tampering | `TestRemoteKernelFailsClosed`, `TestEmbeddedKernelFailsClosedOnMalformedInput`, `opa test` |
| T5 prompt injection | `TestSafetyContract_TelemetryCannotInjectCommands`, `TestSanitizeQuarantinesControlPlaneLabels` |
| T6 data poisoning | `TestAssessDoesNotManufactureConfidenceFromRepetition`, `TestEngineDeduplicatesRepeatedRuleFirings` |
| T7 audit destruction | `TestSinkExposesNoMutationMethods`, `TestPostgresAuditLogRejectsUpdateAndDelete` |
| T10 denial of service | `TestSafetyContract_OversizedPayloadsAreRejected`, `TestRateLimiter*`, `TestMemoryStoreBoundsEventRetention` |
| T11 weaponised response | The whole `TestSafetyContract_*` suite |

## Review status

This model was written by the same people who wrote the code, which is exactly
the wrong way to threat-model. An independent review is tracked as an issue and
is a prerequisite for anything beyond a lab deployment.
