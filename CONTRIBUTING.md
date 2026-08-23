# Contributing to GRIEFER

Thanks for looking. GRIEFER is an early research project, which means there is a
lot of room to shape it — and that a contribution changing a safety property
carries real weight.

---

## Before you start

Read [docs/SAFETY_MODEL.md](docs/SAFETY_MODEL.md). It is short, and it is the
part of the design that is hardest to put back once broken.

For anything touching response, policy or the trust boundary, also read
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Setting up

**Requires:** Go 1.25+, Node 22+, pnpm, and — for the full test suite —
`postgresql@17`, `nats-server` and `opa` on `PATH`.

```bash
git clone https://github.com/kamilxgriefer/griefer-security-platform.git
cd griefer-security-platform
make build          # backend and console
make check          # every quality gate
```

Run against real infrastructure:

```bash
make services-up    # native PostgreSQL, NATS and OPA
make test-live
make services-down
```

Or with Docker:

```bash
make up && make demo
```

## Quality gates

`make check` runs everything CI runs:

| Gate | Command |
|---|---|
| Go and Rego formatting | `make fmt-check` |
| `go vet` | `make vet` |
| Policy type-check and unit tests | `make policy-check` |
| Go tests, race detector on | `make test` |
| Console lint | `make lint-console` |
| TypeScript typecheck | `make typecheck` |
| Console tests | `make test-console` |

## What a good change looks like

### Every safety-relevant change needs a test that fails without it

Not "has test coverage". A test that **fails** if the change is reverted. If you
cannot write one, that is usually a sign the change is not testable, which is a
sign it is not verifiable.

Look at `tests/integration/security_test.go` for the style: one test per
guarantee, named after the failure it prevents.

### Comments explain why, not what

The code says what it does. A comment earns its place by explaining a decision
someone would otherwise undo:

```go
// A revoked token cannot be un-revoked. The user simply signs in again, so the
// action is low-harm — but it is genuinely not reversible, and saying otherwise
// would let it bypass the approval gate.
Reversible: false,
```

Not:

```go
// Set reversible to false
Reversible: false,
```

### Errors are actionable

An error message should tell someone what to do. `internal/config` is the
reference:

```
config: refusing to bind "0.0.0.0:8080". GRIEFER v0.1 has no authentication, so a
non-loopback bind exposes an unauthenticated ingest and audit API. Set
GRIEFER_ALLOW_PUBLIC_BIND=true only on an isolated lab network
```

### Client-facing errors never leak internals

No stack traces, no file paths, no driver errors, no SQL. The detail goes to the
log keyed by request id. This is tested.

### Bound everything attacker-influenced

Every field, list, map and query that an outside party can influence needs a
limit. "It would never be that large in practice" is not a limit.

## Changes that need an ADR

Open an [ADR](docs/adr/) *before* the pull request if the change:

- alters a guarantee in the safety model,
- changes a trust boundary,
- adds a dependency inside the trust boundary,
- changes the event schema non-additively,
- **adds an evidence category** — this changes what counts as independent
  corroboration, and therefore what GRIEFER may do without a human,
- or introduces a component that can reach an actuator.

An ADR that says "we accepted this cost for this reason" is fine. An undocumented
weakening is not.

## Adding a detection rule

Rules live in `detections/correlation/` as YAML and are evaluated against a closed
allowlist of event fields.

```yaml
- id: GRF-CORR-00NN
  title: Short, specific, readable in an incident list
  description: >-
    What it detects, and — importantly — when it fires legitimately. A rule with
    no stated false positives has not been thought about.
  category: authentication        # SAFETY-RELEVANT: see above
  severity: medium
  confidence: 0.55                # (0,1]. Be honest; this feeds risk scoring.
  techniques:
    - id: T1078
      name: Valid Accounts
      tactic: Initial Access
  match:
    event_type: [user_signin]
    conditions:
      - field: network.first_seen_for_actor
        equals: "true"
```

Checklist:

- [ ] The rule constrains at least one field. An unconstrained rule matches all
      telemetry and fails to load.
- [ ] Every referenced field is in the allowlist in `internal/correlation/rules.go`.
- [ ] The category is correct — it determines what GRIEFER may do automatically.
- [ ] Confidence reflects reality. Weak signals should say so.
- [ ] The description names the legitimate cases.
- [ ] A test asserts it fires when it should and does not when it should not.

## Adding a response action

Actions live in `internal/incidents/catalog.go` and are the only place their
safety properties may be defined.

- [ ] `Reversible: true` **only** if `RollbackAction` names something that
      genuinely undoes it. `TestCatalogInvariants` enforces this.
- [ ] `Destructive: true` if it irreversibly destroys data or access. Destructive
      actions are denied unconditionally and never recommended.
- [ ] `Isolation: true` if it cuts a subject off from the environment — these are
      held to the corroboration bar.
- [ ] Add policy tests in both `policies/rego/griefer/response_test.rego` and
      `internal/policy/policy_test.go`.
- [ ] Add a case to `TestSafetyContract_NothingIsEverExecuted`.

## Adding a fixture

- [ ] `"synthetic": true` — the loader refuses anything that does not declare it.
- [ ] `.example` domains, RFC 5737 addresses, a fictional cloud account.
- [ ] **No credential values.** A secret appears as an identifier, never a value.
      `TestFixturesContainNoRealIdentifiers` enforces this.
- [ ] Absolute timestamps — the replay path rebases them.

## Commits and pull requests

[Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add read-only Entra ID connector
fix: reject events with a future timestamp beyond the skew allowance
docs: explain the fail-closed contract
test: cover the isolation corroboration rule
security: bound the rate limiter's client map
```

The body should explain *why*. A reviewer can read the diff.

Pull requests: keep them focused, fill in the template, say what you tested and
how, and call out anything that weakens a guarantee.

## Getting a review

This is a small project. Review may take a few days. A change that is well tested,
well explained and narrowly scoped gets reviewed faster than one that is not.

For a security issue, do **not** open a pull request first — see
[SECURITY.md](SECURITY.md).

## Code of conduct

Be straightforward and be kind. Disagree about the work, not the person. Assume
the other party is trying to make this better.

## Licence

Contributions are licensed under Apache 2.0, matching the project.
