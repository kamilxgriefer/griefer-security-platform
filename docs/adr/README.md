# Architecture decision records

Short documents recording a decision, its context, and what it costs.

An ADR is required when a change:

- alters a guarantee in [SAFETY_MODEL.md](../SAFETY_MODEL.md),
- changes a trust boundary,
- adds a dependency inside the trust boundary,
- changes the event schema in a way that is not purely additive,
- adds an evidence category (this changes what counts as independent
  corroboration, and therefore what GRIEFER may do without a human),
- or introduces a component that can reach an actuator.

Format: numbered, `NNNN-short-title.md`, with **Context**, **Decision**,
**Consequences** and **Alternatives considered**. Records are immutable — a
reversal is a new ADR that supersedes the old one.

| # | Title | Status |
|---|---|---|
| [0001](0001-modular-monolith.md) | Start as a modular monolith | Accepted |
| [0002](0002-policy-kernel-separation.md) | Separate the Policy Kernel from detection | Accepted |
| [0003](0003-fail-closed-policy.md) | Fail closed on policy unavailability | Accepted |
| [0004](0004-simulation-only-v01.md) | Ship v0.1 with no actuator | Accepted |
| [0005](0005-evidence-categories.md) | Gate automation on independent evidence categories | Accepted |
| [0006](0006-action-evaluation-audit-atomicity.md) | Evaluate policy outside the transaction, persist the decision inside one | Accepted |
