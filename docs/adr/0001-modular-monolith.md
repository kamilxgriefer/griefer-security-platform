# 0001 — Start as a modular monolith

**Status:** Accepted · v0.1

## Context

GRIEFER has components that look like natural services: ingestion, correlation,
graph, policy, API. The reflex for a platform of this shape is to start with
microservices, and the argument for it is real — independent scaling, independent
deployment, failure isolation.

The argument against is that we do not yet know where the boundaries are. The
correlation engine's interface to storage changed three times while building v0.1.
Each of those would have been a cross-service contract migration.

## Decision

Ship one Go binary with strict internal package boundaries.

Boundaries are enforced by Go's package system and by narrow interfaces:
`correlation.IncidentStore` declares the two methods correlation needs, rather
than importing the whole store. Dependencies point inward; nothing imports
`internal/api`.

`internal/bus` publishes to NATS JetStream even though nothing consumes it yet,
because that is the seam a future split would follow, and a seam that has never
carried traffic is a seam that does not work.

## Consequences

**Good.** One deployment, one log stream, one failure domain to reason about.
Refactoring across boundaries is a compiler error rather than a migration.
Integration tests run the real system in-process. A contributor can hold the whole
thing in their head.

**Bad.** Correlation cannot be scaled independently of ingestion. A panic in one
component could take down the process — mitigated by the recovery middleware and
the panic guard around correlation, but the blast radius is process-wide. Two
in-process pieces of state (the graph, correlation subject state) block horizontal
scaling until M2.

## Alternatives considered

**Microservices from day one.** Rejected: pays distributed-systems cost — network
failure modes, partial deploys, distributed tracing, schema versioning between
services — before the boundaries have settled.

**Modular monolith with in-process events only.** Rejected: no NATS means the
split path is theoretical.

**Serverless functions.** Rejected: correlation is stateful, and cold-start
latency on an ingestion path is the wrong trade.
