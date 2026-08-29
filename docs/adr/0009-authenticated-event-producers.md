# 0009 — Authenticate event producers and bind them to a source identity

**Status:** Accepted · v0.1 (M4, partial)

## Context

[docs/THREAT_MODEL.md](../THREAT_MODEL.md) T1 lists "no producer authentication —
anyone who can reach the API can submit events" under *Not mitigated*. The
shared `INTERNAL_API_TOKEN` admits a connection; nothing after it says who is on
the other end.

That would be a smaller problem if the platform did not rest a safety property
on it. It does. The corroboration gate in
`policies/rego/griefer/response.rego` requires two distinct evidence categories
before automation, and until recently T1 described this as meaning "compromising
a single sensor is not enough to drive an action".

A live test against a running instance, holding only the service credential,
posted four schema-valid events for one identity — `user_signin`,
`session_created`, `role_assignment_changed`, `secret_accessed` — and produced
one incident with three evidence categories and a risk score of 40, at which
point the kernel returned `allow` for an isolation-class action.

That claim has since been corrected to say what the gate delivers: independent
*category*, never independent *source*. `TestSafetyContract_OneCredentialSatisfiesTheCorroborationGate`
states the residual in executable form.

The reason one credential reaches three categories is that nothing binds a
producer to what it claims to be. `source_type` and `source_name` are strings in
the request body, and every category-producing rule keys on fields the same
request asserts.

## Decision

**A producer presents its own credential, and that credential is entitled to
specific `(source_type, source_name)` pairs.**

Two headers on the ingest routes, alongside the existing service credential:

```
X-Griefer-Producer:     okta-prod
X-Griefer-Producer-Key: <at least 32 bytes of entropy>
```

Two headers rather than one so the name is a map lookup: a misconfiguration then
produces "producer okta-prod presented an unknown key" server-side rather than
"nothing matched". The key never reaches a log line or an audit entry; only the
name does.

### The entitlement is the control, not the credential

This is the part worth being precise about, because it is the part that closes
T1's headline hole. Authenticating a producer and then letting it claim any
`source_name` would leave the corroboration gate exactly as satisfiable from one
credential as it is today — the sender would simply need a credential first.

So a keyring entry carries an explicit list of permitted pairs, matched exactly,
with no wildcards. An event whose `source_type`/`source_name` is not in its
producer's list is refused after normalisation and before storage, and the
refusal is audited with the pair that was claimed.

### Three identities, ANDed, never ranked

GRIEFER now recognises three, and they answer different questions:

| Identity | Question | Carried by |
|---|---|---|
| Service credential | May this connection reach the API at all? | `Authorization: Bearer` |
| Producer credential | Which sensor is this telemetry from? | the two headers above |
| Operator assertion | Which person is behind this request? | `X-Griefer-Actor*` |

None may be inferred from another. In particular `httpx.Principal.Role` does not
gain a producer member, a producer never satisfies `RequireRole`, and
`RequireRole` continues to admit a request with no actor assertion even when a
producer is present — that admission is about operators and must not be read as
a role grant to a sensor.

### With no producers configured

Ingest behaves exactly as it does today, and startup warns. A deployment that
has not configured a keyring is not silently downgraded into thinking it has
one; it is told it has none. Once a keyring exists, an unauthenticated ingest is
refused — configuring one producer turns the boundary on for all of them, which
is the only rule that does not leave a bypass.

### Revocation is a restart

Configuration is read once at startup and there is no signal handler that
re-reads it, so revoking a key means redeploying. Rotation has a two-key window
— a previous digest is accepted alongside the current one — so a producer can be
moved without a synchronised deploy. Both sentences belong in the operator
documentation rather than in a footnote, because an operator who believes a key
is revoked when it is not is worse off than one who knows it is not.

## Failure modes

**A malformed producer assertion.** A name with no key is refused as malformed,
not treated as absent. Dropping a malformed assertion into the absent case is
how an absent case becomes a bypass, which is the rule `internal/httpx/principal.go`
already states for operator headers.

**Enumeration.** An unknown producer name is compared against a dummy digest
generated at startup, so it costs the same as a wrong key, and both return the
same refusal. The distinction survives only in the metric label and the log.

**A flood of refusals.** Producer verification sits inside the rate limiter, so
a token-holder cannot turn rejected ingest into unbounded writes to an
append-only trail.

**A producer that is honest but wrong.** Unaffected by any of this. Entitlement
binds where telemetry claims to come from, not whether what it says happened.

## Consequences

`security_events` gains a `producer_id` column, additive, NULL on existing rows.
Audit entries for ingest are attributed to `producer:<name>` rather than to
`system:griefer`, so the trail records which credential supplied each event.

Ingest gains two refusal reasons, `producer_missing` and
`producer_source_mismatch`, both audited.

**What this does NOT deliver, in the words the documentation must also use:
after this change the corroboration gate still counts independent CATEGORY and
never independent SOURCE.** The same four events from one *entitled* producer
still produce three categories and still reach `allow`. What changes is that the
sender needs a producer credential, can only claim the source pairs its operator
entitled it to, and is named in the trail. Anyone reading this diff and
concluding the gate is fixed has been misled.

Making the gate count distinct producers is a separate decision, with its own
record, because it changes what GRIEFER may do without a human.
[ADR 0005](0005-evidence-categories.md) anticipated it: it rejected distinct
sources *as the bar* — one source legitimately produces several kinds of
evidence — and said the idea was "worth revisiting as an additional dimension".
An additional dimension is what it will be, ANDed with categories rather than
replacing them, and 0005 stays Accepted.

Even then, "two distinct producer credentials" is not "two independent sensors".
Two keys in one CI secret store, on one collector host, or in one deployment
manifest count as two, and the Security Graph has no producer entity, so nothing
can place them behind a shared compromise. That distance is the sentence most
likely to be quietly overclaimed on its way into the threat model.

## Alternatives considered

**Mutual TLS, with the producer identity from a client certificate.** Rejected
for slice 1, on deployment reality and on one disqualifying property. Railway
has no secret-file mount, so a server key would arrive base64 in an environment
variable — the one place the configuration checks exist to keep key material out
of; the console reaches the API over `http://api.railway.internal:8080`, for
which no public CA will issue a certificate; and the container healthcheck dials
plain HTTP in an image with no shell. The disqualifier is that a rejected
handshake produces no access-log line, no counter, no audit entry and no request
id — a refusal with none of the four traces this platform records, which is the
defect `internal/httpx/middleware.go`'s access log exists to prevent.

**Per-request HMAC signing.** Genuinely stronger on message integrity and
freshness, and deferred rather than rejected. Two reasons. The entitlement table
does the source binding either way — a signature proves who sent the bytes, not
that the `source_name` inside them is true. And after-the-fact re-verification,
the property that would most justify the cost, is unexercisable today: the store
persists GRIEFER's own re-marshalling of a struct that normalisation has already
rewritten, so a MAC checked at ingest can never be checked again. Making it
re-checkable needs a raw-payload column, a digest column and a key history — a
larger change than the one that closes T1's headline hole. Named as v2.

**A `producer_keys` table, for revocation without a restart.** Rejected for
slice 1. It puts the credential store behind the same database whose
compromise the audit chain already treats as the worst case, and it adds a
startup dependency to a path that must work before the platform is ready. The
restart cost is stated plainly instead.
