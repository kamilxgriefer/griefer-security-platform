# 0007 — Hash-chain the audit trail without an external anchor

**Status:** Accepted · v0.1 (M4, partial)

## Context

The v0.1 trail is tamper-RESISTANT. `audit.Sink` exposes `Append` and `List` and
nothing else, a PostgreSQL trigger raises on `UPDATE` and `DELETE`, and
database-assigned sequence numbers make a removed row a visible gap. All three
are enforced by tests.

None of them survives an adversary with DDL rights, who drops the trigger and
rewrites whatever they like. The test suite's own reset helper demonstrates the
boundary honestly, with `TRUNCATE`.

[SAFETY_MODEL.md](../SAFETY_MODEL.md) planned four things for M4:

1. `prev_hash` and `entry_hash` on every entry,
2. any removal or alteration breaks the chain,
3. periodic anchoring of the chain head to append-only external storage,
4. `GET /api/v1/audit/verify` returning the first broken link.

Points 1 and 4 are buildable inside this repository. Point 3 is not: it needs
append-only storage under a different authority than the database, which this
project does not have and cannot honestly fake. Point 2, as written, is false
without point 3 — an attacker who recomputes the chain forward breaks nothing.
The plan gets away with the phrasing because it walks it back three lines later.

That leaves a real decision, because the two halves are not equally available
and the weaker half is the one that is buildable today.

## Decision

**Ship the chain now, without the anchor, and make every artefact that reports
on it say what it is not.**

### The canonical form

One implementation, `internal/audit/chain.go`, called by both stores and by the
verifier. There is no second canonical form anywhere, because two would drift
and the drift would surface as a verifier reporting tampering on healthy rows.

The pre-image is domain-separated (`griefer.audit.chain.v1`) and every field is
length-prefixed with a big-endian `uint64`, so the concatenation is injective:
`actor="ab", action="c"` cannot collide with `actor="a", action="bc"`.

Two details are load-bearing, and both exist because the hash is computed from a
Go value on the way in and recomputed from what PostgreSQL returned on the way
out. Anywhere those two disagree, `verify` reports tampering on a row nobody
touched — which is worse than having no verifier, because it destroys the
signal the verifier exists to carry.

**Time.** `TIMESTAMPTZ` holds microseconds; `time.Time` holds nanoseconds. The
hash covers `Timestamp.UTC().UnixMicro()` as a decimal integer, so the
sub-microsecond part is outside the hash by construction rather than by luck.
`Recorder.Prepare` also truncates at the point of stamping, which closes a
divergence that predates this change: the memory store kept nanoseconds where
PostgreSQL kept microseconds, and the two stores' `List` returned different
timestamps for the same entry.

**Numbers.** `Details` is `map[string]any` and round-trips through `jsonb`,
which stores numbers as `NUMERIC` and re-renders them on output. Whether it
returns `1e+21` or `1000000000000000000000` is a server-side choice. Both sides
therefore decode with `json.Decoder` + `UseNumber` and normalise each number
from its decimal digits into a mantissa/exponent pair. No `float64` enters the
hash path, so `9007199254740993` survives exactly and any rendering of the same
`NUMERIC` normalises to the same bytes.

`Details` is encoded as type-tagged, length-prefixed binary rather than as JSON
text: there is then no escaping question, and the string `"42"` cannot collide
with the number `42`.

### Details is bounded, never refused

Oversized `Details` is replaced with a marker recording its size and key count.
It is not rejected, and no value in it is rejected.

This is not a stylistic preference. `Details` carries producer-influenced values,
`recordAudit` logs and returns on a `Prepare` failure, and `persistEvaluation`
logs and continues. Any rejection reachable from producer-influenced content is
a way for an attacker to suppress the audit entry describing their own event.
**Hashing must never become a denial primitive against the trail it protects.**

### The chain head is a row, and it is locked first

`audit_chain_head` holds one row: the chain id, the head sequence and the head
hash. Every transaction that writes audit takes `SELECT … FOR UPDATE` on it as
its **first** statement, before any other row lock, and holds it to commit.

Taking it first makes the lock order global, so there is no cycle to deadlock
on. Holding it to commit is what keeps `nextval` order and chain order the same
— and `ORDER BY sequence ASC` is what `verify` walks.

**`prev_hash` is read from the trail, not from the head row.** The head row is a
tripwire, and a tripwire must never be load-bearing. `audit_chain_head` is the
one table here with no append-only trigger, and the service's own role must be
able to update it. Were `prev_hash` derived from `head_hash`, one `UPDATE`
putting any already-claimed hash there would make every subsequent `INSERT`
collide with the fork index — and because `recordAudit` logs a failed audit
write and carries on, the entire trail would go silent with nothing anywhere
saying so. One statement, and GRIEFER stops recording. That is precisely the
kill switch this decision refuses elsewhere, and it would have been built in
under a different name.

So the head row does two jobs, and neither can stop a write. Its lock serialises
appends and exists when the trail is empty, which is when the genesis race would
otherwise happen. And it is the only thing inside this database that
distinguishes a truncated trail from an intact one, because a trail with its tail
removed is a shorter chain whose every link still checks out. A wrong value in it
is a discrepancy `verify` reports; the next append rewrites it.

It is the one table in this subsystem that is updated, and it deliberately
carries no append-only trigger.

### Pre-M4 rows are never backfilled

`chain_id`, `prev_hash`, `entry_hash` and `hash_version` are additive `ALTER`s.
Rows written before the migration keep `NULL` in all four and stay that way.

Backfilling would require an `UPDATE` against `audit_log`, which means dropping
the trigger — the DDL-rights bypass this decision exists to raise the cost of.
It would also prove nothing: hashes computed today over rows written last year
attest only that those rows hash to what they say today, and anyone with the
rights to run the backfill had the rights to alter the rows first.

`NULL` reads as **outside the chain**. Not as verified, and not as broken.
`verify` reports those rows in their own `unchained` section for that reason.

### A detected break does not stop GRIEFER writing

This is a deliberate departure from the platform's fail-closed stance, and it is
recorded here rather than left implicit.

GRIEFER fails closed on *actuation* (ADR 0003) because acting without a verified
permission could change the world. Refusing to *append* prevents nothing from
happening — it prevents the record of it. Three reasons, in order of weight:

1. **Fail-closed here protects nothing.** Suppressing evidence during the
   incident where evidence matters most inverts the safety property rather than
   applying it.
2. **It would hand an attacker a kill switch.** One `UPDATE` against one row
   would silence the whole trail, making the cheapest attack on GRIEFER "break
   the chain, then work in the dark".
3. **Staying open costs no evidence.** A break is a permanent, immutable fact in
   the table: later entries link to the actual head as normal and the chain does
   not heal. A *linkage* break — a removal or an insertion — is found by a full
   scan, so it is reported identically tomorrow and today. A *content* break — an
   entry edited without rehashing — is found only within the window `verify`
   recomputed, so as the trail grows it leaves the default answer and has to be
   swept for. That is a property of the check, not of the record: the altered row
   stays altered and stays findable.

Readiness is not degraded on a break either: `/ready` governs whether the process
takes traffic, and failing it would be fail-closed through the back door with a
restart storm attached.

Nothing else fails either, and getting there took a correction. An earlier draft
of this decision refused an append that would fork the chain, with a unique index
on `(chain_id, prev_hash)`, on the reasoning that refusing to corrupt is not the
same as refusing to record.

That reasoning was wrong about who gets refused. A unique index refuses the
*second* row to claim a predecessor, and by construction that is GRIEFER's:
whoever bypasses the head lock inserts first. Anyone holding `INSERT` could claim
the current tail's hash at any sequence number they chose, and every audit write
afterwards would be refused — silently, because `recordAudit` logs a failed write
and carries on. It was reason 2 of this section rebuilt under a different name.

The index is gone. What it was buying is already covered: a row inserted
mid-chain leaves the row after it linking to a predecessor that is no longer its
neighbour, and the linkage walk reports that as `link_mismatch`.

### `hash_version`

Recorded per row, and **inside the hash pre-image**. A verifier meeting a version
it does not implement reports that row **unverifiable**, never broken: "this
binary is older than that row" and "someone edited that row" must not look the
same to whoever was woken up.

Hashing it is what stops that mercy being abused. Left outside the pre-image it
would be a free-floating column that alone decides whether a row is recomputed at
all, so an edit could be paired with a version bump and the content check would
skip the row it should have caught. It cannot make an unknown version verifiable
— nothing can — but `unverifiable` is a distinct status that outranks
`consistent`, so the attempt is loud rather than silent, and the runbook says to
treat it as tampering until a downgrade explains it.

Linkage compares stored hashes to stored hashes and never recomputes, so it
still runs and still reports across a version it cannot verify content for.

### What `verify` returns

`200` in every case, including a broken chain — a `5xx` would be
indistinguishable from the endpoint being down. A `500` means only that the check
could not be run.

The response carries `status` rather than a `valid` boolean, and `empty` is a
distinct status from `consistent`, because an empty chain is a valid chain and a
truncated trail reporting "intact" is the most misleading thing this endpoint
could say. It also carries `store`, `externally_anchored: false` and a fixed
`attests` sentence on every response, so that a green result pasted into an
incident report carries its own qualification.

## Failure modes

**A false positive from the canonical form.** The failure this design fears
most: `verify` reporting tampering on healthy data trains its readers to ignore
it. Mitigated by a single implementation, by the round-trip conformance tests
that write awkward values through both stores and recompute after reading back,
and by both sides running the same decoder over the same JSON.

**Head-lock contention.** Every audit write against one database now serialises
on one row lock. Ingest audit and evaluation audit both take it. This is a real
throughput ceiling and it is accepted below.

**A stale head after a partial restore.** `head_sequence` ahead of the trail is
reported as a warning with `status: consistent`, because the surviving rows
really are consistent; what changed is that there are fewer of them. That
combination is the signature of truncation. A head *behind* the trail, or level
with it under a different hash, gets its own warning: neither can arise from
appending, since the head advances in the same transaction as the entry.

**A second writer.** An older binary, a second deployment or a `psql` session
writing entries without the head lock can insert a row mid-chain. The row after
it then links to a predecessor that is no longer its neighbour, which `verify`
reports as `link_mismatch`. Detection rather than prevention is deliberate: see
the fork discussion above for why preventing it cost more than it bought.

A second *GRIEFER* is not a second writer in this sense — both take the same head
row lock, so they are serialised against each other.

**Truncation to empty.** Not detectable from the chain, and the head row can be
rewritten by anyone who could do the truncating. Stated as a limit rather than
mitigated.

**Content verification is windowed, and linkage is not.** Linkage compares
stored hashes to stored hashes and is one ordered scan, so it covers the whole
chain on every call. Content has to decode `Details` and recompute a hash per
row in Go, so it covers at most `MaxPageSize` rows per request — newest first,
because that is what someone woken at three in the morning wants first.

An entry edited without rehashing more than a page ago is therefore not in the
default answer, and is found by paging outward with `offset`. The report says so
on its face: `content.scope` is `window` and it carries the sequence range it
actually examined, so a windowed result cannot be read as a whole-trail one.

Making the dear check as broad as the cheap one on every call would make the
cheap one useless, and the cheap one is the one that catches deletion.

## Consequences

Every audit write is now a transaction where the plain `Append` used to be one
autocommit `INSERT` on the pool, and every one of them serialises on
`audit_chain_head`. Audit is not a throughput path — the same argument ADR 0006
makes about evaluation — but this is a lower ceiling than before and it is the
price of the chain being a chain.

`PostgresStore.List` now decodes `Details` with `UseNumber`, so both stores
return `json.Number` where one returned `float64`. The JSON on the wire is
unchanged. This lands as its own commit ahead of the feature.

`storage.Store` gains `VerifyAuditChain`. `audit.Sink` does **not** — it keeps
exactly `Append` and `List`, because that pair is the guarantee the type system
carries, and `TestSinkExposesNoMutationMethods` fails on a third method of any
name.

The two test reset helpers must reset the head row rather than truncate it.
Truncating it would drop the seed row and reintroduce the genesis race.

Milestone M4 does not close. Identity integration and producer authentication
are its other half, and anchoring is not shipping at all.

## Alternatives considered

**Anchor now, to something.** Rejected. The candidates available are the
process log and the same host's filesystem, both writable by whoever writes the
database. An anchor that does not live under a different authority is a longer
sentence in a document, not evidence. Naming it as shipped would be the exact
defect commit `6207b63` exists to correct.

**A pure advisory lock, with no head row.** `pg_advisory_xact_lock` serialises
appends just as well and adds no writable table to a subsystem whose stated
property is that nothing in it is updatable. Rejected because tail truncation
would then be undetectable by anything inside the database. The asymmetry is
real and is the weakest point of this decision: someone who can rewrite the head
row can hide the truncation warning. They can also rewrite `audit_log`, so this
removes a tripwire rather than opening a door — but it is a tripwire against
accident and partial restore, not against an adversary, and it must not be
described as more.

**A unique index on `(chain_id, prev_hash)`.** Rejected, twice over. As the
primary mechanism it refuses the *entry* under contention, so a busy trail loses
records. As a backstop against a writer that bypasses the lock it is worse than
useless: it refuses the second row to claim a predecessor, which is always
GRIEFER's, so one `INSERT` from anyone holding that grant silences the trail
permanently. Insertion is detected by the linkage walk instead.

**Refusing values that cannot be canonicalised.** Rejected. See "never refused"
above: it hands an attacker who can influence `Details` a way to suppress the
entry describing their own event.

**Coercing `Details` at write time** so that the stored value is by construction
hashable — round-tripping through `float64` and marking the entry normalised.
Rejected. It never produces a false positive, which is the right instinct, but
it makes the trail record `9007199254740992` where the producer said `…93`. An
audit trail that alters the value it records to make its own hash convenient has
the trade backwards.

**Fail closed on a detected break.** Rejected, at length, above.

**A chain-start marker digesting every pre-chain row.** Rejected. It costs a
full-table read at startup, a new emitted action and a failure path in
`NewPostgresStore`, to produce an artefact whose value is easy to overstate: a
digest computed at time T over data an attacker rewrote at T-1 certifies the
forgery.
