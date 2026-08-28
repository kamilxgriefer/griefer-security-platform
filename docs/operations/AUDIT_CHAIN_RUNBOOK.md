# Audit chain — triage runbook

`GET /api/v1/audit/verify` reports whether the audit trail is internally
consistent. This is how to read its answer, and which of the answers is the one
that is not boring.

Administrator-only. A caller holding the service credential with no asserted
operator is admitted, which is the platform's own internals; the role gate binds
the console, not the credential.

## Read `status`, not the HTTP code

The endpoint answers `200` in every case, a broken chain included. A `5xx` for
"broken" would be indistinguishable from the endpoint being down. A `500` means
only that the check could not be run.

| `status` | Meaning |
|---|---|
| `consistent` | Every link checked out, and every entry in the content window hashes to what it says. |
| `broken` | Something does not add up. `linkage.break` or `content.break` names it. |
| `unchained` | Rows exist and none carries a hash. A deployment that has not yet written an entry through a current binary. |
| `unverifiable` | Rows carry a `hash_version` this build does not implement. The binary is older than the rows. |
| `empty` | No rows at all. **Not** folded into `consistent`: an empty chain is a valid chain, and this is what a wholesale `TRUNCATE` looks like. |

## Triage table

| Signal | Reading |
|---|---|
| `recorded_head.matches_trail: false`, head ahead, `status: consistent` | Truncate or restore. The surviving rows really are consistent; there are fewer of them. Compare `chain_id` against the last startup log line. |
| warning `recorded_head_disagrees_with_trail` | The head is behind the trail, or names a different hash. Appending cannot produce this — the head advances in the same transaction as the entry — so the row was written by something else. The chain itself does not depend on it and the next append rewrites it; what needs explaining is who wrote it. |
| `chain_id` differs from the one this deployment logged | A different database. Almost always a wrong DSN, not an attack. |
| `unchained.entries > 0`, all at the bottom (`unchained.last_sequence < linkage.first_sequence`) | Rows predating the chain migration. Expected once, benign, and they never gain hashes. |
| `linkage.break.kind: unchained_after_chain_start` | A hashless row **above** the chain start. A mixed-version deploy wrote through an old binary — or something that is not GRIEFER wrote to this table. |
| `status: unverifiable` | Rows carry a canonical-form version this build does not implement. If this deployment has NOT been downgraded, nothing here ever wrote that version — treat it as tampering until a downgrade explains it, because a version bump is how an edit gets a row skipped by the content check. If it has, deploy the newer build and re-verify. Linkage still ran either way: it compares stored hashes and never recomputes. |
| `linkage.break.kind: foreign_chain` | A chained row belonging to another chain. A restore that merged two trails is the boring explanation; a row inserted by someone holding only `INSERT` is the other. Not boring. |
| `linkage.break.kind: missing_predecessor` | The oldest surviving entry names a predecessor that is not there. **A prefix of the trail was removed.** This is not boring. |
| `linkage.break.kind: link_mismatch` | A row was removed from, or inserted into, the middle. Not boring. |
| `content.break.kind: content_mismatch`, linkage intact | A row was edited without rehashing. Not boring. |
| warning `content_check_covered_part_of_the_trail` | Normal on any trail longer than one page. It says `consistent` describes the rows that were recomputed, not all of them. Sweep if you have a reason to suspect an edit. |
| warning `content_check_covered_no_entries` | The offset is past the end of the trail. Nothing was recomputed at all, so `consistent` here rests on linkage alone. |
| `status: consistent`, everything matching | Nothing was detected. That is not the same as nothing having happened — see below. |

## Sweeping the whole trail for an edit

The two checks have different reach, and it matters when you are looking for a
specific thing.

**Linkage is full-scope.** Every call compares every chained row's `prev_hash`
against its predecessor's `entry_hash`. A removal or an insertion is caught on
the first call, and on every call after it.

**Content is windowed.** Recomputing an entry's hash from its own content means
decoding it in Go, so `verify` does that for at most 200 rows per request,
newest first. `content.from_sequence` and `content.to_sequence` say exactly which
rows were examined.

So an entry edited without rehashing, more than one page back, will not appear in
the default answer. To sweep:

```bash
# 200 rows at a time, oldest page last. Stop when content.entries comes back 0.
for off in $(seq 0 200 "$TRAIL_LENGTH"); do
  curl -sS "$API/api/v1/audit/verify?limit=200&offset=$off" \
    -H "Authorization: Bearer $INTERNAL_API_TOKEN" \
    -H "X-Griefer-Actor: $YOU" -H "X-Griefer-Actor-Role: admin" |
    jq -c '{offset: .content.from_sequence, to: .content.to_sequence, break: .content.break}'
done
```

`linkage.entries` on any response gives `TRAIL_LENGTH`. A sweep is worth doing
when linkage is clean but you have another reason to suspect an entry was
changed — linkage would not see that, because an edit that leaves the stored
hashes alone breaks no link.

## What a green result does not mean

`consistent` answers *is this trail internally consistent*, not *is this trail
the one GRIEFER wrote*.

The hash function and the canonical form are both in this repository and no
secret enters the computation. A role that can write to `audit_log` can alter an
entry, recompute every hash after it, and this endpoint will report the result
intact. `externally_anchored` is `false` on every response for that reason.

What raises the cost is that the attacker must rewrite the whole suffix rather
than one row. What would close it is anchoring — comparing `linkage.head_hash`
against a copy held under a different authority.

**Which is worth doing by hand today.** Record `linkage.head_hash` and
`linkage.head_sequence` somewhere outside this database — a ticket, a chat
message, a second system's log. A rewrite cannot reach a copy it does not
control, so one saved head is enough to catch one. This is thin, and it is thin
because it depends on someone having kept the copy.

## Queries behind each row

Run these against the database, not the API, when the endpoint itself is in
doubt.

```sql
-- the recorded head against the trail's actual head
SELECT h.chain_id, h.head_sequence, h.head_hash, h.updated_at,
       (SELECT max(sequence) FROM audit_log WHERE entry_hash IS NOT NULL) AS trail_head
FROM audit_chain_head h;

-- the first broken link, if any
--
-- The chain_id filter is not optional: it is what the endpoint applies, and
-- without it a row belonging to another chain is walked as though it were part
-- of this one, which reports a link mismatch where the endpoint reports
-- foreign_chain. Two different answers to the same question is worse than
-- either.
WITH chained AS (
    SELECT sequence, id, prev_hash,
           lag(entry_hash) OVER (ORDER BY sequence) AS expected
    FROM audit_log
    WHERE entry_hash IS NOT NULL
      AND chain_id = (SELECT chain_id FROM audit_chain_head)
)
SELECT sequence, id, prev_hash, expected
FROM chained
WHERE prev_hash IS DISTINCT FROM COALESCE(expected, '')
ORDER BY sequence LIMIT 1;

-- chained rows belonging to a chain that is not this database's
SELECT sequence, id, chain_id FROM audit_log
WHERE entry_hash IS NOT NULL
  AND chain_id IS DISTINCT FROM (SELECT chain_id FROM audit_chain_head)
ORDER BY sequence LIMIT 5;

-- rows outside the chain, and whether they sit below the chain start
SELECT count(*) FILTER (WHERE entry_hash IS NULL)  AS unchained,
       min(sequence) FILTER (WHERE entry_hash IS NOT NULL) AS chain_start,
       max(sequence) FILTER (WHERE entry_hash IS NULL)     AS last_unchained
FROM audit_log;

-- is the append-only trigger still there at all
SELECT tgname, tgenabled FROM pg_trigger
WHERE tgrelid = 'audit_log'::regclass AND NOT tgisinternal;
```

That last one matters: the chain is what detects an alteration *after* the fact,
and the trigger is what stops one being made through ordinary access. A missing
or disabled trigger is itself the finding, whatever the chain says.

## A break does not stop GRIEFER writing

Deliberately, and recorded in
[ADR 0007](../adr/0007-hash-chained-audit-without-anchor.md).

Refusing to append would prevent nothing from happening — it would prevent the
record of it, during the incident where the record matters most. It would also
hand an attacker a kill switch: one `UPDATE` against one row would silence the
whole trail.

A break is a permanent, immutable fact in the table: later entries link to the
actual head as normal and the chain does not heal. A linkage break is reported
identically tomorrow and today, because linkage is full-scope. A content break
stays in the table just as permanently, but finding it again once the trail has
grown means paging outward — see "Sweeping the whole trail for an edit" above. Readiness is not degraded either: `/ready`
governs whether the process takes traffic, and failing it would be fail-closed
through the back door with a restart storm attached.

Nothing else fails either. An earlier version of this design refused an append
that would fork the chain, via a unique index on `(chain_id, prev_hash)`. That
was removed: such an index refuses the *second* row to claim a predecessor, and
by construction that is GRIEFER's, because whoever bypasses the head lock
inserts first. One `INSERT` would have silenced the trail permanently. A row
inserted mid-chain is caught by the linkage walk instead, as `link_mismatch`.

## If the store is `memory`

`store` on every response names the implementation that answered. On the memory
store there is no trigger, nothing durable, and the chain was recomputed by the
process that wrote it — a `consistent` there says the process agrees with itself.
`GRIEFER_STORAGE_POSTGRES` defaults to `false`, so check this field before
reading the result as the PostgreSQL guarantee.
