# 0008 — Anchor the audit chain in the operator's hands

**Status:** Accepted · v0.1 (M4, partial)

## Context

[ADR 0007](0007-hash-chained-audit-without-anchor.md) shipped the hash chain and
was explicit about what it left open:

> Periodic anchoring of the chain head to append-only external storage.
> Comparing the head against a value the database role cannot reach is what
> turns *consistent* into *unaltered*.

The reason it was left open has not changed. Anchoring needs storage under a
different authority than the database, and this project has none. The candidates
to hand — the process log, the same host's filesystem — are writable by whoever
writes the database, and 0007 rejected them for exactly that reason: an anchor
that does not live under a different authority is a longer sentence in a
document, not evidence.

What 0007 also recorded, in one line and then moved on from:

> One thing survives even that: an `entry_hash` recorded anywhere outside this
> database disagrees with the rewritten chain, so a single exported page is
> enough to catch it. That is a real property and a thin one, because it depends
> on someone having kept a copy.

`TestAConsistentlyForgedAppendIsNotDetected` and
`TestAnOperatorHeldAnchorCatchesAConsistentRewrite` both demonstrate the hole
that property addresses: an attacker who rewrites every entry and recomputes
every hash produces a trail that `GET /api/v1/audit/verify` reports as
consistent, because that endpoint has nothing to compare against except the
chain itself.

So the gap is not that the mechanism is unknown. It is that the mechanism was
left as a remark, and a remark is not a control.

## Decision

**The operator is the external authority.**

`GET /api/v1/audit/anchor` issues a commitment to the trail's current head —
chain id, sequence, `entry_hash`, the number of chained entries, and an
instruction saying to keep it elsewhere. `POST /api/v1/audit/anchor` takes one
back and compares it.

One anchor pins **every entry at or before its sequence**. `entry_hash` covers
`prev_hash`, which covers its predecessor's, back to the genesis, so altering
anything in that prefix changes the anchored hash. A single kept anchor is
therefore a commitment to the whole history behind it, not to one row.

This is the only check in the platform whose reference value did not come out of
the database being checked, which is precisely why it survives an attacker who
controls that database.

### What it does not do, said here rather than discovered later

It does not anchor automatically, and it does not anchor anywhere. If nobody
takes an anchor, or takes one and leaves it in a GRIEFER page, nothing is
gained: the response carries the instruction in a `keep` field because that is
where someone copying a JSON blob is looking, and a README is not.

It says nothing about entries written **after** the anchored sequence. Those are
covered by the chain's own consistency and by the next anchor.

It says nothing about entries that were never written. No hash can.

An anchor from the memory store commits to a trail that does not survive a
restart, and says so in the same field.

### Why an endpoint rather than a file the platform writes

A file GRIEFER writes lands wherever GRIEFER can write, which is where its
attacker can write. Handing the operator an artefact and telling them where it
must go moves the copy outside the blast radius in the only way available: by
making a person carry it.

That is a weaker control than a write to append-only storage under separate
authority, and it is not offered as an equal. It is offered because it is real,
buildable today, and strictly better than the remark it replaces.

## Failure modes

**Nobody takes an anchor.** The control does not exist. The runbook makes taking
one the last step of any incident touching the trail, and the startup log line
already carries a head hash for the same purpose.

**An anchor is kept inside GRIEFER.** Same outcome, and the `keep` field is the
mitigation.

**An anchor is checked against the wrong deployment.** Reported as
`foreign_chain` rather than as tampering, because the two must not look alike.

**A stale anchor after a legitimate restore.** A restore to a point before the
anchor reports `entry_missing`. That is correct — the trail really is shorter
than the anchor — and the runbook says to re-anchor after a restore.

**The anchor endpoint is used to fish for the trail's shape.** It reveals the
head hash and the entry count to an administrator, who can already read the
trail itself. The head hash is a commitment, not a secret: publishing it inside
the trust boundary makes detection more likely, not less.

## Consequences

`storage.Store` gains `IssueAuditAnchor` and `CheckAuditAnchor`, on the
interface for the reason `SaveActionWithAudit` gives: an integrity control a
caller silently loses depending on configuration is not a control worth stating.

`docs/SAFETY_MODEL.md` can now say something it could not: that a rewrite of the
whole suffix is detectable, **conditional on an anchor having been kept**. The
condition is load-bearing and travels with the claim everywhere it appears.

M4 still does not close. Automated anchoring to storage under separate authority
remains open, and so do the Entra ID connector and producer authentication.

## Alternatives considered

**Write the anchor to the process log.** Rejected in 0007 and still rejected.
The log is not append-only and usually shares a host with the database. It
raises cost; it does not create evidence. The startup line stays for its
operational value and is described as exactly that.

**Anchor to a second table with a different database role.** Rejected. It needs
a role separation the deployment does not have, and a second table in the same
cluster is the same authority wearing a hat.

**A signed anchor, with GRIEFER holding the key.** Rejected, and the reason is
worth writing down: a signature made with a key the platform holds is verifiable
by anyone and forgeable by whoever takes the key — which is the same adversary
who rewrites the table. It would make the artefact look stronger without making
it stronger, which is the failure mode this repository cares most about.

**Wait for real external anchoring.** Rejected. It has no owner and no date, and
in the meantime the platform's own tests demonstrate an undetectable rewrite.
Shipping the weak-but-real control and naming it accurately is better than
shipping nothing and naming it "planned".
