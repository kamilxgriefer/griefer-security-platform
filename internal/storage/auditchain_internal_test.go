package storage

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
)

// These tests do their damage INSIDE a transaction that is always rolled back.
//
// That matters for two reasons. Disabling the append-only trigger takes an
// ACCESS EXCLUSIVE lock on audit_log, so no other session can observe the
// half-wrecked trail; and nothing is ever committed, so a package sharing
// GRIEFER_TEST_POSTGRES_DSN cannot inherit a corrupted chain from a test run.
// The verifier runs against the transaction rather than the pool, which is why
// it takes a querier.

func chainTestStore(t *testing.T) (*PostgresStore, context.Context) {
	t.Helper()
	dsn := os.Getenv("GRIEFER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GRIEFER_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	store, err := NewPostgresStore(ctx, PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := store.pool.Exec(ctx,
		`TRUNCATE security_events, incidents, response_actions, audit_log RESTART IDENTITY`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if _, err := store.pool.Exec(ctx,
		`UPDATE audit_chain_head SET head_sequence = 0, head_hash = NULL, updated_at = now()`); err != nil {
		t.Fatalf("reset chain head: %v", err)
	}
	return store, ctx
}

func seedChain(t *testing.T, store *PostgresStore, ctx context.Context, n int) []*audit.Entry {
	t.Helper()
	out := make([]*audit.Entry, 0, n)
	for i := 1; i <= n; i++ {
		e := &audit.Entry{
			ID:          fmt.Sprintf("aud-tamper-%03d", i),
			Timestamp:   time.Date(2026, 8, 27, 10, 0, i, 0, time.UTC),
			Actor:       "user:ana",
			ActorRole:   "admin",
			Action:      audit.ActionPolicyEvaluated,
			SubjectType: audit.SubjectAction,
			SubjectID:   fmt.Sprintf("act-%03d", i),
			Outcome:     audit.OutcomeSuccess,
			Reason:      "allowed by policy",
			Details:     map[string]any{"i": i},
		}
		if err := store.Append(ctx, e); err != nil {
			t.Fatalf("Append(%d) error = %v", i, err)
		}
		out = append(out, e)
	}
	return out
}

// wreck runs fn inside a transaction with the append-only trigger disabled,
// verifies within that same transaction, and always rolls back.
func wreck(t *testing.T, store *PostgresStore, ctx context.Context, fn func(pgx.Tx)) *AuditChainReport {
	t.Helper()
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if _, err := tx.Exec(ctx, `ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only`); err != nil {
		t.Skipf("cannot disable the append-only trigger as this role, so tampering cannot be simulated: %v", err)
	}
	fn(tx)
	report, err := verifyAuditChain(ctx, tx, store.Kind(), 0, 0)
	if err != nil {
		t.Fatalf("verifyAuditChain() error = %v", err)
	}
	return report
}

// TestEditingAnEntryIsDetected. The trigger refuses this in production; the
// point of the chain is that it is still visible to someone who got past it.
func TestEditingAnEntryIsDetected(t *testing.T) {
	store, ctx := chainTestStore(t)
	seedChain(t, store, ctx, 4)

	report := wreck(t, store, ctx, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx,
			`UPDATE audit_log SET outcome = $1 WHERE id = $2`, audit.OutcomeDenied, "aud-tamper-002"); err != nil {
			t.Fatalf("tamper: %v", err)
		}
	})
	if report.Status != ChainBroken {
		t.Fatalf("Status = %q, want %q after an entry was edited", report.Status, ChainBroken)
	}
	if report.Content.Break == nil || report.Content.Break.Kind != BreakContentMismatch {
		t.Fatalf("Content.Break = %+v, want kind %q", report.Content.Break, BreakContentMismatch)
	}
	if report.Content.Break.ID != "aud-tamper-002" {
		t.Errorf("break names %q, want the entry that was edited", report.Content.Break.ID)
	}
	// Linkage is untouched: the edit did not move any stored hash. That the two
	// checks answer differently is the point of separating them.
	if report.Linkage.Break != nil {
		t.Errorf("Linkage.Break = %+v; an edit without rehashing should not break linkage", report.Linkage.Break)
	}
}

// TestDeletingAnEntryFromTheMiddleIsDetected.
func TestDeletingAnEntryFromTheMiddleIsDetected(t *testing.T) {
	store, ctx := chainTestStore(t)
	seedChain(t, store, ctx, 5)

	report := wreck(t, store, ctx, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `DELETE FROM audit_log WHERE id = $1`, "aud-tamper-003"); err != nil {
			t.Fatalf("tamper: %v", err)
		}
	})
	if report.Status != ChainBroken {
		t.Fatalf("Status = %q, want %q after an entry was deleted", report.Status, ChainBroken)
	}
	if report.Linkage.Break == nil || report.Linkage.Break.Kind != BreakLinkMismatch {
		t.Fatalf("Linkage.Break = %+v, want kind %q", report.Linkage.Break, BreakLinkMismatch)
	}
	if report.Linkage.Break.ID != "aud-tamper-004" {
		t.Errorf("break names %q; the survivor whose predecessor vanished is aud-tamper-004",
			report.Linkage.Break.ID)
	}
}

// TestDeletingThePrefixOfTheTrailIsDetected. The oldest surviving entry names a
// predecessor that is not there, which nothing but the chain would show.
func TestDeletingThePrefixOfTheTrailIsDetected(t *testing.T) {
	store, ctx := chainTestStore(t)
	seedChain(t, store, ctx, 5)

	report := wreck(t, store, ctx, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `DELETE FROM audit_log WHERE sequence <= 2`); err != nil {
			t.Fatalf("tamper: %v", err)
		}
	})
	if report.Status != ChainBroken {
		t.Fatalf("Status = %q, want %q after the trail's prefix was deleted", report.Status, ChainBroken)
	}
	if report.Linkage.Break == nil || report.Linkage.Break.Kind != BreakMissingPredecessor {
		t.Fatalf("Linkage.Break = %+v, want kind %q", report.Linkage.Break, BreakMissingPredecessor)
	}
}

// TestTruncatingTheTailLeavesAConsistentChainAndAnAheadHead.
//
// This is the limit the safety model states rather than mitigates: a trail with
// its tail removed is a shorter chain whose every link still checks out. The
// recorded head is the only thing inside the database that notices, and only
// because whoever deleted the rows did not also rewrite it.
func TestTruncatingTheTailLeavesAConsistentChainAndAnAheadHead(t *testing.T) {
	store, ctx := chainTestStore(t)
	seedChain(t, store, ctx, 5)

	report := wreck(t, store, ctx, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `DELETE FROM audit_log WHERE sequence >= 4`); err != nil {
			t.Fatalf("tamper: %v", err)
		}
	})
	if report.Status != ChainConsistent {
		t.Fatalf("Status = %q, want %q -- the surviving rows really are consistent; "+
			"what changed is that there are fewer of them", report.Status, ChainConsistent)
	}
	if report.RecordedHead == nil || report.RecordedHead.MatchesTrail {
		t.Fatalf("RecordedHead = %+v, want MatchesTrail false", report.RecordedHead)
	}
	if !hasWarning(report, WarnRecordedHeadAhead) {
		t.Errorf("Warnings = %v, want %q -- without it a truncated trail reports clean",
			report.Warnings, WarnRecordedHeadAhead)
	}
}

// TestAnUnchainedRowAboveTheChainStartIsDetected. Every row a current binary
// writes is chained, so one that is not was written by something else.
func TestAnUnchainedRowAboveTheChainStartIsDetected(t *testing.T) {
	store, ctx := chainTestStore(t)
	seedChain(t, store, ctx, 3)

	report := wreck(t, store, ctx, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `
			INSERT INTO audit_log (id, occurred_at, actor, action, subject_type, subject_id, outcome, reason)
			VALUES ('aud-foreign', now(), 'user:mallory', 'response.simulated', 'action', 'act-x', 'success', '')`,
		); err != nil {
			t.Fatalf("tamper: %v", err)
		}
	})
	if report.Status != ChainBroken {
		t.Fatalf("Status = %q, want %q", report.Status, ChainBroken)
	}
	if report.Linkage.Break == nil || report.Linkage.Break.Kind != BreakUnchainedAfterStart {
		t.Fatalf("Linkage.Break = %+v, want kind %q", report.Linkage.Break, BreakUnchainedAfterStart)
	}
}

// TestRowsWrittenBeforeTheChainAreUnchainedNotBroken.
//
// A deployment that already held audit rows must not light up red the moment it
// gains the chain. Those rows are outside it, which is neither verified nor
// broken.
func TestRowsWrittenBeforeTheChainAreUnchainedNotBroken(t *testing.T) {
	store, ctx := chainTestStore(t)

	report := wreck(t, store, ctx, func(tx pgx.Tx) {
		for i := 1; i <= 3; i++ {
			if _, err := tx.Exec(ctx, `
				INSERT INTO audit_log (id, occurred_at, actor, action, subject_type, subject_id, outcome, reason)
				VALUES ($1, now(), 'system:griefer', 'system.started', 'system', '', 'success', '')`,
				fmt.Sprintf("aud-legacy-%d", i)); err != nil {
				t.Fatalf("seed pre-chain row: %v", err)
			}
		}
	})
	if report.Status != ChainUnchained {
		t.Fatalf("Status = %q, want %q", report.Status, ChainUnchained)
	}
	if report.Unchained.Entries != 3 {
		t.Errorf("Unchained.Entries = %d, want 3", report.Unchained.Entries)
	}
	if report.Linkage.Break != nil {
		t.Errorf("Linkage.Break = %+v; pre-chain rows are not broken links", report.Linkage.Break)
	}
}

// TestAnInsertedRowIsDetectedAndDoesNotSilenceTheTrail.
//
// Two things at once, because they are the same decision seen from both sides.
//
// A row inserted mid-chain by something that did not take the head lock is
// DETECTED: the row after it now links to a predecessor that is no longer its
// neighbour, which the linkage walk reports.
//
// And it does not stop GRIEFER recording. An earlier version of this design
// refused such an append with a unique index on (chain_id, prev_hash). That
// index refuses the SECOND row to claim a predecessor -- always GRIEFER's,
// because whoever bypasses the lock inserts first -- so one INSERT would have
// silenced the trail permanently, with recordAudit logging the failure and
// carrying on.
func TestAnInsertedRowIsDetectedAndDoesNotSilenceTheTrail(t *testing.T) {
	store, ctx := chainTestStore(t)
	seeded := seedChain(t, store, ctx, 3)
	tail := seeded[len(seeded)-1]

	// Claim the current tail's hash as a predecessor, at a sequence of the
	// attacker's choosing, without holding the head lock.
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO audit_log (id, occurred_at, actor, action, subject_type, subject_id, outcome, reason,
		                       chain_id, prev_hash, entry_hash, hash_version)
		VALUES ('aud-injected', now(), 'user:mallory', 'response.simulated', 'action', 'act-x', 'success', '',
		        $1, $2, 'deadbeefdeadbeef', $3)`,
		tail.ChainID, seeded[0].EntryHash, audit.ChainHashVersion); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// The trail keeps recording. This is the assertion that matters most.
	next := &audit.Entry{
		ID:          "aud-after-injection",
		Timestamp:   time.Date(2026, 8, 27, 10, 0, 9, 0, time.UTC),
		Actor:       "system:griefer",
		Action:      audit.ActionEventIngested,
		SubjectType: audit.SubjectEvent,
		SubjectID:   "evt-after-injection",
		Outcome:     audit.OutcomeSuccess,
	}
	if err := store.Append(ctx, next); err != nil {
		t.Fatalf("Append() failed after a row was injected: %v\n"+
			"One INSERT must not be able to stop GRIEFER recording.", err)
	}

	report, err := store.VerifyAuditChain(ctx, 0, 0)
	if err != nil {
		t.Fatalf("VerifyAuditChain() error = %v", err)
	}
	if report.Status != ChainBroken {
		t.Fatalf("Status = %q, want %q -- a row was inserted into the trail",
			report.Status, ChainBroken)
	}
	if report.Linkage.Break == nil || report.Linkage.Break.Kind != BreakLinkMismatch {
		t.Fatalf("Linkage.Break = %+v, want kind %q", report.Linkage.Break, BreakLinkMismatch)
	}
}

// TestAnEntryFromAnotherChainIsDetected.
//
// This is the one insertion that survives both other checks unaided. Linkage
// walks a single chain_id, so a foreign row is not in the walk at all; content
// recomputes each row against its OWN chain_id, so a forgery whose hashes are
// internally consistent passes. Without a check for it, an attacker holding
// nothing but INSERT could add entries to the trail -- a decision GRIEFER never
// made, in GRIEFER's own record -- and the verifier would call it consistent.
func TestAnEntryFromAnotherChainIsDetected(t *testing.T) {
	store, ctx := chainTestStore(t)
	seedChain(t, store, ctx, 3)

	forged := &audit.Entry{
		ID:          "aud-forged",
		Timestamp:   time.Date(2026, 8, 27, 11, 0, 0, 0, time.UTC),
		Actor:       "user:mallory",
		ActorRole:   "admin",
		Action:      audit.ActionActionSimulated,
		SubjectType: audit.SubjectAction,
		SubjectID:   "act-forged",
		Outcome:     audit.OutcomeSuccess,
		Reason:      "allowed by policy",
	}
	const foreignChain = "chn-not-this-database"
	_, _, canonical, err := audit.CanonicalDetails(nil)
	if err != nil {
		t.Fatalf("CanonicalDetails() error = %v", err)
	}
	// A correctly computed hash, for a chain that is not this one. The forgery
	// is internally consistent; that is exactly why it needs its own check.
	hash := audit.ChainHash(foreignChain, audit.GenesisPrevHash, forged, canonical)

	tx, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (id, occurred_at, actor, actor_role, action, subject_type, subject_id,
		                       outcome, reason, chain_id, prev_hash, entry_hash, hash_version)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		forged.ID, forged.Timestamp, forged.Actor, forged.ActorRole, forged.Action, forged.SubjectType,
		forged.SubjectID, forged.Outcome, forged.Reason,
		foreignChain, audit.GenesisPrevHash, hash, audit.ChainHashVersion); err != nil {
		t.Fatalf("insert forged entry: %v", err)
	}

	report, err := verifyAuditChain(ctx, tx, store.Kind(), 0, 0)
	if err != nil {
		t.Fatalf("verifyAuditChain() error = %v", err)
	}
	if report.Status != ChainBroken {
		t.Fatalf("Status = %q, want %q -- an entry GRIEFER never wrote is sitting in its trail",
			report.Status, ChainBroken)
	}
	if report.Linkage.Break == nil || report.Linkage.Break.Kind != BreakForeignChain {
		t.Fatalf("Linkage.Break = %+v, want kind %q", report.Linkage.Break, BreakForeignChain)
	}
	if report.Linkage.Break.ID != forged.ID {
		t.Errorf("break names %q, want %q", report.Linkage.Break.ID, forged.ID)
	}
	// And the content check must NOT be what caught it: the forgery hashes
	// correctly against its own chain. If this ever starts failing, the reason
	// the foreign-chain check exists has changed.
	if report.Content.Break != nil && report.Content.Break.ID == forged.ID {
		t.Errorf("content caught the forgery (%+v); it should not, which is why the "+
			"foreign-chain check is a separate one", report.Content.Break)
	}
}

// TestAnEntryWithAProducerControlCharacterIsStillRecorded.
//
// The suppression path this closes, end to end: `source_name` is bounded in
// length by the ingest schema but not in content, `Reason` on an accepted event
// is built from it, a TEXT column refuses a NUL byte, and `recordAudit` logs a
// failed audit write and carries on. Refusing the entry anywhere on this path
// would let anyone who can submit one event have it recorded with nothing in
// the trail describing it.
func TestAnEntryWithAProducerControlCharacterIsStillRecorded(t *testing.T) {
	store, ctx := chainTestStore(t)

	entry := &audit.Entry{
		ID:          "aud-nul-001",
		Timestamp:   time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC),
		Actor:       "system:griefer",
		Action:      audit.ActionEventIngested,
		SubjectType: audit.SubjectEvent,
		SubjectID:   "evt-legitimate",
		Outcome:     audit.OutcomeSuccess,
		// Exactly the shape internal/api/service.go builds on an accepted event.
		Reason: "event accepted from cloud_audit/attacker\x00name",
	}
	if err := store.Append(ctx, entry); err != nil {
		t.Fatalf("Append() refused an entry carrying a producer-supplied NUL: %v\n"+
			"That refusal is an audit-suppression primitive: one event submission would "+
			"then be recorded with no entry describing it.", err)
	}

	entries, _, err := store.List(ctx, 10, 0)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("List() returned %d entries, want 1", len(entries))
	}
	got := entries[0]
	if strings.ContainsRune(got.Reason, 0) {
		t.Errorf("a NUL reached the column: %q", got.Reason)
	}
	if !strings.Contains(got.Reason, "attacker") {
		t.Errorf("sanitisation discarded more than the offending byte: %q", got.Reason)
	}
	if _, ok := got.Details["sanitised_fields"]; !ok {
		t.Errorf("the stored entry does not record that it was changed: %v", got.Details)
	}

	// And the chain still verifies: what was hashed is what was stored.
	report, err := store.VerifyAuditChain(ctx, 0, 0)
	if err != nil {
		t.Fatalf("VerifyAuditChain() error = %v", err)
	}
	if report.Status != ChainConsistent {
		t.Fatalf("Status = %q, want %q (content break %+v) -- sanitising after hashing "+
			"would show up exactly here", report.Status, ChainConsistent, report.Content.Break)
	}
}

// TestVerifyIsConsistentWhileTheTrailIsBeingWritten.
//
// The report is assembled from several statements. Run against the pool, each
// would get its own snapshot, and an append committing between the chain-head
// read and the trail-head read would make a healthy trail report
// matches_trail false with the recorded head BEHIND the trail -- a combination
// that means nothing and has no row in the runbook.
//
// An integrity check that cries wolf under write load is one nobody reads, so
// this is a correctness test, not a performance one.
func TestVerifyIsConsistentWhileTheTrailIsBeingWritten(t *testing.T) {
	store, ctx := chainTestStore(t)
	seedChain(t, store, ctx, 2)

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			e := &audit.Entry{
				ID:          fmt.Sprintf("aud-concurrent-%04d", i),
				Timestamp:   time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC),
				Actor:       "system:griefer",
				Action:      audit.ActionEventIngested,
				SubjectType: audit.SubjectEvent,
				SubjectID:   fmt.Sprintf("evt-%04d", i),
				Outcome:     audit.OutcomeSuccess,
			}
			if err := store.Append(ctx, e); err != nil {
				return
			}
		}
	}()

	for i := 0; i < 25; i++ {
		report, err := store.VerifyAuditChain(ctx, 0, 0)
		if err != nil {
			close(done)
			wg.Wait()
			t.Fatalf("VerifyAuditChain() error = %v", err)
		}
		if report.Status != ChainConsistent {
			close(done)
			wg.Wait()
			t.Fatalf("Status = %q under concurrent appends; linkage break %+v",
				report.Status, report.Linkage.Break)
		}
		if report.RecordedHead == nil || !report.RecordedHead.MatchesTrail {
			close(done)
			wg.Wait()
			t.Fatalf("RecordedHead = %+v while the trail was being written; the report was "+
				"assembled from more than one snapshot", report.RecordedHead)
		}
		// The partial-window warning is expected and correct here: the trail
		// outgrows the default page while this runs. What must NOT appear is
		// the head-ahead warning, which would mean the report had been
		// assembled from more than one snapshot.
		if hasWarning(report, WarnRecordedHeadAhead) {
			close(done)
			wg.Wait()
			t.Fatalf("Warnings = %v on a healthy trail", report.Warnings)
		}
	}
	close(done)
	wg.Wait()
}

// TestAPartialContentWindowIsSaidOutLoud.
//
// `consistent` is the truth about the entries that were examined. On any trail
// longer than one page that is not all of them, and a status that did not say
// so would read as "every entry was recomputed" -- while an entry edited
// without rehashing below the window was never looked at.
func TestAPartialContentWindowIsSaidOutLoud(t *testing.T) {
	store, ctx := chainTestStore(t)
	seedChain(t, store, ctx, 6)

	partial, err := store.VerifyAuditChain(ctx, 2, 0)
	if err != nil {
		t.Fatalf("VerifyAuditChain() error = %v", err)
	}
	if partial.Status != ChainConsistent {
		t.Fatalf("Status = %q, want %q", partial.Status, ChainConsistent)
	}
	if !hasWarning(partial, WarnContentWindowIsPartial) {
		t.Errorf("Warnings = %v, want %q -- 2 of 6 entries were recomputed",
			partial.Warnings, WarnContentWindowIsPartial)
	}

	// An offset past the end recomputes nothing at all.
	empty, err := store.VerifyAuditChain(ctx, 10, 100)
	if err != nil {
		t.Fatalf("VerifyAuditChain() error = %v", err)
	}
	if !hasWarning(empty, WarnContentWindowIsEmpty) {
		t.Errorf("Warnings = %v, want %q", empty.Warnings, WarnContentWindowIsEmpty)
	}

	// And a window that covers the whole chain says nothing extra.
	full, err := store.VerifyAuditChain(ctx, 200, 0)
	if err != nil {
		t.Fatalf("VerifyAuditChain() error = %v", err)
	}
	if hasWarning(full, WarnContentWindowIsPartial) || hasWarning(full, WarnContentWindowIsEmpty) {
		t.Errorf("Warnings = %v on a window covering the whole chain", full.Warnings)
	}
}

// TestACorruptedChainHeadDoesNotStopTheTrail.
//
// audit_chain_head is the one table in this subsystem with no append-only
// trigger, and the service's own role must be able to update it. If prev_hash
// were derived from head_hash, writing any already-claimed hash there would
// make every subsequent INSERT collide with uq_audit_log_chain_prev -- and
// since recordAudit logs a failed audit write and carries on, the whole trail
// would go silent with nothing anywhere saying so. One statement, and GRIEFER
// stops recording.
//
// So the head row must be a tripwire, never a kill switch: writes continue, and
// verify reports the discrepancy.
func TestACorruptedChainHeadDoesNotStopTheTrail(t *testing.T) {
	store, ctx := chainTestStore(t)
	seeded := seedChain(t, store, ctx, 3)

	// The hash of the FIRST entry: already claimed as entry 2's prev_hash.
	poison := seeded[0].EntryHash
	if _, err := store.pool.Exec(ctx,
		`UPDATE audit_chain_head SET head_hash = $1, head_sequence = 1`, poison); err != nil {
		t.Fatalf("poison the head: %v", err)
	}

	// Before anything else writes: the discrepancy is visible, and the chain
	// itself is sound. A head behind the trail cannot arise from appending,
	// because the head advances in the same transaction as the entry.
	before, err := store.VerifyAuditChain(ctx, 0, 0)
	if err != nil {
		t.Fatalf("VerifyAuditChain() error = %v", err)
	}
	if before.Status != ChainConsistent {
		t.Errorf("Status = %q, want %q (%+v)", before.Status, ChainConsistent, before.Linkage.Break)
	}
	if before.RecordedHead == nil || before.RecordedHead.MatchesTrail {
		t.Fatalf("RecordedHead = %+v, want MatchesTrail false", before.RecordedHead)
	}
	if !hasWarning(before, WarnRecordedHeadDiverged) {
		t.Errorf("Warnings = %v, want %q", before.Warnings, WarnRecordedHeadDiverged)
	}

	// And the trail keeps recording. This is the assertion that matters: with
	// prev_hash taken from head_hash, this Append would collide with
	// uq_audit_log_chain_prev and every audit write after it would too.
	next := &audit.Entry{
		ID:          "aud-after-poison",
		Timestamp:   time.Date(2026, 8, 27, 10, 0, 9, 0, time.UTC),
		Actor:       "system:griefer",
		Action:      audit.ActionEventIngested,
		SubjectType: audit.SubjectEvent,
		SubjectID:   "evt-after-poison",
		Outcome:     audit.OutcomeSuccess,
	}
	if err := store.Append(ctx, next); err != nil {
		t.Fatalf("Append() failed after the chain head was corrupted: %v\n"+
			"One UPDATE of a trigger-free row must not be able to stop the audit trail.", err)
	}
	if next.PrevHash != seeded[len(seeded)-1].EntryHash {
		t.Errorf("the new entry linked to %q; the trail's actual head is %q",
			next.PrevHash, seeded[len(seeded)-1].EntryHash)
	}

	// The append rewrites the head as it goes, so the discrepancy closes by
	// itself. That is worth knowing rather than worth preventing: the record it
	// describes is intact either way, and a head that could not recover would
	// need an operator for something the next write fixes.
	after, err := store.VerifyAuditChain(ctx, 0, 0)
	if err != nil {
		t.Fatalf("VerifyAuditChain() error = %v", err)
	}
	if after.RecordedHead == nil || !after.RecordedHead.MatchesTrail {
		t.Errorf("RecordedHead = %+v after a further append; it should have caught up",
			after.RecordedHead)
	}
	if after.Status != ChainConsistent {
		t.Errorf("Status = %q, want %q", after.Status, ChainConsistent)
	}
}

// TestAConsistentlyForgedAppendIsNotDetected states a limit in executable form.
//
// The canonical form is in this repository and no secret enters it, so anyone
// who can INSERT can compute a well-formed link onto the current head. The
// chain continues over it and verify reports consistent.
//
// This test exists to fail if that ever silently changes -- in either
// direction. If a future change makes this detectable, the documents claiming
// it is not are the change under review; if someone reads the chain as proof
// that GRIEFER wrote every entry, this is the counter-example.
//
// docs/SAFETY_MODEL.md states the same limit in prose. Producer authentication
// and per-caller credentials are what would speak to it.
func TestAConsistentlyForgedAppendIsNotDetected(t *testing.T) {
	store, ctx := chainTestStore(t)
	seeded := seedChain(t, store, ctx, 3)
	tail := seeded[len(seeded)-1]

	forged := &audit.Entry{
		ID:          "aud-forged-append",
		Timestamp:   time.Date(2026, 8, 27, 10, 0, 9, 0, time.UTC),
		Actor:       "user:root",
		ActorRole:   "admin",
		Action:      audit.ActionActionSimulated,
		SubjectType: audit.SubjectAction,
		SubjectID:   "act-never-happened",
		Outcome:     audit.OutcomeSuccess,
		Reason:      "a decision GRIEFER never made",
	}
	_, _, canonical, err := audit.CanonicalDetails(nil)
	if err != nil {
		t.Fatalf("CanonicalDetails() error = %v", err)
	}
	// Linked onto the real head, in this database's own chain, hashed by the
	// same function the platform uses. Nothing distinguishes it.
	hash := audit.ChainHash(tail.ChainID, tail.EntryHash, forged, canonical)

	if _, err := store.pool.Exec(ctx, `
		INSERT INTO audit_log (id, occurred_at, actor, actor_role, action, subject_type, subject_id,
		                       outcome, reason, chain_id, prev_hash, entry_hash, hash_version)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		forged.ID, forged.Timestamp, forged.Actor, forged.ActorRole, forged.Action, forged.SubjectType,
		forged.SubjectID, forged.Outcome, forged.Reason,
		tail.ChainID, tail.EntryHash, hash, audit.ChainHashVersion); err != nil {
		t.Fatalf("insert forged append: %v", err)
	}

	report, err := store.VerifyAuditChain(ctx, 0, 0)
	if err != nil {
		t.Fatalf("VerifyAuditChain() error = %v", err)
	}
	if report.Status != ChainConsistent {
		t.Fatalf("Status = %q, want %q.\n"+
			"If this now DETECTS a consistently forged append, the documents saying it cannot "+
			"are stale and are part of this change. Break: %+v / %+v",
			report.Status, ChainConsistent, report.Linkage.Break, report.Content.Break)
	}
	if report.Linkage.Entries != 4 {
		t.Errorf("Linkage.Entries = %d, want 4 -- the forgery is counted as part of the chain",
			report.Linkage.Entries)
	}
}

func hasWarning(r *AuditChainReport, want string) bool {
	for _, w := range r.Warnings {
		if w == want {
			return true
		}
	}
	return false
}
