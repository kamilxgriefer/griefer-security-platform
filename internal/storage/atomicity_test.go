package storage_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
)

// This file exercises the atomic write contract — SaveActionWithAudit and
// entry-only writes — against every store implementation, using the same factory
// pattern as the conformance suite in store_test.go.
//
// The guarantee under test is the one GRIEFER's accountability story rests on:
// a response action and the audit entries explaining it are durable together or
// not at all. A stored action with no trail is a change nobody can account for.
// A stored trail naming an action that was never written points at nothing.
// Either half alone is worse than a clean failure, because both read as
// complete to whoever audits them later.

// atomicAction builds a response action that is valid enough to persist.
func atomicAction(t *testing.T, id, incidentID string) *incidents.ResponseAction {
	t.Helper()
	return &incidents.ResponseAction{
		ID: id, IncidentID: incidentID, ActionType: "preserve_evidence",
		Mode: incidents.ModeSimulate, Status: incidents.ActionSimulated,
		RequestedBy: "system:griefer", CreatedAt: at, Reversible: true,
		RollbackAction: "release_evidence_hold",
		PolicyDecision: &incidents.PolicyDecision{
			Effect: "allow", Allow: true, Reasons: []string{"corroborated"},
			PolicyPackage: "griefer.response", PolicyVersion: "0.1.0", EvaluatedAt: at,
		},
	}
}

// atomicEntry builds a valid audit entry of the shape persistEvaluation
// produces: an actor, the role that actor held, and a result in Details.
func atomicEntry(t *testing.T, id, role, result string, offset int) *audit.Entry {
	t.Helper()
	return &audit.Entry{
		ID: id, Timestamp: at.Add(time.Duration(offset) * time.Second),
		Actor: "analyst@example.com", ActorRole: role,
		Action: audit.ActionPolicyEvaluated, SubjectType: audit.SubjectAction,
		SubjectID: "act-atomic-1", Outcome: audit.OutcomeSuccess, Reason: "because",
		RequestID: "req-atomic-1",
		Details:   map[string]any{"result": result, "incident_id": "inc-atomic-1"},
	}
}

// storeCounts is how much a store holds. Atomicity is only observable as a
// before/after comparison, so the tests below take one of these on each side of
// a call that must fail.
type storeCounts struct {
	actions      int
	auditEntries int
}

// countStore snapshots the whole store. It reads through the public surface on
// purpose: the guarantee is about what a reader can see, not about internals.
func countStore(t *testing.T, store storage.Store) storeCounts {
	t.Helper()
	ctx := context.Background()
	_, actions, err := store.ListActions(ctx, "", storage.MaxPageSize, 0)
	if err != nil {
		t.Fatalf("ListActions() error = %v", err)
	}
	_, entries, err := store.List(ctx, storage.MaxPageSize, 0)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	return storeCounts{actions: actions, auditEntries: entries}
}

// seedBaseline puts one action and one audit entry in the store so that a later
// failed write has something it could plausibly corrupt. Asserting "the store
// is still empty" would pass even if a rollback wiped everything.
func seedBaseline(t *testing.T, store storage.Store) storeCounts {
	t.Helper()
	ctx := context.Background()
	if err := store.SaveActionWithAudit(ctx,
		atomicAction(t, "act-baseline", "inc-atomic-1"),
		[]*audit.Entry{atomicEntry(t, "aud-baseline", "admin", audit.ResultAllowed, 0)},
	); err != nil {
		t.Fatalf("seeding SaveActionWithAudit() error = %v", err)
	}
	return countStore(t, store)
}

func TestSaveActionWithAuditMakesActionAndEntriesReadableTogether(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			store := f.open(t)
			ctx := context.Background()
			if err := store.SaveIncident(ctx, sampleIncident("inc-atomic-1", 81, "critical", at)); err != nil {
				t.Fatalf("SaveIncident() error = %v", err)
			}

			action := atomicAction(t, "act-atomic-1", "inc-atomic-1")
			entries := []*audit.Entry{
				atomicEntry(t, "aud-atomic-1", "admin", audit.ResultAllowed, 1),
				atomicEntry(t, "aud-atomic-2", "admin", audit.ResultRequiresApproval, 2),
			}
			if err := store.SaveActionWithAudit(ctx, action, entries); err != nil {
				t.Fatalf("SaveActionWithAudit() error = %v", err)
			}

			got, err := store.GetAction(ctx, "act-atomic-1")
			if err != nil {
				t.Fatalf("GetAction() error = %v", err)
			}
			// The policy decision is the record of WHY the action exists. If the
			// transactional path dropped it, the action would be as unaccountable
			// as one written with no audit entry at all.
			if got.PolicyDecision == nil || got.PolicyDecision.Effect != "allow" {
				t.Errorf("the policy decision did not survive the atomic write: %+v", got.PolicyDecision)
			}

			stored, total, err := store.List(ctx, storage.MaxPageSize, 0)
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}
			if total != 2 || len(stored) != 2 {
				t.Fatalf("List() = %d items / total %d, want 2/2", len(stored), total)
			}
			wantIDs := []string{"aud-atomic-1", "aud-atomic-2"}
			for i, want := range wantIDs {
				if stored[i].ID != want {
					t.Errorf("entry %d id = %q, want %q", i, stored[i].ID, want)
				}
			}
			if stored[0].Details["result"] != audit.ResultAllowed {
				t.Errorf("audit details were lost: %+v", stored[0].Details)
			}

			// Both stores stamp the caller's entries with the sequence they were
			// given, so a caller can report what it wrote without re-reading.
			for i, e := range entries {
				if e.Sequence == 0 {
					t.Errorf("entry %d was not stamped with a sequence", i)
				}
			}

			_, actionTotal, err := store.ListActions(ctx, "inc-atomic-1", 10, 0)
			if err != nil {
				t.Fatalf("ListActions() error = %v", err)
			}
			if actionTotal != 1 {
				t.Errorf("ListActions() total = %d, want 1", actionTotal)
			}
		})
	}
}

func TestSaveActionWithAuditWritesOnlyTheEntriesWhenTheActionIsNil(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			store := f.open(t)
			ctx := context.Background()

			// This is the shape of an evaluation refused before any action
			// existed — an unknown action type, a caller without the role. The
			// refusal still has to be recorded, so a nil action must not turn the
			// whole call into a no-op or an error.
			entries := []*audit.Entry{
				atomicEntry(t, "aud-nil-action-1", "analyst", audit.ResultInvalidAction, 1),
				atomicEntry(t, "aud-nil-action-2", "analyst", audit.ResultInsufficientPermission, 2),
			}
			if err := store.SaveActionWithAudit(ctx, nil, entries); err != nil {
				t.Fatalf("SaveActionWithAudit() with a nil action error = %v", err)
			}

			counts := countStore(t, store)
			if counts.actions != 0 {
				t.Errorf("a nil action wrote %d response actions, want 0", counts.actions)
			}
			if counts.auditEntries != 2 {
				t.Errorf("audit entries = %d, want 2; the refusal must still be recorded", counts.auditEntries)
			}
		})
	}
}

func TestAWholeBatchOfEntriesIsWrittenWithIncreasingSequences(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			store := f.open(t)
			ctx := context.Background()

			batch := make([]*audit.Entry, 0, 4)
			for i := 1; i <= 4; i++ {
				batch = append(batch, atomicEntry(t,
					fmt.Sprintf("aud-batch-%d", i), "admin", audit.ResultDenied, i))
			}
			if err := store.SaveActionWithAudit(ctx, nil, batch); err != nil {
				t.Fatalf("SaveActionWithAudit() error = %v", err)
			}

			got, total, err := store.List(ctx, storage.MaxPageSize, 0)
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}
			if total != 4 || len(got) != 4 {
				t.Fatalf("List() = %d items / total %d, want 4/4", len(got), total)
			}
			// Sequences decide the order the trail is read in. If a batch write
			// left them flat or out of order, the narrative of a single incident
			// would be unreconstructable.
			for i := 1; i < len(got); i++ {
				if got[i].Sequence <= got[i-1].Sequence {
					t.Errorf("sequence is not increasing across the batch: %d then %d",
						got[i-1].Sequence, got[i].Sequence)
				}
			}
			for i := 1; i < len(batch); i++ {
				if batch[i].Sequence <= batch[i-1].Sequence {
					t.Errorf("the caller's entries were stamped out of order: %d then %d",
						batch[i-1].Sequence, batch[i].Sequence)
				}
			}

			// An empty batch is what a code path with nothing to say produces. It
			// must be a no-op, not an error the caller has to special-case.
			if err := store.SaveActionWithAudit(ctx, nil, nil); err != nil {
				t.Errorf("SaveActionWithAudit() with no entries error = %v, want nil", err)
			}
			if counts := countStore(t, store); counts.auditEntries != 4 {
				t.Errorf("an empty batch changed the trail: %d entries, want 4", counts.auditEntries)
			}
		})
	}
}

// TestSaveActionWithAuditWritesNothingWhenAnyEntryIsInvalid is the heart of the
// atomicity guarantee.
//
// A partial write here is the dangerous failure mode: an action persisted with
// half its explanation, or a trail that records an evaluation whose action does
// not exist. Both look complete to a reader. The store must therefore reject
// the whole call and leave the previous state exactly as it was — including any
// entry that appeared EARLIER in the same rejected batch.
func TestSaveActionWithAuditWritesNothingWhenAnyEntryIsInvalid(t *testing.T) {
	valid := func(t *testing.T, id string, offset int) *audit.Entry {
		t.Helper()
		return atomicEntry(t, id, "admin", audit.ResultAllowed, offset)
	}
	tests := []struct {
		name    string
		entries func(t *testing.T) []*audit.Entry
	}{
		{
			name: "a nil entry",
			entries: func(t *testing.T) []*audit.Entry {
				t.Helper()
				return []*audit.Entry{nil}
			},
		},
		{
			name: "an entry with no id",
			entries: func(t *testing.T) []*audit.Entry {
				t.Helper()
				return []*audit.Entry{{
					Timestamp: at, Actor: "analyst@example.com",
					Action: audit.ActionPolicyEvaluated, Outcome: audit.OutcomeSuccess,
				}}
			},
		},
		{
			// The interesting case: the first entry is perfectly writable, so a
			// store that validates lazily would already have committed it by the
			// time it reaches the bad one.
			name: "a nil entry after a valid one",
			entries: func(t *testing.T) []*audit.Entry {
				t.Helper()
				return []*audit.Entry{valid(t, "aud-partial-1", 1), nil}
			},
		},
		{
			name: "an entry with no id after two valid ones",
			entries: func(t *testing.T) []*audit.Entry {
				t.Helper()
				return []*audit.Entry{
					valid(t, "aud-partial-2", 1),
					valid(t, "aud-partial-3", 2),
					{Timestamp: at, Action: audit.ActionPolicyEvaluated, Outcome: audit.OutcomeDenied},
				}
			},
		},
	}

	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					// A fresh store per case: the postgres factory truncates on
					// open, so two open at once would not both keep their state.
					store := f.open(t)
					ctx := context.Background()
					before := seedBaseline(t, store)

					err := store.SaveActionWithAudit(ctx,
						atomicAction(t, "act-partial", "inc-atomic-1"), tt.entries(t))
					if err == nil {
						t.Fatal("SaveActionWithAudit() accepted a batch containing an invalid entry")
					}

					after := countStore(t, store)
					if after != before {
						t.Errorf("a rejected write changed the store: before %+v, after %+v", before, after)
					}
					// Named explicitly, because these are the two ways the
					// guarantee breaks and the counts alone do not say which.
					if _, getErr := store.GetAction(ctx, "act-partial"); getErr == nil {
						t.Error("the action was persisted even though its audit entries were rejected")
					}
					entries, _, listErr := store.List(ctx, storage.MaxPageSize, 0)
					if listErr != nil {
						t.Fatalf("List() error = %v", listErr)
					}
					for _, e := range entries {
						if e.ID != "aud-baseline" {
							t.Errorf("entry %q from the rejected batch was written anyway", e.ID)
						}
					}
				})
			}
		})
	}
}

// TestAnEntryOnlyBatchWritesNothingWhenAnyEntryIsInvalid is the same guarantee for
// the entries-only path, which is what the deny and error exits use.
func TestAnEntryOnlyBatchWritesNothingWhenAnyEntryIsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		entries func(t *testing.T) []*audit.Entry
	}{
		{
			name: "a nil entry",
			entries: func(t *testing.T) []*audit.Entry {
				t.Helper()
				return []*audit.Entry{nil}
			},
		},
		{
			name: "a nil entry after a valid one",
			entries: func(t *testing.T) []*audit.Entry {
				t.Helper()
				return []*audit.Entry{atomicEntry(t, "aud-append-partial-1", "admin", audit.ResultDenied, 1), nil}
			},
		},
		{
			name: "an entry with no id after a valid one",
			entries: func(t *testing.T) []*audit.Entry {
				t.Helper()
				return []*audit.Entry{
					atomicEntry(t, "aud-append-partial-2", "admin", audit.ResultDenied, 1),
					{Timestamp: at, Action: audit.ActionActionDenied, Outcome: audit.OutcomeDenied},
				}
			},
		},
	}

	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					store := f.open(t)
					ctx := context.Background()
					before := seedBaseline(t, store)

					if err := store.SaveActionWithAudit(ctx, nil, tt.entries(t)); err == nil {
						t.Fatal("SaveActionWithAudit() accepted a batch containing an invalid entry")
					}

					after := countStore(t, store)
					if after != before {
						t.Errorf("a rejected batch changed the store: before %+v, after %+v", before, after)
					}
					entries, _, err := store.List(ctx, storage.MaxPageSize, 0)
					if err != nil {
						t.Fatalf("List() error = %v", err)
					}
					for _, e := range entries {
						if e.ID != "aud-baseline" {
							t.Errorf("entry %q from the rejected batch was written anyway", e.ID)
						}
					}
				})
			}
		})
	}
}

// TestSaveActionWithAuditRejectsAnActionWithNoIDAndWritesNothing covers the
// other half of the batch. An action with no id cannot be fetched, referenced
// by an audit entry, or rolled back, so accepting one would produce a change
// with no handle on it — and the entries describing it must not be written
// either, since they would name an action nobody can retrieve.
func TestSaveActionWithAuditRejectsAnActionWithNoIDAndWritesNothing(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			store := f.open(t)
			ctx := context.Background()
			before := seedBaseline(t, store)

			bad := atomicAction(t, "", "inc-atomic-1")
			entries := []*audit.Entry{atomicEntry(t, "aud-no-action-id", "admin", audit.ResultAllowed, 1)}
			if err := store.SaveActionWithAudit(ctx, bad, entries); err == nil {
				t.Fatal("SaveActionWithAudit() accepted a response action with no id")
			}

			after := countStore(t, store)
			if after != before {
				t.Errorf("a rejected write changed the store: before %+v, after %+v", before, after)
			}
			stored, _, err := store.List(ctx, storage.MaxPageSize, 0)
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}
			for _, e := range stored {
				if e.ID == "aud-no-action-id" {
					t.Error("the audit entry was written for an action the store refused")
				}
			}
		})
	}
}

// TestAtomicallyWrittenEntriesReadBackInSequenceOrderWithActorRoleKept checks
// what an auditor actually reads.
//
// ActorRole is recorded per entry rather than looked up at read time precisely
// so that a later role change cannot rewrite who was authorised to do what. If
// the transactional write path dropped the role — or if the trail came back in
// any order but sequence — the record would no longer answer the question it
// exists to answer.
func TestAtomicallyWrittenEntriesReadBackInSequenceOrderWithActorRoleKept(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			store := f.open(t)
			ctx := context.Background()

			// Written across both atomic entry points, and interleaved, so the
			// ordering assertion is about the store's sequence rather than about
			// one call's slice order.
			first := []*audit.Entry{
				atomicEntry(t, "aud-order-1", "admin", audit.ResultAllowed, 1),
				atomicEntry(t, "aud-order-2", "analyst", audit.ResultRequiresApproval, 2),
			}
			if err := store.SaveActionWithAudit(ctx,
				atomicAction(t, "act-order-1", "inc-atomic-1"), first); err != nil {
				t.Fatalf("SaveActionWithAudit() error = %v", err)
			}
			// An empty role is the honest value for a request that asserted no
			// principal. It must round-trip as empty, not as some default role.
			second := []*audit.Entry{
				atomicEntry(t, "aud-order-3", "", audit.ResultPolicyTimeout, 3),
				atomicEntry(t, "aud-order-4", "analyst", audit.ResultDenied, 4),
			}
			if err := store.SaveActionWithAudit(ctx, nil, second); err != nil {
				t.Fatalf("SaveActionWithAudit() error = %v", err)
			}

			got, total, err := store.List(ctx, storage.MaxPageSize, 0)
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}
			if total != 4 || len(got) != 4 {
				t.Fatalf("List() = %d items / total %d, want 4/4", len(got), total)
			}

			want := []struct {
				id   string
				role string
			}{
				{"aud-order-1", "admin"},
				{"aud-order-2", "analyst"},
				{"aud-order-3", ""},
				{"aud-order-4", "analyst"},
			}
			for i, w := range want {
				if got[i].ID != w.id {
					t.Errorf("position %d holds %q, want %q; the trail is not in sequence order",
						i, got[i].ID, w.id)
				}
				if got[i].ActorRole != w.role {
					t.Errorf("entry %s ActorRole = %q, want %q", got[i].ID, got[i].ActorRole, w.role)
				}
				if got[i].Actor != "analyst@example.com" {
					t.Errorf("entry %s Actor = %q, want the recorded principal", got[i].ID, got[i].Actor)
				}
				if i > 0 && got[i].Sequence <= got[i-1].Sequence {
					t.Errorf("sequence is not increasing: %d then %d", got[i-1].Sequence, got[i].Sequence)
				}
			}
			if got[2].Details["result"] != audit.ResultPolicyTimeout {
				t.Errorf("Details[result] = %v, want %q; a timeout must stay distinguishable "+
					"from a deliberate denial", got[2].Details["result"], audit.ResultPolicyTimeout)
			}
		})
	}
}

// TestACommittedEntryCannotBeChangedByMutatingTheCallersCopy is a KNOWN-FAILING
// demonstration against the memory store. See the skip below.
//
// A write that returns success has committed. After that point the only way the
// stored entry should change is another Append — that is the whole content of
// "append-only", and the trigger in schema.sql exists to enforce it even against
// a careless psql session. An entry whose Details still point at memory the
// caller owns is committed in name only: whoever holds the original pointer can
// silently rewrite the verdict on a record that has already been audited, with
// no store call and nothing in the trail to show it happened.
//
// This is the audit-trail twin of the check the conformance suite already makes
// for incidents ("the store returned a live reference; a handler could rewrite
// history by accident"), and it matters more here, because the audit trail is
// the artifact the platform's accountability rests on.
func TestACommittedEntryCannotBeChangedByMutatingTheCallersCopy(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			if f.name == "memory" {
				// BUG (not fixed here, per the task's rules): MemoryStore
				// aliases the caller's Details map into the store.
				//
				// internal/storage/memory.go, appendAuditLocked, does
				// `clone := *entry` — a shallow struct copy. Entry.Details is a
				// map, so the "clone" shares the caller's map header. List then
				// does the same shallow copy on the way out, so a reader sees
				// whatever the original caller most recently wrote. The fix is a
				// deep copy of Details on write, next to the deepCopyIncident /
				// deepCopyAction helpers that already exist in that file for
				// exactly this reason.
				//
				// PostgresStore is unaffected: appendAudit json.Marshals Details
				// at write time, so the stored bytes stop tracking the caller.
				// The subtest below therefore runs for real against postgres and
				// guards it against regressing to the memory store's behaviour.
				t.Skip("known bug: MemoryStore.appendAuditLocked shallow-copies Entry, aliasing Details")
			}

			store := f.open(t)
			ctx := context.Background()

			entry := atomicEntry(t, "aud-alias-1", "analyst", audit.ResultDenied, 1)
			if err := store.SaveActionWithAudit(ctx, nil, []*audit.Entry{entry}); err != nil {
				t.Fatalf("SaveActionWithAudit() error = %v", err)
			}

			// A denial rewritten into an approval is the exact tampering the
			// append-only trail is supposed to make impossible.
			entry.Details["result"] = audit.ResultAllowed
			entry.Details["injected"] = "should never appear"

			got, _, err := store.List(ctx, storage.MaxPageSize, 0)
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}
			if got[0].Details["result"] != audit.ResultDenied {
				t.Errorf("a committed verdict changed to %v when the caller mutated its own copy",
					got[0].Details["result"])
			}
			if _, injected := got[0].Details["injected"]; injected {
				t.Error("the caller added a field to an entry the store had already committed")
			}
		})
	}
}
