package storage_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
)

// chainEntry builds an audit entry the way a caller would, minus the stamping
// Recorder.Prepare does.
func chainEntry(n int, details map[string]any) *audit.Entry {
	return &audit.Entry{
		ID:          fmt.Sprintf("aud-chain-%03d", n),
		Timestamp:   at,
		Actor:       "user:ana",
		ActorRole:   "admin",
		Action:      audit.ActionPolicyEvaluated,
		SubjectType: audit.SubjectAction,
		SubjectID:   fmt.Sprintf("act-%03d", n),
		Outcome:     audit.OutcomeSuccess,
		Reason:      "allowed by policy",
		RequestID:   fmt.Sprintf("req-%03d", n),
		Details:     details,
	}
}

// TestAuditChainConformance runs one contract against every store, for the
// reason the rest of this suite exists: a chain guarantee that held only in
// PostgreSQL would be discovered in production rather than here.
func TestAuditChainConformance(t *testing.T) {
	for _, f := range factories(t) {
		t.Run(f.name, func(t *testing.T) {
			t.Run("ordinary appends produce a consistent chain", func(t *testing.T) {
				store := f.open(t)
				ctx := context.Background()
				for i := 1; i <= 5; i++ {
					if err := store.Append(ctx, chainEntry(i, map[string]any{"i": i})); err != nil {
						t.Fatalf("Append(%d) error = %v", i, err)
					}
				}
				report, err := store.VerifyAuditChain(ctx, 0, 0)
				if err != nil {
					t.Fatalf("VerifyAuditChain() error = %v", err)
				}
				if report.Status != storage.ChainConsistent {
					t.Fatalf("Status = %q (%+v, %+v), want %q",
						report.Status, report.Linkage.Break, report.Content.Break, storage.ChainConsistent)
				}
				if report.Linkage.Entries != 5 {
					t.Errorf("Linkage.Entries = %d, want 5", report.Linkage.Entries)
				}
				if report.Content.Entries != 5 {
					t.Errorf("Content.Entries = %d, want 5", report.Content.Entries)
				}
				if report.Unchained.Entries != 0 {
					t.Errorf("Unchained.Entries = %d, want 0", report.Unchained.Entries)
				}
			})

			t.Run("the first entry starts the chain and every other links back", func(t *testing.T) {
				store := f.open(t)
				ctx := context.Background()
				for i := 1; i <= 4; i++ {
					if err := store.Append(ctx, chainEntry(i, nil)); err != nil {
						t.Fatalf("Append(%d) error = %v", i, err)
					}
				}
				entries, _, err := store.List(ctx, 100, 0)
				if err != nil {
					t.Fatalf("List() error = %v", err)
				}
				if len(entries) != 4 {
					t.Fatalf("List() returned %d entries, want 4", len(entries))
				}
				if entries[0].PrevHash != audit.GenesisPrevHash {
					t.Errorf("the first entry names a predecessor (%q); an unchained row would look the same",
						entries[0].PrevHash)
				}
				for i := 1; i < len(entries); i++ {
					if entries[i].PrevHash != entries[i-1].EntryHash {
						t.Errorf("entry %d links to %q, but its predecessor hashes to %q",
							i, entries[i].PrevHash, entries[i-1].EntryHash)
					}
					if entries[i].EntryHash == "" {
						t.Errorf("entry %d carries no hash", i)
					}
					if entries[i].ChainID != entries[0].ChainID {
						t.Errorf("entry %d belongs to chain %q, not %q", i, entries[i].ChainID, entries[0].ChainID)
					}
				}
			})

			// The test this whole design is arranged around. Every value here is
			// something a round trip through jsonb is entitled to re-render, and
			// a verifier that reported tampering on any of them would be worse
			// than no verifier at all.
			t.Run("awkward details do not produce a false tamper report", func(t *testing.T) {
				store := f.open(t)
				ctx := context.Background()
				awkward := []map[string]any{
					nil,
					{},
					{"big": int64(9007199254740993)},
					// Negative zero is NOT written as -0.0: in Go that literal is
					// plain 0.0. The signed-zero case belongs to the canonical
					// form and is covered there, over raw JSON, where a producer
					// can actually send it.
					{"float": 1.50, "exp": 1e21, "tiny": 1e-300},
					{"unicode": "zazolc gesla jazn / 105 / ok", "empty": ""},
					{"nested": map[string]any{"list": []any{1, "2", true, nil}}},
					{"quarantined_keys": []string{"griefer.control", "griefer.internal"}},
					{"deep": map[string]any{"a": map[string]any{"b": map[string]any{"c": []any{0.1, 0.2}}}}},
				}
				for i, d := range awkward {
					if err := store.Append(ctx, chainEntry(i+1, d)); err != nil {
						t.Fatalf("Append(%d, %v) error = %v", i, d, err)
					}
				}
				report, err := store.VerifyAuditChain(ctx, 0, 0)
				if err != nil {
					t.Fatalf("VerifyAuditChain() error = %v", err)
				}
				if report.Status != storage.ChainConsistent {
					t.Fatalf("Status = %q; linkage break %+v; content break %+v -- "+
						"a false positive here trains operators to ignore this check",
						report.Status, report.Linkage.Break, report.Content.Break)
				}
				if report.Content.Entries != len(awkward) {
					t.Errorf("Content.Entries = %d, want %d", report.Content.Entries, len(awkward))
				}
			})

			t.Run("an empty trail is empty, not consistent", func(t *testing.T) {
				store := f.open(t)
				report, err := store.VerifyAuditChain(context.Background(), 0, 0)
				if err != nil {
					t.Fatalf("VerifyAuditChain() error = %v", err)
				}
				if report.Status != storage.ChainEmpty {
					t.Errorf("Status = %q, want %q -- a truncated trail reporting intact is the "+
						"most misleading thing this check could say", report.Status, storage.ChainEmpty)
				}
			})

			t.Run("an atomic batch chains inside its transaction", func(t *testing.T) {
				store := f.open(t)
				ctx := context.Background()
				entries := []*audit.Entry{chainEntry(1, nil), chainEntry(2, map[string]any{"k": "v"})}
				if err := store.SaveActionWithAudit(ctx, nil, entries); err != nil {
					t.Fatalf("SaveActionWithAudit() error = %v", err)
				}
				if entries[0].EntryHash == "" || entries[1].PrevHash != entries[0].EntryHash {
					t.Errorf("the batch did not chain: %q then prev %q", entries[0].EntryHash, entries[1].PrevHash)
				}
				report, err := store.VerifyAuditChain(ctx, 0, 0)
				if err != nil {
					t.Fatalf("VerifyAuditChain() error = %v", err)
				}
				if report.Status != storage.ChainConsistent {
					t.Errorf("Status = %q, want %q (%+v)", report.Status, storage.ChainConsistent, report.Linkage.Break)
				}
			})

			// Two writers must not read the same head and both claim it. In
			// PostgreSQL the head row lock provides this; in the memory store
			// the mutex does. One test, one invariant, both stores.
			t.Run("concurrent appends produce one chain, not a fork", func(t *testing.T) {
				store := f.open(t)
				ctx := context.Background()
				const writers = 8
				var wg sync.WaitGroup
				errs := make(chan error, writers)
				for i := 0; i < writers; i++ {
					wg.Add(1)
					go func(n int) {
						defer wg.Done()
						if err := store.Append(ctx, chainEntry(n, map[string]any{"writer": n})); err != nil {
							errs <- err
						}
					}(i + 1)
				}
				wg.Wait()
				close(errs)
				for err := range errs {
					t.Fatalf("concurrent Append() error = %v", err)
				}
				report, err := store.VerifyAuditChain(ctx, 0, 0)
				if err != nil {
					t.Fatalf("VerifyAuditChain() error = %v", err)
				}
				if report.Status != storage.ChainConsistent {
					t.Fatalf("Status = %q after %d concurrent appends; linkage break %+v",
						report.Status, writers, report.Linkage.Break)
				}
				if report.Linkage.Entries != writers {
					t.Errorf("Linkage.Entries = %d, want %d", report.Linkage.Entries, writers)
				}
			})

			// The qualification travels with the answer, not only in a document
			// nobody opens.
			t.Run("every report says what it is not evidence of", func(t *testing.T) {
				store := f.open(t)
				report, err := store.VerifyAuditChain(context.Background(), 0, 0)
				if err != nil {
					t.Fatalf("VerifyAuditChain() error = %v", err)
				}
				if report.ExternallyAnchored {
					t.Error("ExternallyAnchored is true, but no anchor has shipped")
				}
				if report.Attests != storage.AuditChainAttests {
					t.Errorf("Attests = %q, want the fixed qualification", report.Attests)
				}
				if report.Store != store.Kind() {
					t.Errorf("Store = %q, want %q -- a response that does not name the store lets a "+
						"memory result read as the PostgreSQL guarantee", report.Store, store.Kind())
				}
				if report.Warnings == nil {
					t.Error("Warnings is null; every other endpoint returns an empty list")
				}
			})

			t.Run("the content window is bounded and reports its own scope", func(t *testing.T) {
				store := f.open(t)
				ctx := context.Background()
				for i := 1; i <= 6; i++ {
					if err := store.Append(ctx, chainEntry(i, nil)); err != nil {
						t.Fatalf("Append(%d) error = %v", i, err)
					}
				}
				report, err := store.VerifyAuditChain(ctx, 2, 0)
				if err != nil {
					t.Fatalf("VerifyAuditChain() error = %v", err)
				}
				if report.Content.Entries != 2 {
					t.Errorf("Content.Entries = %d, want 2", report.Content.Entries)
				}
				if report.Linkage.Entries != 6 {
					t.Errorf("Linkage.Entries = %d, want 6 -- linkage is not windowed", report.Linkage.Entries)
				}
				if report.Content.FromSequence == 0 || report.Content.ToSequence == 0 {
					t.Errorf("the content window does not report its own range: %+v", report.Content)
				}
				if report.Content.ToSequence < report.Content.FromSequence {
					t.Errorf("content window is inverted: %+v", report.Content)
				}
			})
		})
	}
}
