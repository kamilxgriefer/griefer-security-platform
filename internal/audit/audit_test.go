package audit_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
)

func TestSinkExposesNoMutationMethods(t *testing.T) {
	// The append-only guarantee is enforced by the type system: adding Update
	// or Delete to audit.Sink would break it, and this test fails if anyone
	// does.
	sinkType := reflect.TypeOf((*audit.Sink)(nil)).Elem()
	allowed := map[string]bool{"Append": true, "List": true}
	for i := 0; i < sinkType.NumMethod(); i++ {
		name := sinkType.Method(i).Name
		if !allowed[name] {
			t.Errorf("audit.Sink exposes %q; the audit trail has no update and no delete", name)
		}
	}
	if sinkType.NumMethod() != len(allowed) {
		t.Errorf("audit.Sink has %d methods, want %d", sinkType.NumMethod(), len(allowed))
	}
}

func TestRecorderStampsEntries(t *testing.T) {
	fixed := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	store := storage.NewMemoryStore(0)
	rec, err := audit.NewRecorderWithClock(store, func() time.Time { return fixed })
	if err != nil {
		t.Fatalf("NewRecorderWithClock() error = %v", err)
	}

	entry, err := rec.Record(context.Background(), audit.Entry{
		Action: audit.ActionPolicyEvaluated, SubjectType: audit.SubjectAction,
		SubjectID: "act-1", Outcome: audit.OutcomeDenied, Reason: "destructive",
	})
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if entry.ID == "" {
		t.Error("Record() assigned no id")
	}
	if !entry.Timestamp.Equal(fixed) {
		t.Errorf("Timestamp = %v, want the injected clock %v", entry.Timestamp, fixed)
	}
	if entry.Actor != "system:griefer" {
		t.Errorf("Actor = %q, want the system default", entry.Actor)
	}
	if entry.Sequence == 0 {
		t.Error("the sink assigned no sequence number")
	}
}

func TestRecorderRejectsIncompleteEntries(t *testing.T) {
	rec, err := audit.NewRecorder(storage.NewMemoryStore(0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	tests := []struct {
		name  string
		entry audit.Entry
	}{
		{"no action", audit.Entry{Outcome: audit.OutcomeSuccess}},
		{"no outcome", audit.Entry{Action: audit.ActionEventIngested}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := rec.Record(context.Background(), tt.entry); err == nil {
				t.Error("Record() accepted an entry that cannot be interpreted later")
			}
		})
	}
}

func TestNewRecorderRequiresASink(t *testing.T) {
	if _, err := audit.NewRecorder(nil); err == nil {
		t.Error("NewRecorder(nil) should fail; a recorder with nowhere to write silently loses evidence")
	}
}

type failingSink struct{}

func (failingSink) Append(context.Context, *audit.Entry) error { return errors.New("disk full") }
func (failingSink) List(context.Context, int, int) ([]*audit.Entry, int, error) {
	return nil, 0, errors.New("disk full")
}

func TestRecorderSurfacesWriteFailures(t *testing.T) {
	rec, err := audit.NewRecorder(failingSink{})
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	if _, err := rec.Record(context.Background(), audit.Entry{
		Action: audit.ActionEventIngested, Outcome: audit.OutcomeSuccess,
	}); err == nil {
		t.Error("Record() swallowed a write failure; whether to proceed without audit is the caller's decision")
	}
}

func TestRecorderPreservesOrder(t *testing.T) {
	store := storage.NewMemoryStore(0)
	rec, err := audit.NewRecorder(store)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if _, err := rec.Record(ctx, audit.Entry{
			Action: audit.ActionEventIngested, SubjectType: audit.SubjectEvent,
			Outcome: audit.OutcomeSuccess, Reason: "entry",
		}); err != nil {
			t.Fatalf("Record() error = %v", err)
		}
	}
	entries, total, err := rec.List(ctx, 100, 0)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 10 {
		t.Fatalf("total = %d, want 10", total)
	}
	for i := 1; i < len(entries); i++ {
		if entries[i].Sequence <= entries[i-1].Sequence {
			t.Fatalf("sequence went backwards at %d", i)
		}
	}
}
