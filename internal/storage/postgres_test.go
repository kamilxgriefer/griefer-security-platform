package storage_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
)

// truncate empties every GRIEFER table so each conformance sub-test starts
// clean.
//
// TRUNCATE is used rather than DELETE precisely because DELETE on audit_log is
// blocked by the append-only trigger. That asymmetry is the point: the trigger
// stops ordinary writes, not an operator with DDL rights. See
// TestPostgresAuditLogRejectsUpdateAndDelete below and docs/SAFETY_MODEL.md.
func truncate(t *testing.T, store storage.Store) {
	t.Helper()
	dsn := os.Getenv("GRIEFER_TEST_POSTGRES_DSN")
	if dsn == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect for truncate: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	if _, err := conn.Exec(ctx,
		`TRUNCATE security_events, incidents, response_actions, audit_log RESTART IDENTITY`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// TestPostgresAuditLogRejectsUpdateAndDelete proves the database-level
// append-only guarantee, not just the Go interface's absence of an Update
// method.
func TestPostgresAuditLogRejectsUpdateAndDelete(t *testing.T) {
	dsn := os.Getenv("GRIEFER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GRIEFER_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	store, err := storage.NewPostgresStore(ctx, storage.PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()
	truncate(t, store)

	if err := store.Append(ctx, &audit.Entry{
		ID: "aud-immutable-1", Timestamp: time.Now().UTC(), Actor: "system:griefer",
		Action: audit.ActionPolicyEvaluated, SubjectType: audit.SubjectAction,
		SubjectID: "act-1", Outcome: audit.OutcomeDenied, Reason: "denied for the test",
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	tests := []struct {
		name string
		sql  string
	}{
		{"rewriting a verdict", `UPDATE audit_log SET outcome = 'success' WHERE id = 'aud-immutable-1'`},
		{"deleting an entry", `DELETE FROM audit_log WHERE id = 'aud-immutable-1'`},
		{"clearing the trail", `DELETE FROM audit_log`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := conn.Exec(ctx, tt.sql)
			if err == nil {
				t.Fatal("the database accepted a mutation of the audit trail")
			}
			if !strings.Contains(err.Error(), "append-only") {
				t.Errorf("error = %q, want the append-only trigger to have fired", err)
			}
		})
	}

	entries, total, err := store.List(ctx, 10, 0)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 1 || entries[0].Outcome != audit.OutcomeDenied {
		t.Errorf("the audit entry was altered: total=%d entries=%+v", total, entries)
	}
}

func TestNewPostgresStoreRejectsBadInput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("empty DSN", func(t *testing.T) {
		if _, err := storage.NewPostgresStore(ctx, storage.PostgresOptions{}); err == nil {
			t.Error("NewPostgresStore() accepted an empty DSN")
		}
	})

	t.Run("unparseable DSN does not echo the password", func(t *testing.T) {
		_, err := storage.NewPostgresStore(ctx, storage.PostgresOptions{
			DSN: "postgres://user:sup3rs3cret@:::/bad",
		})
		if err == nil {
			t.Fatal("NewPostgresStore() accepted an unparseable DSN")
		}
		if strings.Contains(err.Error(), "sup3rs3cret") {
			t.Errorf("error leaked the password: %q", err)
		}
	})

	t.Run("unreachable host fails fast", func(t *testing.T) {
		start := time.Now()
		_, err := storage.NewPostgresStore(ctx, storage.PostgresOptions{
			DSN:            "postgres://griefer:griefer@127.0.0.1:1/griefer?sslmode=disable",
			ConnectTimeout: 3 * time.Second,
		})
		if err == nil {
			t.Fatal("NewPostgresStore() connected to a closed port")
		}
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Errorf("took %s to fail; a wrong DSN must not hang a container health check", elapsed)
		}
	})
}
