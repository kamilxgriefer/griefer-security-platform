package integration_test

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// truncateAll empties the GRIEFER tables between live-service runs.
//
// TRUNCATE rather than DELETE, because DELETE on audit_log is refused by the
// append-only trigger. That the reset needs a privileged statement is the point:
// ordinary application access cannot rewrite the trail.
func truncateAll(ctx context.Context, dsn string) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	if _, err := conn.Exec(ctx,
		`TRUNCATE security_events, incidents, response_actions, audit_log RESTART IDENTITY`); err != nil {
		return fmt.Errorf("truncate: %w", err)
	}
	// audit_chain_head is reset, NOT truncated. Truncating would drop the seed
	// row that every audit write locks, and the next append would fail rather
	// than start a fresh chain. Resetting it to the genesis state is what makes
	// each test's chain independent of the last one's — without it the first
	// entry of a run links to a predecessor that TRUNCATE has just deleted,
	// which is indistinguishable from a deleted prefix.
	if _, err := conn.Exec(ctx,
		`UPDATE audit_chain_head SET head_sequence = 0, head_hash = NULL, updated_at = now()`); err != nil {
		return fmt.Errorf("reset audit chain head: %w", err)
	}
	return nil
}
