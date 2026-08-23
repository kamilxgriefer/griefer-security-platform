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
	return nil
}
