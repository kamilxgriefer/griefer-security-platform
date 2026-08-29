package storage

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
)

//go:embed schema.sql
var schemaSQL string

// PostgresStore persists GRIEFER state in PostgreSQL.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// PostgresOptions configures the connection pool.
type PostgresOptions struct {
	DSN             string
	MaxOpenConns    int32
	MaxIdleConns    int32
	ConnMaxLifetime time.Duration
	// ConnectTimeout bounds the initial connection attempt so a wrong DSN fails
	// startup quickly instead of hanging a container health check.
	ConnectTimeout time.Duration
}

// NewPostgresStore connects to PostgreSQL, verifies the connection and applies
// the schema. Migration is idempotent, so a restart against an existing
// database is a no-op.
func NewPostgresStore(ctx context.Context, opts PostgresOptions) (*PostgresStore, error) {
	if strings.TrimSpace(opts.DSN) == "" {
		return nil, fmt.Errorf("storage: postgres DSN is required")
	}
	cfg, err := pgxpool.ParseConfig(opts.DSN)
	if err != nil {
		// The DSN can contain a password; never echo it back.
		return nil, fmt.Errorf("storage: postgres DSN is not parseable")
	}
	if opts.MaxOpenConns > 0 {
		cfg.MaxConns = opts.MaxOpenConns
	}
	if opts.MaxIdleConns > 0 {
		cfg.MinConns = opts.MaxIdleConns
	}
	if opts.ConnMaxLifetime > 0 {
		cfg.MaxConnLifetime = opts.ConnMaxLifetime
	}
	connectTimeout := opts.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = 10 * time.Second
	}

	connectCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(connectCtx, cfg)
	if err != nil {
		return nil, fmt.Errorf("storage: create postgres pool: %w", err)
	}
	if err := pool.Ping(connectCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("storage: postgres unreachable: %w", err)
	}
	store := &PostgresStore{pool: pool}
	if err := store.Migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

// Migrate applies the embedded schema.
func (s *PostgresStore) Migrate(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := s.pool.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("storage: apply schema: %w", err)
	}
	return nil
}

// Kind implements Store.
func (s *PostgresStore) Kind() string { return "postgres" }

// Ping implements Store.
func (s *PostgresStore) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("storage: postgres ping: %w", err)
	}
	return nil
}

// Close implements Store.
func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

// SaveEvent implements Store. Re-ingesting an event with a known id is
// idempotent rather than an error: producers retry, and a retry storm must not
// turn into an error storm.
func (s *PostgresStore) SaveEvent(ctx context.Context, ev *events.SecurityEvent) (EventSaveResult, error) {
	if ev == nil || ev.ID == "" {
		return EventSaveResult{}, fmt.Errorf("storage: event requires an id")
	}
	doc, err := json.Marshal(ev)
	if err != nil {
		return EventSaveResult{}, fmt.Errorf("storage: encode event: %w", err)
	}
	const q = `
		INSERT INTO security_events (
			id, schema_version, occurred_at, received_at, source_type, source_name,
			event_type, category, severity, actor_key, correlation_id, document, producer_id
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (id) DO NOTHING`
	tag, err := s.pool.Exec(ctx, q,
		ev.ID, ev.SchemaVersion, ev.Timestamp, ev.ReceivedAt, ev.SourceType, ev.SourceName,
		ev.EventType, string(ev.Category), string(ev.Severity), nullable(ev.ActorKey()),
		nullable(ev.CorrelationID), doc, nullable(ev.ProducerID))
	if err != nil {
		return EventSaveResult{}, fmt.Errorf("storage: insert event: %w", err)
	}
	// ON CONFLICT DO NOTHING affects no rows on a repeat, which is how the
	// caller learns that this event was already here.
	if tag.RowsAffected() > 0 {
		return EventSaveResult{Stored: true}, nil
	}
	var existing *string
	if err := s.pool.QueryRow(ctx,
		`SELECT producer_id FROM security_events WHERE id = $1`, ev.ID).Scan(&existing); err != nil {
		return EventSaveResult{}, fmt.Errorf("storage: read the producer of an existing event: %w", err)
	}
	out := EventSaveResult{}
	if existing != nil {
		out.ExistingProducerID = *existing
	}
	return out, nil
}

// ListEvents implements Store, newest first.
func (s *PostgresStore) ListEvents(ctx context.Context, limit, offset int) ([]*events.SecurityEvent, int, error) {
	limit = ClampLimit(limit)
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM security_events`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("storage: count events: %w", err)
	}
	rows, err := s.pool.Query(ctx,
		`SELECT document FROM security_events ORDER BY received_at DESC, id DESC LIMIT $1 OFFSET $2`,
		limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("storage: query events: %w", err)
	}
	defer rows.Close()

	out := make([]*events.SecurityEvent, 0, limit)
	for rows.Next() {
		var doc []byte
		if err := rows.Scan(&doc); err != nil {
			return nil, 0, fmt.Errorf("storage: scan event: %w", err)
		}
		var ev events.SecurityEvent
		if err := json.Unmarshal(doc, &ev); err != nil {
			return nil, 0, fmt.Errorf("storage: decode event: %w", err)
		}
		out = append(out, &ev)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("storage: iterate events: %w", err)
	}
	return out, total, nil
}

// CountEvents implements Store.
func (s *PostgresStore) CountEvents(ctx context.Context) (int, error) {
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM security_events`).Scan(&total); err != nil {
		return 0, fmt.Errorf("storage: count events: %w", err)
	}
	return total, nil
}

// SaveIncident implements Store as an upsert: correlation rewrites an incident
// in full every time evidence changes.
func (s *PostgresStore) SaveIncident(ctx context.Context, inc *incidents.Incident) error {
	if inc == nil || inc.ID == "" {
		return fmt.Errorf("storage: incident requires an id")
	}
	doc, err := json.Marshal(inc)
	if err != nil {
		return fmt.Errorf("storage: encode incident: %w", err)
	}
	const q = `
		INSERT INTO incidents (
			id, schema_version, title, status, severity, risk_score, confidence,
			first_seen, last_seen, updated_at, primary_identity, document
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (id) DO UPDATE SET
			title = EXCLUDED.title,
			status = EXCLUDED.status,
			severity = EXCLUDED.severity,
			risk_score = EXCLUDED.risk_score,
			confidence = EXCLUDED.confidence,
			first_seen = EXCLUDED.first_seen,
			last_seen = EXCLUDED.last_seen,
			updated_at = EXCLUDED.updated_at,
			primary_identity = EXCLUDED.primary_identity,
			document = EXCLUDED.document`
	_, err = s.pool.Exec(ctx, q,
		inc.ID, inc.SchemaVersion, inc.Title, string(inc.Status), string(inc.Severity),
		inc.RiskScore, inc.Confidence, inc.FirstSeen, inc.LastSeen, inc.UpdatedAt,
		nullable(inc.PrimaryIdentity), doc)
	if err != nil {
		return fmt.Errorf("storage: upsert incident: %w", err)
	}
	return nil
}

// GetIncident implements Store.
func (s *PostgresStore) GetIncident(ctx context.Context, id string) (*incidents.Incident, error) {
	var doc []byte
	err := s.pool.QueryRow(ctx, `SELECT document FROM incidents WHERE id = $1`, id).Scan(&doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: query incident: %w", err)
	}
	var inc incidents.Incident
	if err := json.Unmarshal(doc, &inc); err != nil {
		return nil, fmt.Errorf("storage: decode incident: %w", err)
	}
	return &inc, nil
}

// ListIncidents implements Store.
func (s *PostgresStore) ListIncidents(ctx context.Context, filter IncidentFilter) ([]*incidents.Incident, int, error) {
	filter = filter.Normalize()

	// Predicates are assembled from a fixed set of clauses with bound
	// parameters; no caller-supplied text ever reaches the SQL text itself.
	var (
		clauses []string
		args    []any
	)
	if filter.Status != "" {
		args = append(args, filter.Status)
		clauses = append(clauses, fmt.Sprintf("status = $%d", len(args)))
	}
	if filter.Severity != "" {
		args = append(args, filter.Severity)
		clauses = append(clauses, fmt.Sprintf("severity = $%d", len(args)))
	}
	if filter.MinRiskScore > 0 {
		args = append(args, filter.MinRiskScore)
		clauses = append(clauses, fmt.Sprintf("risk_score >= $%d", len(args)))
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}

	var total int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM incidents`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("storage: count incidents: %w", err)
	}

	args = append(args, filter.Limit, filter.Offset)
	q := fmt.Sprintf(
		`SELECT document FROM incidents%s ORDER BY last_seen DESC, id DESC LIMIT $%d OFFSET $%d`,
		where, len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("storage: query incidents: %w", err)
	}
	defer rows.Close()

	out := make([]*incidents.Incident, 0, filter.Limit)
	for rows.Next() {
		var doc []byte
		if err := rows.Scan(&doc); err != nil {
			return nil, 0, fmt.Errorf("storage: scan incident: %w", err)
		}
		var inc incidents.Incident
		if err := json.Unmarshal(doc, &inc); err != nil {
			return nil, 0, fmt.Errorf("storage: decode incident: %w", err)
		}
		out = append(out, &inc)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("storage: iterate incidents: %w", err)
	}
	return out, total, nil
}

// querier is the overlap between a connection pool and a transaction.
//
// Both pgxpool.Pool and pgx.Tx provide these three methods, so a write can be
// expressed once and then run either on its own or as part of a larger unit.
// The alternative — a second copy of each statement for the transactional
// path — is how the two copies end up disagreeing about what a column means.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// SaveActionWithAudit implements Store.
//
// The response action and the entries describing its evaluation are written in
// one transaction, so the trail cannot disagree with the record it describes.
// A response action with no audit entry is a change nobody can account for; an
// audit entry naming an action that was never written points at nothing.
//
// Note what is NOT inside the transaction: the policy evaluation. It happens
// before this is called, because holding a database transaction open across a
// call to another service ties one system's connection budget to another
// system's latency.
func (s *PostgresStore) SaveActionWithAudit(ctx context.Context, action *incidents.ResponseAction, entries []*audit.Entry) error {
	return s.inTx(ctx, func(tx querier) error {
		// The chain lock is taken before saveAction so that every transaction
		// touching audit takes it first. Action ids are unique per request and
		// same-row contention is vanishingly unlikely — which is exactly the
		// "it would never happen in practice" that does not count as a bound.
		head, err := lockAuditChainHead(ctx, tx)
		if err != nil {
			return err
		}
		if action != nil {
			if err := saveAction(ctx, tx, action); err != nil {
				return err
			}
		}
		for _, entry := range entries {
			if err := appendAudit(ctx, tx, &head, entry); err != nil {
				return err
			}
		}
		return nil
	})
}

// inTx runs fn inside a transaction, rolling back on any error.
//
// The rollback uses context.WithoutCancel: when the failure is a cancelled or
// timed-out request, a rollback issued on that same dead context cannot be
// delivered, and the transaction would be left for the server to reap.
func (s *PostgresStore) inTx(ctx context.Context, fn func(querier) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("storage: begin transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("storage: commit transaction: %w", err)
	}
	return nil
}

// SaveAction implements Store.
func (s *PostgresStore) SaveAction(ctx context.Context, action *incidents.ResponseAction) error {
	return saveAction(ctx, s.pool, action)
}

// saveAction writes a response action through q, which may be the pool or a
// transaction.
func saveAction(ctx context.Context, q querier, action *incidents.ResponseAction) error {
	if action == nil || action.ID == "" {
		return fmt.Errorf("storage: response action requires an id")
	}
	doc, err := json.Marshal(action)
	if err != nil {
		return fmt.Errorf("storage: encode response action: %w", err)
	}
	const stmt = `
		INSERT INTO response_actions (
			id, incident_id, action_type, mode, status, requested_by, created_at, document
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (id) DO UPDATE SET
			status = EXCLUDED.status,
			document = EXCLUDED.document`
	_, err = q.Exec(ctx, stmt,
		action.ID, action.IncidentID, action.ActionType, string(action.Mode),
		string(action.Status), action.RequestedBy, action.CreatedAt, doc)
	if err != nil {
		return fmt.Errorf("storage: upsert response action: %w", err)
	}
	return nil
}

// GetAction implements Store.
func (s *PostgresStore) GetAction(ctx context.Context, id string) (*incidents.ResponseAction, error) {
	var doc []byte
	err := s.pool.QueryRow(ctx, `SELECT document FROM response_actions WHERE id = $1`, id).Scan(&doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: query response action: %w", err)
	}
	var action incidents.ResponseAction
	if err := json.Unmarshal(doc, &action); err != nil {
		return nil, fmt.Errorf("storage: decode response action: %w", err)
	}
	return &action, nil
}

// ListActions implements Store.
func (s *PostgresStore) ListActions(ctx context.Context, incidentID string, limit, offset int) ([]*incidents.ResponseAction, int, error) {
	limit = ClampLimit(limit)
	if offset < 0 {
		offset = 0
	}
	where := ""
	args := []any{}
	if incidentID != "" {
		args = append(args, incidentID)
		where = " WHERE incident_id = $1"
	}
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM response_actions`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("storage: count response actions: %w", err)
	}
	args = append(args, limit, offset)
	q := fmt.Sprintf(
		`SELECT document FROM response_actions%s ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d`,
		where, len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("storage: query response actions: %w", err)
	}
	defer rows.Close()

	out := make([]*incidents.ResponseAction, 0, limit)
	for rows.Next() {
		var doc []byte
		if err := rows.Scan(&doc); err != nil {
			return nil, 0, fmt.Errorf("storage: scan response action: %w", err)
		}
		var action incidents.ResponseAction
		if err := json.Unmarshal(doc, &action); err != nil {
			return nil, 0, fmt.Errorf("storage: decode response action: %w", err)
		}
		out = append(out, &action)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("storage: iterate response actions: %w", err)
	}
	return out, total, nil
}

// Append implements audit.Sink. The database assigns the sequence, so ordering
// is decided by PostgreSQL rather than by whichever replica happened to write.
// chainHead is the chain state one audit-writing transaction carries between
// the entries it writes.
type chainHead struct {
	chainID  string
	prevHash string // "" when the chain has no entries yet, i.e. the genesis prev_hash
	sequence int64
}

// lockAuditChainHead takes the chain lock and returns the hash the next entry
// must link to.
//
// The lock is taken BEFORE the head is read and is held to commit. Releasing it
// after the read would let two writers each hold a valid predecessor and insert
// in either order, at which point nextval order and chain order diverge — and
// ORDER BY sequence ASC, which is what verify walks, would stop being chain
// order.
//
// Every transaction that writes audit takes this first, before any other row
// lock, so audit writers are totally ordered against each other and ordered
// against response_actions in one direction only. There is no cycle to
// deadlock on.
func lockAuditChainHead(ctx context.Context, q querier) (chainHead, error) {
	var h chainHead
	err := q.QueryRow(ctx, `
		SELECT chain_id, head_sequence
		FROM audit_chain_head WHERE only_row FOR UPDATE`,
	).Scan(&h.chainID, &h.sequence)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return h, fmt.Errorf("storage: audit_chain_head has no row, so audit writes cannot be serialised; " +
			"run the schema migration against this database")
	case err != nil:
		return h, fmt.Errorf("storage: lock audit chain head: %w", err)
	}

	// The predecessor comes from the TRAIL, not from head_hash.
	//
	// This is the difference between a tripwire and a kill switch. head_hash
	// sits in the one table in this subsystem with no append-only trigger, and
	// the service's own role must be able to update it. Deriving prev_hash from
	// it would mean that a single UPDATE putting any already-claimed hash there
	// makes every subsequent INSERT collide with uq_audit_log_chain_prev — and
	// since recordAudit logs a failed audit write and carries on, the whole
	// trail would go silent with nothing anywhere saying so. One statement, and
	// GRIEFER stops recording.
	//
	// Read from audit_log instead and head_hash cannot stop anything. A wrong
	// value there is then exactly what it should be: a discrepancy verify
	// reports, in a row the chain does not depend on.
	var tail *string
	err = q.QueryRow(ctx, `
		SELECT entry_hash FROM audit_log
		 WHERE chain_id = $1 AND entry_hash IS NOT NULL
		 ORDER BY sequence DESC LIMIT 1`, h.chainID).Scan(&tail)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		h.prevHash = audit.GenesisPrevHash
	case err != nil:
		return h, fmt.Errorf("storage: read audit chain tail: %w", err)
	default:
		if tail != nil {
			h.prevHash = *tail
		}
	}
	return h, nil
}

// Append implements audit.Sink.
//
// This is a transaction where it used to be one autocommit INSERT on the pool,
// because a chain link cannot be computed from a head another writer may
// already have moved. The cost is real and is recorded in ADR 0007: every audit
// write against this database now serialises on one row lock.
func (s *PostgresStore) Append(ctx context.Context, entry *audit.Entry) error {
	return s.inTx(ctx, func(tx querier) error {
		head, err := lockAuditChainHead(ctx, tx)
		if err != nil {
			return err
		}
		return appendAudit(ctx, tx, &head, entry)
	})
}

// appendAudit writes one audit entry through q, which must be a transaction
// holding the chain-head lock, and advances head to the entry it wrote.
func appendAudit(ctx context.Context, q querier, head *chainHead, entry *audit.Entry) error {
	// First, and unchanged: the conformance suite and the atomicity suite both
	// depend on a missing id being refused before anything else is examined.
	if entry == nil || entry.ID == "" {
		return fmt.Errorf("storage: audit entry requires an id")
	}
	// Sanitise before hashing, so that what is hashed is what is stored.
	audit.SanitiseEntry(entry)
	details, _, canonical, err := audit.CanonicalDetails(entry.Details)
	if err != nil {
		return fmt.Errorf("storage: canonicalise audit details: %w", err)
	}
	// Belt and braces for an entry built by hand rather than by Prepare, which
	// is every entry the store-level tests write.
	entry.Timestamp = entry.Timestamp.UTC().Truncate(time.Microsecond)
	entry.ChainID, entry.PrevHash = head.chainID, head.prevHash
	entry.EntryHash = audit.ChainHash(head.chainID, head.prevHash, entry, canonical)

	const stmt = `
		INSERT INTO audit_log (
			id, occurred_at, actor, actor_role, action, subject_type, subject_id, outcome, reason, request_id, details,
			chain_id, prev_hash, entry_hash, hash_version
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		RETURNING sequence`
	err = q.QueryRow(ctx, stmt,
		entry.ID, entry.Timestamp, entry.Actor, nullable(entry.ActorRole), entry.Action, entry.SubjectType,
		entry.SubjectID, entry.Outcome, entry.Reason, nullable(entry.RequestID), details,
		entry.ChainID, entry.PrevHash, entry.EntryHash, audit.ChainHashVersion,
	).Scan(&entry.Sequence)
	if err != nil {
		return fmt.Errorf("storage: append audit entry: %w", err)
	}

	// Per entry rather than once at the end of the transaction. Once at the end
	// is one fewer round trip and one forgotten call away from a stale head,
	// and a stale head is a fork rather than a slow query.
	if _, err := q.Exec(ctx, `
		UPDATE audit_chain_head SET head_sequence = $1, head_hash = $2, updated_at = now()
		WHERE only_row`, entry.Sequence, entry.EntryHash); err != nil {
		return fmt.Errorf("storage: advance audit chain head: %w", err)
	}
	head.prevHash, head.sequence = entry.EntryHash, entry.Sequence
	return nil
}

// List implements audit.Sink, oldest first.
func (s *PostgresStore) List(ctx context.Context, limit, offset int) ([]*audit.Entry, int, error) {
	limit = ClampLimit(limit)
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("storage: count audit entries: %w", err)
	}
	const q = `
		SELECT sequence, id, occurred_at, actor, COALESCE(actor_role, ''), action,
		       subject_type, subject_id, outcome, reason, COALESCE(request_id, ''), details,
		       COALESCE(chain_id, ''), COALESCE(prev_hash, ''), COALESCE(entry_hash, '')
		FROM audit_log ORDER BY sequence ASC LIMIT $1 OFFSET $2`
	rows, err := s.pool.Query(ctx, q, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("storage: query audit entries: %w", err)
	}
	defer rows.Close()

	out := make([]*audit.Entry, 0, limit)
	for rows.Next() {
		var (
			entry   audit.Entry
			details []byte
		)
		if err := rows.Scan(&entry.Sequence, &entry.ID, &entry.Timestamp, &entry.Actor,
			&entry.ActorRole, &entry.Action, &entry.SubjectType, &entry.SubjectID,
			&entry.Outcome, &entry.Reason, &entry.RequestID, &details,
			&entry.ChainID, &entry.PrevHash, &entry.EntryHash); err != nil {
			return nil, 0, fmt.Errorf("storage: scan audit entry: %w", err)
		}
		if len(details) > 0 {
			// UseNumber, not a plain Unmarshal. Without it a JSON integer past
			// 2^53 decodes to the nearest float64, so the trail would report a
			// number its producer did not write — and the memory store, which
			// keeps the caller's value, would disagree with this one.
			dec := json.NewDecoder(bytes.NewReader(details))
			dec.UseNumber()
			if err := dec.Decode(&entry.Details); err != nil {
				return nil, 0, fmt.Errorf("storage: decode audit details: %w", err)
			}
		}
		entry.Timestamp = entry.Timestamp.UTC()
		out = append(out, &entry)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("storage: iterate audit entries: %w", err)
	}
	return out, total, nil
}

// nullable converts an empty string into a SQL NULL so that "absent" and
// "empty" stay distinguishable in the database.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
