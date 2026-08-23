-- GRIEFER v0.1 schema.
--
-- Shape note: each table stores indexed scalar columns for the fields GRIEFER
-- filters and orders by, plus the full domain object as JSONB. That is a
-- deliberate v0.1 trade-off — it keeps the Go model and the database in step
-- while the model is still moving. A normalized relational model for entities
-- and edges arrives with the persistent Security Graph in milestone M2.

CREATE TABLE IF NOT EXISTS security_events (
    id              TEXT PRIMARY KEY,
    schema_version  TEXT        NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL,
    source_type     TEXT        NOT NULL,
    source_name     TEXT        NOT NULL,
    event_type      TEXT        NOT NULL,
    category        TEXT        NOT NULL,
    severity        TEXT        NOT NULL,
    actor_key       TEXT,
    correlation_id  TEXT,
    document        JSONB       NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_security_events_received_at ON security_events (received_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_actor_key   ON security_events (actor_key);
CREATE INDEX IF NOT EXISTS idx_security_events_category    ON security_events (category);

CREATE TABLE IF NOT EXISTS incidents (
    id               TEXT PRIMARY KEY,
    schema_version   TEXT             NOT NULL,
    title            TEXT             NOT NULL,
    status           TEXT             NOT NULL,
    severity         TEXT             NOT NULL,
    risk_score       INTEGER          NOT NULL,
    confidence       DOUBLE PRECISION NOT NULL,
    first_seen       TIMESTAMPTZ      NOT NULL,
    last_seen        TIMESTAMPTZ      NOT NULL,
    updated_at       TIMESTAMPTZ      NOT NULL,
    primary_identity TEXT,
    document         JSONB            NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents (last_seen DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status    ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity  ON incidents (severity);

CREATE TABLE IF NOT EXISTS response_actions (
    id           TEXT PRIMARY KEY,
    incident_id  TEXT        NOT NULL,
    action_type  TEXT        NOT NULL,
    mode         TEXT        NOT NULL,
    status       TEXT        NOT NULL,
    requested_by TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    document     JSONB       NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_response_actions_incident ON response_actions (incident_id, created_at DESC);

-- The audit trail is append-only.
--
-- The application never issues an UPDATE or DELETE against this table: the Go
-- interface (audit.Sink) exposes only Append and List. The trigger below is
-- defence in depth against a future code path — or a careless psql session —
-- that tries anyway.
--
-- This is tamper-RESISTANT, not tamper-EVIDENT. A role with DDL rights can drop
-- the trigger. Hash-chaining entries so that removal is detectable is milestone
-- M4; see docs/SAFETY_MODEL.md.
CREATE TABLE IF NOT EXISTS audit_log (
    sequence     BIGSERIAL PRIMARY KEY,
    id           TEXT        NOT NULL UNIQUE,
    occurred_at  TIMESTAMPTZ NOT NULL,
    actor        TEXT        NOT NULL,
    action       TEXT        NOT NULL,
    subject_type TEXT        NOT NULL,
    subject_id   TEXT        NOT NULL DEFAULT '',
    outcome      TEXT        NOT NULL,
    reason       TEXT        NOT NULL DEFAULT '',
    request_id   TEXT,
    details      JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_log_action  ON audit_log (action);
CREATE INDEX IF NOT EXISTS idx_audit_log_subject ON audit_log (subject_type, subject_id);

CREATE OR REPLACE FUNCTION griefer_audit_log_is_append_only() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'griefer: audit_log is append-only (attempted %)', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'audit_log_append_only'
          AND tgrelid = 'audit_log'::regclass
    ) THEN
        CREATE TRIGGER audit_log_append_only
            BEFORE UPDATE OR DELETE ON audit_log
            FOR EACH ROW EXECUTE FUNCTION griefer_audit_log_is_append_only();
    END IF;
END;
$$;
