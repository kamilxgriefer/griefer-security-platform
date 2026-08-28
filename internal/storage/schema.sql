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
-- The trigger is tamper-RESISTANT: a role with DDL rights can drop it. The
-- chain columns below are what make an alteration DETECTABLE after the fact --
-- though not attributable, since the chain lives in this same database and no
-- secret enters it. See docs/adr/0007-hash-chained-audit-without-anchor.md.
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

-- actor_role records the role held at the time of the entry.
--
-- Added after the table shipped, so it is an additive ALTER rather than a
-- column in the CREATE above: an existing deployment must gain the column
-- without its table being dropped and rebuilt. Rows written before this
-- migration keep NULL, which reads as "unknown" rather than as a false claim
-- that they were written by an analyst.
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS actor_role TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_log_action  ON audit_log (action);
CREATE INDEX IF NOT EXISTS idx_audit_log_subject ON audit_log (subject_type, subject_id);
-- The trail is read newest-first and is filtered by who acted and by which
-- request produced it; without these, every such read is a sequential scan.
CREATE INDEX IF NOT EXISTS idx_audit_log_occurred_at ON audit_log (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor       ON audit_log (actor);
CREATE INDEX IF NOT EXISTS idx_audit_log_request_id  ON audit_log (request_id) WHERE request_id IS NOT NULL;

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

-- prev_hash and entry_hash chain each entry to its predecessor.
--
-- Additive ALTERs rather than columns in the CREATE above, for the reason
-- actor_role gives: a deployed database must gain them without being rebuilt.
--
-- Rows written before this migration keep NULL in all four, and that is where
-- they stay. Filling them in means an UPDATE, which the trigger below refuses,
-- so a backfill would have to drop the guarantee it claims to strengthen. It
-- would also prove nothing: hashes computed today over rows written last year
-- attest only that those rows hash to what they say today, and anyone with the
-- rights to run the backfill had the rights to alter the rows first. NULL reads
-- as "outside the chain" -- not as "verified", and not as "broken".
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS chain_id   TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash  TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS entry_hash TEXT;

-- hash_version records which canonical form produced entry_hash. A verifier
-- that meets a version it does not implement reports that row unverifiable,
-- never broken: "this binary is older than that row" and "someone edited that
-- row" must not look the same to whoever was woken up.
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS hash_version SMALLINT;

-- Half a link reads as a break at verify time for a row nobody touched. This
-- catches a future code path that writes some of the four and not the rest; it
-- does nothing about an attacker, who can write all four.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'audit_log_chain_link_is_whole'
          AND conrelid = 'audit_log'::regclass
    ) THEN
        ALTER TABLE audit_log ADD CONSTRAINT audit_log_chain_link_is_whole
            CHECK (num_nulls(chain_id, prev_hash, entry_hash, hash_version) IN (0, 4));
    END IF;
END;
$$;

-- There is deliberately NO uniqueness constraint on (chain_id, prev_hash).
--
-- One was tried. It refuses the SECOND row to claim a predecessor -- and by
-- construction that second row is GRIEFER's, because whoever bypasses the head
-- lock inserts first. Anyone holding INSERT could therefore claim the current
-- tail's hash with one statement, at any sequence number they liked, and every
-- audit write after it would be refused. recordAudit logs a failed write and
-- carries on, so the trail would simply go quiet.
--
-- Refusing to record is the failure this subsystem exists to prevent, and a
-- constraint that turns one INSERT into permanent silence is worth less than
-- what it was buying. What it was buying is already covered: a row inserted
-- mid-chain leaves the row after it linking to a predecessor that is no longer
-- its neighbour, which the linkage walk reports as link_mismatch.
DROP INDEX IF EXISTS uq_audit_log_chain_prev;

-- Every append reads the chain's newest entry to find its predecessor, because
-- deriving that from audit_chain_head would let one UPDATE of a trigger-free
-- row stop the trail. Without this index that read walks back over the primary
-- key from the end of the table.
CREATE INDEX IF NOT EXISTS idx_audit_log_chain_tail
    ON audit_log (chain_id, sequence DESC) WHERE entry_hash IS NOT NULL;

-- audit_chain_head is a pointer, not a record, which is why it carries no
-- append-only trigger and is the one table in this subsystem that is updated.
--
-- It does two jobs. The FOR UPDATE lock on its single row is what stops two
-- concurrent appends reading the same head and both claiming it; unlike a lock
-- on the newest audit_log row it exists when the trail is empty, which is
-- exactly when the genesis race would otherwise happen. And a head that is
-- ahead of the trail is the only thing inside this database that distinguishes
-- a truncated or partially restored trail from an intact one, because a trail
-- with its tail removed is a shorter chain whose every link still checks out.
--
-- Someone who can rewrite this row can hide that signal. They can also rewrite
-- audit_log, so this removes a tripwire rather than opening a door -- but it is
-- a tripwire against accident and partial restore, not against an adversary,
-- and it must not be described as more.
CREATE TABLE IF NOT EXISTS audit_chain_head (
    only_row      BOOLEAN     PRIMARY KEY DEFAULT TRUE CHECK (only_row),
    chain_id      TEXT        NOT NULL,
    head_sequence BIGINT      NOT NULL DEFAULT 0,
    head_hash     TEXT,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- chain_id is minted once per database and never changes. Two databases that
-- disagree about it hold two different trails however alike their contents
-- look, which is what makes a restore into the wrong DSN visible.
INSERT INTO audit_chain_head (only_row, chain_id)
VALUES (TRUE, 'chn-' || gen_random_uuid()::text)
ON CONFLICT (only_row) DO NOTHING;
