package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
)

// Statuses a chain verification can report.
//
// A status rather than a boolean, and `empty` distinct from `consistent`,
// because an empty chain IS a valid chain: TRUNCATE is the one complete form of
// audit destruction the chain cannot detect, and a green result there would be
// the most misleading thing this check could say.
const (
	ChainConsistent   = "consistent"
	ChainBroken       = "broken"
	ChainUnchained    = "unchained"    // rows exist, none of them carry a hash
	ChainUnverifiable = "unverifiable" // a hash_version this build does not implement
	ChainEmpty        = "empty"        // no rows at all
)

// Kinds of break, each naming a different thing that happened.
const (
	// BreakMissingPredecessor is what deleting a PREFIX of the trail looks
	// like: the oldest surviving entry names a predecessor that is not there.
	BreakMissingPredecessor = "missing_predecessor"
	// BreakLinkMismatch is an entry whose prev_hash is not its predecessor's
	// entry_hash — a row removed or inserted mid-chain.
	BreakLinkMismatch = "link_mismatch"
	// BreakContentMismatch is an entry whose stored hash does not match its own
	// content: edited without rehashing.
	BreakContentMismatch = "content_mismatch"
	// BreakUnexpectedGenesis is an entry claiming to start the chain from a
	// position that is not the start.
	BreakUnexpectedGenesis = "unexpected_genesis"
	// BreakUnchainedAfterStart is a row with no hash sitting above the first
	// chained row. Every row a current binary writes is chained, so this one
	// was not written by a current binary.
	BreakUnchainedAfterStart = "unchained_after_chain_start"
	// BreakForeignChain is a chained row belonging to a chain that is not this
	// database's.
	//
	// It is its own kind because such a row survives both other checks: linkage
	// walks a single chain_id, so a foreign row is not in the walk at all, and
	// content recomputes each row against its OWN chain_id, so its hashes check
	// out. A restore that merged two trails is the common cause.
	//
	// What it does NOT close, and must not be read as closing: an insertion
	// that uses THIS database's chain_id and computes its hashes correctly.
	// Nothing here can. The canonical form is in this repository and no secret
	// enters it, so anyone who can INSERT can also compute a well-formed link —
	// which is the same limit docs/SAFETY_MODEL.md states about rewriting, seen
	// from the adding side rather than the altering side.
	BreakForeignChain = "foreign_chain"
)

// Warnings a report can carry alongside a status.
const (
	// WarnRecordedHeadAhead is orthogonal to the status and can appear while
	// the chain is perfectly consistent. That combination is the signature of
	// truncation or a partial restore: the surviving rows really are
	// consistent, there are just fewer of them.
	WarnRecordedHeadAhead = "recorded_head_ahead_of_trail"
	// WarnUnknownHashVersion marks rows this build cannot recompute. Linkage
	// still runs over them, because linkage compares stored hashes to stored
	// hashes and never recomputes.
	WarnUnknownHashVersion = "unknown_hash_version_present"
	// WarnMemoryStore says the answer describes process memory: no trigger, no
	// durability, and a chain recomputed by the process that wrote it.
	WarnMemoryStore = "memory_store_chain_is_not_durable"
	// WarnContentWindowIsPartial says the content check saw fewer entries than
	// the chain holds.
	//
	// Linkage is full-scope; content is not, because it must decode and rehash
	// each row. Without this warning a `consistent` status reads as "every
	// entry was recomputed", when an entry edited without rehashing below the
	// window was never looked at. The window's own range is in content.
	WarnContentWindowIsPartial = "content_check_covered_part_of_the_trail"
	// WarnContentWindowIsEmpty says the content check recomputed nothing at
	// all, which is what an offset past the end of the trail produces.
	WarnContentWindowIsEmpty = "content_check_covered_no_entries"
	// WarnRecordedHeadDiverged covers the other directions the recorded head
	// can be wrong: behind the trail, or level with it while naming a different
	// hash. Neither can happen from ordinary writing — the head advances in the
	// same transaction as the entry — so either means the row was written by
	// something other than an append.
	WarnRecordedHeadDiverged = "recorded_head_disagrees_with_trail"
)

// AuditChainAttests is returned on every report, including every green one.
//
// A machine reader can ignore it. Someone pasting a green response into an
// incident report cannot, and that is the reader it is for.
const AuditChainAttests = "Internal consistency of the entries examined. Not authenticity: " +
	"the chain is stored in the same database as the entries and no secret enters the computation, " +
	"so a role that can rewrite the table can recompute the chain with it. See docs/SAFETY_MODEL.md."

// AuditChainBreak locates the first thing that does not add up.
type AuditChainBreak struct {
	Kind     string `json:"kind"`
	Sequence int64  `json:"sequence"`
	ID       string `json:"id"`
	Detail   string `json:"detail"`
}

// AuditChainLinkage reports the cheap check: stored hashes against stored
// hashes, over the whole chain.
type AuditChainLinkage struct {
	Scope         string           `json:"scope"`
	Entries       int64            `json:"entries"`
	FirstSequence int64            `json:"first_sequence"`
	HeadSequence  int64            `json:"head_sequence"`
	HeadHash      string           `json:"head_hash"`
	Break         *AuditChainBreak `json:"break"`
}

// AuditChainContent reports the dear check: each entry's hash recomputed from
// its own content, over a bounded window.
//
// The window is reported so that a caller cannot read a windowed result as a
// whole-trail result.
type AuditChainContent struct {
	Scope        string           `json:"scope"`
	FromSequence int64            `json:"from_sequence"`
	ToSequence   int64            `json:"to_sequence"`
	Entries      int              `json:"entries"`
	Unverifiable int              `json:"unverifiable"`
	Break        *AuditChainBreak `json:"break"`
}

// AuditChainUnchained counts rows written before the chain existed. They are
// covered by neither check, which is not the same as being broken.
type AuditChainUnchained struct {
	Entries      int64  `json:"entries"`
	LastSequence int64  `json:"last_sequence"`
	Note         string `json:"note"`
}

// AuditChainRecordedHead is the head the database recorded as it wrote, which
// is the only thing inside the database that can be ahead of the trail.
type AuditChainRecordedHead struct {
	Sequence     int64     `json:"sequence"`
	Hash         string    `json:"hash"`
	UpdatedAt    time.Time `json:"updated_at"`
	MatchesTrail bool      `json:"matches_trail"`
}

// AuditChainReport is the whole answer.
type AuditChainReport struct {
	Store     string              `json:"store"`
	ChainID   string              `json:"chain_id"`
	Status    string              `json:"status"`
	Warnings  []string            `json:"warnings"`
	Linkage   AuditChainLinkage   `json:"linkage"`
	Content   AuditChainContent   `json:"content"`
	Unchained AuditChainUnchained `json:"unchained"`
	// RecordedHead is nil on the memory store: there is no table there that
	// could be ahead of the trail.
	RecordedHead *AuditChainRecordedHead `json:"recorded_head"`
	// ExternallyAnchored is always false in v0.1, and is on the wire rather
	// than only in a document so that the missing half of the guarantee travels
	// with every response.
	ExternallyAnchored bool   `json:"externally_anchored"`
	Attests            string `json:"attests"`
}

const unchainedNote = "Written before the chain existed. Covered by neither check."

// newAuditChainReport returns a report with the fields that are the same
// whatever the store found.
func newAuditChainReport(store, chainID string) *AuditChainReport {
	return &AuditChainReport{
		Store:              store,
		ChainID:            chainID,
		Warnings:           []string{},
		Linkage:            AuditChainLinkage{Scope: "full"},
		Content:            AuditChainContent{Scope: "window"},
		Unchained:          AuditChainUnchained{Note: unchainedNote},
		ExternallyAnchored: false,
		Attests:            AuditChainAttests,
	}
}

// settleStatus picks the status from what the two checks found.
//
// Order matters: broken outranks unverifiable, which outranks unchained. An
// operator who has both a break and a row this binary cannot read needs to be
// told about the break.
func (r *AuditChainReport) settleStatus(totalEntries, chainedEntries int64) {
	// Said before the status is chosen, because the status alone cannot carry
	// it: `consistent` is the truth about what was examined, and how much that
	// was belongs beside it rather than folded into it.
	if chainedEntries > 0 {
		switch {
		case r.Content.Entries == 0:
			r.Warnings = append(r.Warnings, WarnContentWindowIsEmpty)
		case int64(r.Content.Entries) < chainedEntries:
			r.Warnings = append(r.Warnings, WarnContentWindowIsPartial)
		}
	}
	switch {
	case totalEntries == 0:
		r.Status = ChainEmpty
	case r.Linkage.Break != nil || r.Content.Break != nil:
		r.Status = ChainBroken
	case chainedEntries == 0:
		r.Status = ChainUnchained
	case r.Content.Unverifiable > 0:
		r.Status = ChainUnverifiable
	default:
		r.Status = ChainConsistent
	}
}

// ---------------------------------------------------------------------------
// PostgreSQL
// ---------------------------------------------------------------------------

// VerifyAuditChain implements Store.
//
// The whole report is assembled inside ONE read-only REPEATABLE READ
// transaction, so every statement in it sees the same trail.
//
// Run against the pool instead, each statement would get its own snapshot: an
// append committing between the chain-head read and the trail-head read makes
// a perfectly healthy trail report matches_trail false, with the recorded head
// BEHIND the trail — a combination that means nothing, has no row in the
// runbook, and would appear only under write load. An integrity check that
// cries wolf on a busy system is one nobody reads.
//
// READ ONLY is not decoration: it says on the transaction itself that
// verification cannot write, and the database enforces it.
func (s *PostgresStore) VerifyAuditChain(ctx context.Context, limit, offset int) (*AuditChainReport, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("storage: begin audit chain verification: %w", err)
	}
	// Rolled back, never committed — it wrote nothing. WithoutCancel so that a
	// cancelled request still releases the snapshot instead of leaving it for
	// the server to reap.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	return verifyAuditChain(ctx, tx, s.Kind(), limit, offset)
}

// verifyAuditChain runs against any querier, which is what lets a test forge
// entries inside a transaction, verify them, and roll back — proving detection
// without ever committing damage to a database another test package shares.
func verifyAuditChain(ctx context.Context, q querier, storeKind string, limit, offset int) (*AuditChainReport, error) {
	limit = ClampLimit(limit)
	if offset < 0 {
		offset = 0
	}

	var (
		chainID  string
		headSeq  int64
		headHash string
		headAt   time.Time
		nullHash *string
	)
	err := q.QueryRow(ctx, `
		SELECT chain_id, head_sequence, head_hash, updated_at FROM audit_chain_head WHERE only_row`,
	).Scan(&chainID, &headSeq, &nullHash, &headAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("storage: audit_chain_head has no row; run the schema migration against this database")
		}
		return nil, fmt.Errorf("storage: read audit chain head: %w", err)
	}
	if nullHash != nil {
		headHash = *nullHash
	}
	report := newAuditChainReport(storeKind, chainID)

	// --- counts ------------------------------------------------------------
	var totalEntries, chainedEntries, unchainedEntries, unchainedLast, firstChained, lastChained int64
	var lastChainedHash *string
	if err := q.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE entry_hash IS NOT NULL),
		       count(*) FILTER (WHERE entry_hash IS NULL),
		       COALESCE(max(sequence) FILTER (WHERE entry_hash IS NULL), 0),
		       COALESCE(min(sequence) FILTER (WHERE entry_hash IS NOT NULL), 0),
		       COALESCE(max(sequence) FILTER (WHERE entry_hash IS NOT NULL), 0)
		FROM audit_log`,
	).Scan(&totalEntries, &chainedEntries, &unchainedEntries, &unchainedLast, &firstChained, &lastChained); err != nil {
		return nil, fmt.Errorf("storage: count audit entries: %w", err)
	}
	if chainedEntries > 0 {
		if err := q.QueryRow(ctx,
			`SELECT entry_hash FROM audit_log WHERE sequence = $1`, lastChained).Scan(&lastChainedHash); err != nil {
			return nil, fmt.Errorf("storage: read trail head: %w", err)
		}
	}
	report.Unchained.Entries = unchainedEntries
	report.Unchained.LastSequence = unchainedLast
	report.Linkage.Entries = chainedEntries
	report.Linkage.FirstSequence = firstChained
	report.Linkage.HeadSequence = lastChained
	if lastChainedHash != nil {
		report.Linkage.HeadHash = *lastChainedHash
	}

	// --- linkage -----------------------------------------------------------
	//
	// One statement. lag() over an index-ordered input is pipelined, so the
	// LIMIT 1 stops the scan at the first mismatch; with no break it is one
	// ordered scan, bounded by the request context.
	if chainedEntries > 0 {
		var (
			seq      int64
			id       string
			prevHash string
			expected *string
		)
		err := q.QueryRow(ctx, `
			WITH chained AS (
			    SELECT sequence, id, prev_hash,
			           lag(entry_hash) OVER (ORDER BY sequence) AS expected
			    FROM audit_log
			    WHERE entry_hash IS NOT NULL AND chain_id = $1
			)
			SELECT sequence, id, prev_hash, expected
			FROM chained
			WHERE prev_hash IS DISTINCT FROM COALESCE(expected, '')
			ORDER BY sequence
			LIMIT 1`, chainID).Scan(&seq, &id, &prevHash, &expected)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			// No break.
		case err != nil:
			return nil, fmt.Errorf("storage: verify audit chain linkage: %w", err)
		default:
			report.Linkage.Break = classifyLinkageBreak(seq, id, prevHash, expected)
		}
	}

	// --- a hashless row above the chain start ------------------------------
	if chainedEntries > 0 && unchainedEntries > 0 {
		var strandedID *string
		var stranded *int64
		if err := q.QueryRow(ctx, `
			SELECT min(sequence) FROM audit_log
			 WHERE entry_hash IS NULL AND sequence > $1`, firstChained).Scan(&stranded); err != nil {
			return nil, fmt.Errorf("storage: scan for unchained entries after the chain start: %w", err)
		}
		if stranded != nil && report.Linkage.Break == nil {
			if err := q.QueryRow(ctx,
				`SELECT id FROM audit_log WHERE sequence = $1`, *stranded).Scan(&strandedID); err != nil {
				return nil, fmt.Errorf("storage: read unchained entry: %w", err)
			}
			id := ""
			if strandedID != nil {
				id = *strandedID
			}
			report.Linkage.Break = &AuditChainBreak{
				Kind: BreakUnchainedAfterStart, Sequence: *stranded, ID: id,
				Detail: "An entry with no hash sits above the first chained entry. Every row a current " +
					"binary writes is chained, so this one was not written by one — a mixed-version " +
					"deploy is the boring explanation, and a second writer is the other.",
			}
		}
	}

	// --- a chained row belonging to someone else's chain -------------------
	if chainedEntries > 0 {
		var foreignSeq *int64
		var foreignID, foreignChain *string
		ferr := q.QueryRow(ctx, `
			SELECT sequence, id, chain_id FROM audit_log
			 WHERE entry_hash IS NOT NULL AND chain_id IS DISTINCT FROM $1
			 ORDER BY sequence LIMIT 1`, chainID).Scan(&foreignSeq, &foreignID, &foreignChain)
		switch {
		case errors.Is(ferr, pgx.ErrNoRows):
			// Every chained row belongs to this chain.
		case ferr != nil:
			return nil, fmt.Errorf("storage: scan for foreign-chain entries: %w", ferr)
		default:
			if report.Linkage.Break == nil && foreignSeq != nil {
				id, foreign := "", ""
				if foreignID != nil {
					id = *foreignID
				}
				if foreignChain != nil {
					foreign = *foreignChain
				}
				report.Linkage.Break = &AuditChainBreak{
					Kind: BreakForeignChain, Sequence: *foreignSeq, ID: id,
					Detail: fmt.Sprintf("Entry belongs to chain %q, not to this database's chain %q. "+
						"A restore that merged two trails is the boring explanation; an inserted row is the other.",
						foreign, chainID),
				}
			}
		}
	}

	// --- content, over a bounded window ------------------------------------
	if err := verifyAuditContent(ctx, q, report, limit, offset); err != nil {
		return nil, err
	}

	// --- the recorded head -------------------------------------------------
	matches := headSeq == lastChained && headHash == report.Linkage.HeadHash
	report.RecordedHead = &AuditChainRecordedHead{
		Sequence: headSeq, Hash: headHash, UpdatedAt: headAt.UTC(), MatchesTrail: matches,
	}
	switch {
	case headSeq > lastChained:
		report.Warnings = append(report.Warnings, WarnRecordedHeadAhead)
	case !matches:
		// Behind the trail, or level with it under a different hash. The chain
		// no longer derives prev_hash from this row, so neither state stops
		// GRIEFER writing — but neither can arise from writing either.
		report.Warnings = append(report.Warnings, WarnRecordedHeadDiverged)
	}

	report.settleStatus(totalEntries, chainedEntries)
	return report, nil
}

// classifyLinkageBreak turns the row the linkage query returned into the thing
// that actually happened.
func classifyLinkageBreak(seq int64, id, prevHash string, expected *string) *AuditChainBreak {
	switch {
	case expected == nil && prevHash != audit.GenesisPrevHash:
		return &AuditChainBreak{
			Kind: BreakMissingPredecessor, Sequence: seq, ID: id,
			Detail: "The oldest chained entry names a predecessor that is not in the trail. " +
				"This is what removing a prefix of the trail looks like.",
		}
	case expected != nil && prevHash == audit.GenesisPrevHash:
		return &AuditChainBreak{
			Kind: BreakUnexpectedGenesis, Sequence: seq, ID: id,
			Detail: "An entry claims to start the chain from a position that is not the start.",
		}
	default:
		want := ""
		if expected != nil {
			want = *expected
		}
		return &AuditChainBreak{
			Kind: BreakLinkMismatch, Sequence: seq, ID: id,
			Detail: fmt.Sprintf("Entry links to %q; its predecessor hashes to %q.", prevHash, want),
		}
	}
}

// verifyAuditContent recomputes each entry's hash from its own content over a
// bounded window, newest first.
//
// It reads the raw details column as bytes and never goes through List: the
// point of hashing what the database actually holds is that there is nothing
// between those bytes and the hash.
func verifyAuditContent(ctx context.Context, q querier, report *AuditChainReport, limit, offset int) error {
	rows, err := q.Query(ctx, `
		SELECT sequence, id, occurred_at, actor, COALESCE(actor_role,''), action, subject_type,
		       subject_id, outcome, reason, COALESCE(request_id,''), details,
		       chain_id, prev_hash, entry_hash, COALESCE(hash_version, 0)
		FROM audit_log WHERE entry_hash IS NOT NULL
		ORDER BY sequence DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return fmt.Errorf("storage: read audit entries for content verification: %w", err)
	}
	defer rows.Close()

	sawUnknownVersion := false
	for rows.Next() {
		var (
			entry       audit.Entry
			details     []byte
			hashVersion int16
		)
		if err := rows.Scan(&entry.Sequence, &entry.ID, &entry.Timestamp, &entry.Actor,
			&entry.ActorRole, &entry.Action, &entry.SubjectType, &entry.SubjectID,
			&entry.Outcome, &entry.Reason, &entry.RequestID, &details,
			&entry.ChainID, &entry.PrevHash, &entry.EntryHash, &hashVersion); err != nil {
			return fmt.Errorf("storage: scan audit entry for content verification: %w", err)
		}
		if report.Content.Entries == 0 {
			report.Content.ToSequence = entry.Sequence
		}
		report.Content.FromSequence = entry.Sequence
		report.Content.Entries++

		if int(hashVersion) != audit.ChainHashVersion {
			// Reported unverifiable, never broken: this binary is older than
			// that row, which must not look like someone editing it.
			report.Content.Unverifiable++
			sawUnknownVersion = true
			continue
		}
		canonical, err := audit.CanonicalDetailsFromRaw(details)
		if err != nil {
			// The column holds JSON no GRIEFER write could have produced.
			if report.Content.Break == nil {
				report.Content.Break = &AuditChainBreak{
					Kind: BreakContentMismatch, Sequence: entry.Sequence, ID: entry.ID,
					Detail: "Details cannot be brought to canonical form: " + err.Error(),
				}
			}
			continue
		}
		// The row's OWN chain_id, not the current head's: its hash was computed
		// with the chain it was written into.
		want := audit.ChainHash(entry.ChainID, entry.PrevHash, &entry, canonical)
		if want != entry.EntryHash && report.Content.Break == nil {
			report.Content.Break = &AuditChainBreak{
				Kind: BreakContentMismatch, Sequence: entry.Sequence, ID: entry.ID,
				Detail: "The entry's stored hash does not match its content: edited without rehashing.",
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("storage: iterate audit entries for content verification: %w", err)
	}
	if sawUnknownVersion {
		report.Warnings = append(report.Warnings, WarnUnknownHashVersion)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

// VerifyAuditChain implements Store.
//
// Same window semantics as the PostgreSQL implementation, so the conformance
// suite tests one contract rather than two. RecordedHead is nil — there is no
// table here that could be ahead of the trail — and the warning says what the
// answer is worth.
func (s *MemoryStore) VerifyAuditChain(_ context.Context, limit, offset int) (*AuditChainReport, error) {
	limit = ClampLimit(limit)
	if offset < 0 {
		offset = 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	report := newAuditChainReport(s.Kind(), s.chainID)
	report.Warnings = append(report.Warnings, WarnMemoryStore)

	total := int64(len(s.auditLog))
	var chained int64
	for _, e := range s.auditLog {
		if e.EntryHash == "" {
			report.Unchained.Entries++
			report.Unchained.LastSequence = e.Sequence
			continue
		}
		chained++
		if report.Linkage.FirstSequence == 0 {
			report.Linkage.FirstSequence = e.Sequence
		}
		report.Linkage.HeadSequence = e.Sequence
		report.Linkage.HeadHash = e.EntryHash
	}
	report.Linkage.Entries = chained

	// --- linkage, over this chain's entries --------------------------------
	//
	// Scoped by chain_id, exactly as the PostgreSQL walk is. Unscoped, an entry
	// from another chain would break linkage here and be reported as a link
	// mismatch, where PostgreSQL skips it and reports it as foreign_chain --
	// two stores answering one contract with two different break kinds.
	expected := audit.GenesisPrevHash
	first := true
	for _, e := range s.auditLog {
		if e.EntryHash == "" || e.ChainID != s.chainID {
			continue
		}
		if e.PrevHash != expected && report.Linkage.Break == nil {
			var exp *string
			if !first {
				prev := expected
				exp = &prev
			}
			report.Linkage.Break = classifyLinkageBreak(e.Sequence, e.ID, e.PrevHash, exp)
		}
		expected = e.EntryHash
		first = false
	}

	// --- a chained row belonging to someone else's chain -------------------
	//
	// Unreachable through this store's own API, which stamps s.chainID on every
	// entry. It is implemented anyway so that the two stores answer the same
	// contract rather than merely passing the same tests.
	for _, e := range s.auditLog {
		if e.EntryHash == "" || e.ChainID == s.chainID {
			continue
		}
		if report.Linkage.Break == nil {
			report.Linkage.Break = &AuditChainBreak{
				Kind: BreakForeignChain, Sequence: e.Sequence, ID: e.ID,
				Detail: fmt.Sprintf("Entry belongs to chain %q, not to this store's chain %q.",
					e.ChainID, s.chainID),
			}
		}
		break
	}

	// --- content, over the same window shape: newest first ------------------
	window := make([]*audit.Entry, 0, len(s.auditLog))
	for i := len(s.auditLog) - 1; i >= 0; i-- {
		if s.auditLog[i].EntryHash != "" {
			window = append(window, s.auditLog[i])
		}
	}
	if offset < len(window) {
		end := offset + limit
		if end > len(window) {
			end = len(window)
		}
		window = window[offset:end]
	} else {
		window = nil
	}
	for i, e := range window {
		if i == 0 {
			report.Content.ToSequence = e.Sequence
		}
		report.Content.FromSequence = e.Sequence
		report.Content.Entries++
		_, _, canonical, err := audit.CanonicalDetails(e.Details)
		if err != nil {
			if report.Content.Break == nil {
				report.Content.Break = &AuditChainBreak{
					Kind: BreakContentMismatch, Sequence: e.Sequence, ID: e.ID,
					Detail: "Details cannot be brought to canonical form: " + err.Error(),
				}
			}
			continue
		}
		if audit.ChainHash(e.ChainID, e.PrevHash, e, canonical) != e.EntryHash && report.Content.Break == nil {
			report.Content.Break = &AuditChainBreak{
				Kind: BreakContentMismatch, Sequence: e.Sequence, ID: e.ID,
				Detail: "The entry's stored hash does not match its content.",
			}
		}
	}

	report.settleStatus(total, chained)
	return report, nil
}
