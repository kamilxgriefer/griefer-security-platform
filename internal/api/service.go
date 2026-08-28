// Package api exposes GRIEFER's HTTP surface and the service layer that
// orchestrates ingestion and policy-governed response.
package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/bus"
	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/graph"
	"github.com/kamilxgriefer/griefer-security-platform/internal/httpx"
	"github.com/kamilxgriefer/griefer-security-platform/internal/idgen"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
	"github.com/kamilxgriefer/griefer-security-platform/internal/policy"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
	"github.com/kamilxgriefer/griefer-security-platform/policies"
)

// Correlator is the subset of the correlation engine the service depends on.
// Declaring it here lets tests substitute a failing correlator to prove that
// ingestion survives a broken analysis path.
type Correlator interface {
	Process(ctx context.Context, ev *events.SecurityEvent) (*incidents.Incident, error)
}

// ErrIncidentNotFound is returned when an action references an unknown incident.
var ErrIncidentNotFound = errors.New("incident not found")

// Service holds GRIEFER's application logic.
type Service struct {
	store      storage.Store
	graph      *graph.Graph
	validator  *events.Validator
	normalizer *events.Normalizer
	correlator Correlator
	kernel     policy.Kernel
	auditor    *audit.Recorder
	publisher  bus.Publisher
	metrics    *Metrics
	logger     *slog.Logger
	now        func() time.Time

	// maxBatchEvents bounds a single batch submission independently of the
	// byte-level body limit: a small body can still hold thousands of tiny
	// events.
	maxBatchEvents int
	// ruleCount is reported on the status endpoint so an operator can tell a
	// running-but-ruleless deployment from a healthy one.
	ruleCount int
}

// ServiceOptions wires a Service. Every dependency is explicit: there is no
// package-level state and no hidden singleton, so a test builds exactly the
// system it means to exercise.
type ServiceOptions struct {
	Store      storage.Store
	Graph      *graph.Graph
	Validator  *events.Validator
	Normalizer *events.Normalizer
	Correlator Correlator
	Kernel     policy.Kernel
	Auditor    *audit.Recorder
	Publisher  bus.Publisher
	Metrics    *Metrics
	Logger     *slog.Logger
	Now        func() time.Time
	// MaxBatchEvents bounds POST /api/v1/events/batch. Defaults to 500.
	MaxBatchEvents int
	// RuleCount is the number of loaded detection rules, reported by the
	// status endpoint.
	RuleCount int
}

// NewService validates the wiring and returns a Service.
func NewService(opts ServiceOptions) (*Service, error) {
	switch {
	case opts.Store == nil:
		return nil, fmt.Errorf("api: store is required")
	case opts.Graph == nil:
		return nil, fmt.Errorf("api: graph is required")
	case opts.Validator == nil:
		return nil, fmt.Errorf("api: validator is required")
	case opts.Kernel == nil:
		return nil, fmt.Errorf("api: policy kernel is required")
	case opts.Auditor == nil:
		return nil, fmt.Errorf("api: audit recorder is required")
	case opts.Metrics == nil:
		return nil, fmt.Errorf("api: metrics are required")
	}
	normalizer := opts.Normalizer
	if normalizer == nil {
		normalizer = events.NewNormalizer()
	}
	publisher := opts.Publisher
	if publisher == nil {
		publisher = bus.NewNoopPublisher()
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	maxBatch := opts.MaxBatchEvents
	if maxBatch <= 0 {
		maxBatch = 500
	}
	return &Service{
		store: opts.Store, graph: opts.Graph, validator: opts.Validator,
		normalizer: normalizer, correlator: opts.Correlator, kernel: opts.Kernel,
		auditor: opts.Auditor, publisher: publisher, metrics: opts.Metrics,
		logger: logger, now: now, maxBatchEvents: maxBatch, ruleCount: opts.RuleCount,
	}, nil
}

// IngestResult reports what happened to one submitted event.
type IngestResult struct {
	EventID     string   `json:"event_id"`
	IncidentID  string   `json:"incident_id,omitempty"`
	RiskScore   int      `json:"risk_score,omitempty"`
	Quarantined []string `json:"quarantined_labels,omitempty"`
	// Degraded names subsystems that failed while handling this event. The
	// event was still accepted and persisted.
	Degraded []string `json:"degraded,omitempty"`
}

// Ingest validates, normalizes, stores and correlates a single raw event.
//
// The ordering here is the requirement, not an implementation detail: an event
// is durably stored BEFORE anything tries to reason about it. Correlation and
// the event bus are best-effort. An attacker who can crash the correlation path
// must not thereby stop GRIEFER from recording what they did.
func (s *Service) Ingest(ctx context.Context, raw []byte) (IngestResult, error) {
	requestID := httpx.RequestIDFromContext(ctx)

	ev, err := s.validator.Decode(raw)
	if err != nil {
		s.metrics.EventsRejected.WithLabelValues("schema").Inc()
		s.recordAudit(ctx, audit.Entry{
			Action: audit.ActionEventRejected, SubjectType: audit.SubjectEvent,
			Outcome: audit.OutcomeDenied, RequestID: requestID,
			Reason:  "event failed schema validation at the ingest trust boundary",
			Details: map[string]any{"error_kind": "schema_validation"},
		})
		return IngestResult{}, err
	}

	if _, err := s.normalizer.Normalize(ev); err != nil {
		s.metrics.EventsRejected.WithLabelValues("normalization").Inc()
		s.recordAudit(ctx, audit.Entry{
			Action: audit.ActionEventRejected, SubjectType: audit.SubjectEvent,
			SubjectID: ev.ID, Outcome: audit.OutcomeDenied, RequestID: requestID,
			Reason:  err.Error(),
			Details: map[string]any{"error_kind": "normalization"},
		})
		return IngestResult{}, err
	}

	result := IngestResult{EventID: ev.ID, Quarantined: ev.Quarantined}

	if err := s.store.SaveEvent(ctx, ev); err != nil {
		s.metrics.EventsRejected.WithLabelValues("storage").Inc()
		s.logger.ErrorContext(ctx, "failed to persist event",
			slog.String("request_id", requestID), slog.String("event_id", ev.ID),
			slog.String("error", err.Error()))
		// This was the ONE failure path in Ingest that recorded nothing.
		// Schema validation, normalization and correlation all leave an entry;
		// a persistence failure left only a log line, so the trail could not
		// distinguish "no such event was ever submitted" from "one was, and
		// GRIEFER could not keep it". A producer able to make this insert fail
		// therefore had a way to act without appearing in the record at all.
		//
		// The error text is deliberately NOT the reason: it is driver output,
		// and CONTRIBUTING.md keeps that out of anything a client can read. It
		// is already in the log, keyed by request id.
		s.recordAudit(ctx, audit.Entry{
			Action: audit.ActionEventRejected, SubjectType: audit.SubjectEvent,
			SubjectID: ev.ID, Outcome: audit.OutcomeFailure, RequestID: requestID,
			Reason: "event could not be persisted; it was not stored and has not been correlated",
			Details: map[string]any{
				"error_kind": "storage",
				// The emitter ResultPersistenceFailed was declared for and had
				// not had until now.
				"result":      audit.ResultPersistenceFailed,
				"source_type": string(ev.SourceType),
				"source_name": ev.SourceName,
			},
		})
		return IngestResult{}, fmt.Errorf("persist event: %w", err)
	}
	s.metrics.EventsIngested.WithLabelValues(string(ev.Category)).Inc()

	if len(ev.Quarantined) > 0 {
		// A producer trying to name a control-plane concept in telemetry is
		// itself a signal worth keeping.
		s.recordAudit(ctx, audit.Entry{
			Action: audit.ActionEventQuarantined, SubjectType: audit.SubjectEvent,
			SubjectID: ev.ID, Outcome: audit.OutcomeDenied, RequestID: requestID,
			Reason:  "telemetry contained reserved control-plane label keys; they were stripped before processing",
			Details: map[string]any{"quarantined_keys": ev.Quarantined, "source_name": ev.SourceName},
		})
	}

	// The graph is part of the recording path, not the reasoning path: it must
	// keep building even when correlation is unavailable.
	s.graph.Project(ev)

	if err := s.publisher.Publish(ctx, ev); err != nil {
		s.metrics.BusErrors.Inc()
		result.Degraded = append(result.Degraded, "event_bus")
		s.logger.WarnContext(ctx, "event bus publish failed; event was still persisted",
			slog.String("request_id", requestID), slog.String("event_id", ev.ID),
			slog.String("error", err.Error()))
	}

	if s.correlator != nil {
		inc, cerr := s.correlate(ctx, ev)
		switch {
		case cerr != nil:
			s.metrics.CorrelationErrors.Inc()
			result.Degraded = append(result.Degraded, "correlation")
			s.logger.ErrorContext(ctx, "correlation failed; event was still persisted",
				slog.String("request_id", requestID), slog.String("event_id", ev.ID),
				slog.String("error", cerr.Error()))
			s.recordAudit(ctx, audit.Entry{
				Action: audit.ActionCorrelationFailed, SubjectType: audit.SubjectEvent,
				SubjectID: ev.ID, Outcome: audit.OutcomeFailure, RequestID: requestID,
				Reason: "correlation engine returned an error; the event is stored and can be reprocessed",
			})
		case inc != nil:
			result.IncidentID = inc.ID
			result.RiskScore = inc.RiskScore
			s.metrics.IncidentsTouched.WithLabelValues("updated").Inc()
			s.recordAudit(ctx, audit.Entry{
				Action: audit.ActionIncidentUpdated, SubjectType: audit.SubjectIncident,
				SubjectID: inc.ID, Outcome: audit.OutcomeSuccess, RequestID: requestID,
				Reason: fmt.Sprintf("incident updated from event %s; risk score %d", ev.ID, inc.RiskScore),
				Details: map[string]any{
					"event_id":        ev.ID,
					"risk_score":      inc.RiskScore,
					"severity":        string(inc.Severity),
					"finding_count":   len(inc.Findings),
					"evidence_types":  categoryStrings(inc.EvidenceCategories()),
					"blast_radius":    inc.BlastRadius.Score,
					"critical_assets": inc.BlastRadius.CriticalAssets,
				},
			})
		}
	} else {
		result.Degraded = append(result.Degraded, "correlation")
	}

	s.recordAudit(ctx, audit.Entry{
		Action: audit.ActionEventIngested, SubjectType: audit.SubjectEvent,
		SubjectID: ev.ID, Outcome: audit.OutcomeSuccess, RequestID: requestID,
		Reason: fmt.Sprintf("event accepted from %s/%s", ev.SourceType, ev.SourceName),
		Details: map[string]any{
			"category": string(ev.Category), "severity": string(ev.Severity),
			"event_type": ev.EventType, "degraded": result.Degraded,
		},
	})
	return result, nil
}

// correlate isolates the correlation call so that a panic inside a detection
// rule degrades analysis instead of taking down ingestion.
func (s *Service) correlate(ctx context.Context, ev *events.SecurityEvent) (inc *incidents.Incident, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			inc = nil
			err = fmt.Errorf("correlation panicked: %v", rec)
		}
	}()
	return s.correlator.Process(ctx, ev)
}

func categoryStrings(in []events.Category) []string {
	out := make([]string, 0, len(in))
	for _, c := range in {
		out = append(out, string(c))
	}
	return out
}

// recordAudit writes an audit entry, logging rather than propagating a failure.
//
// Ingest and evaluate paths return their own primary error; an audit write
// failure must be loud but must not convert a completed, safe operation into a
// client-visible 500. It is surfaced through the audit_write_failures log and
// the /ready check on the store.
func (s *Service) recordAudit(ctx context.Context, entry audit.Entry) {
	if _, err := s.auditor.Record(ctx, entry); err != nil {
		s.logger.ErrorContext(ctx, "failed to write audit entry",
			slog.String("request_id", httpx.RequestIDFromContext(ctx)),
			slog.String("audit_action", entry.Action),
			slog.String("error", err.Error()))
	}
}

// ---------------------------------------------------------------------------
// Response actions
// ---------------------------------------------------------------------------

// EvaluateRequest is a request to have the Policy Kernel judge a proposed
// action.
//
// Note what the client CANNOT supply: whether the action is destructive,
// whether it is reversible, or what would roll it back. Those are resolved
// server-side from the action catalog. A client that could assert them could
// talk the Policy Kernel into anything.
type EvaluateRequest struct {
	IncidentID  string `json:"incident_id"`
	ActionType  string `json:"action_type"`
	Mode        string `json:"mode"`
	RequestedBy string `json:"requested_by"`
	// Automated marks the request as machine-initiated. Human-initiated
	// requests are still policy-gated; the flag only tells the policy which bar
	// to apply.
	Automated bool `json:"automated"`
}

// EvaluateAction runs a proposed action through the Policy Kernel and records
// the outcome. It never contacts an external system.
//
// Every path out of this function leaves an audit entry, including the ones
// that reject the request before a policy is consulted. An evaluation that
// produced no trail is indistinguishable, later, from one that never happened.
func (s *Service) EvaluateAction(ctx context.Context, req EvaluateRequest) (*incidents.ResponseAction, error) {
	requestID := httpx.RequestIDFromContext(ctx)

	// The operator comes from the request context, where PrincipalMiddleware
	// put it after the service credential was verified. req.RequestedBy is
	// deliberately NOT read: it is a body field, and a body is written by
	// whoever made the call. Attributing an action to a value the caller chose
	// makes the trail look authoritative while saying nothing.
	principal := httpx.PrincipalFromContext(ctx)
	actor := principal.Subject
	if actor == "" {
		actor = auditSystemActor
	}

	mode := incidents.Mode(req.Mode)
	if mode == "" {
		mode = incidents.ModeSimulate
	}

	action := &incidents.ResponseAction{
		ID:          idgen.New(idgen.PrefixAction),
		IncidentID:  req.IncidentID,
		ActionType:  req.ActionType,
		Mode:        mode,
		RequestedBy: actor,
		CreatedAt:   s.now().UTC(),
	}

	// base is the audit shape every outcome shares, so no branch can quietly
	// omit the actor, the request id or the subject.
	base := func(result, auditAction, outcome, reason string, extra map[string]any) audit.Entry {
		details := map[string]any{
			"result":             result,
			"incident_id":        req.IncidentID,
			"action_type":        req.ActionType,
			"mode":               string(mode),
			"response_action_id": action.ID,
			"policy_revision":    policies.Revision(),
		}
		for k, v := range extra {
			details[k] = v
		}
		return audit.Entry{
			Actor:       actor,
			ActorRole:   principal.Role,
			Action:      auditAction,
			SubjectType: audit.SubjectAction,
			SubjectID:   action.ID,
			Outcome:     outcome,
			Reason:      reason,
			RequestID:   requestID,
			Details:     details,
		}
	}

	spec, err := incidents.Lookup(req.ActionType)
	if err != nil {
		action.Status = incidents.ActionRejected
		action.Reason = fmt.Sprintf("Action type %q is not defined in the GRIEFER action catalog.", req.ActionType)
		s.persistEvaluation(ctx, action, base(audit.ResultInvalidAction,
			audit.ActionActionRejected, audit.OutcomeDenied, action.Reason, nil))
		return action, err
	}
	if !mode.Valid() {
		action.Status = incidents.ActionRejected
		action.Reason = fmt.Sprintf("Response mode %q is not recognised.", req.Mode)
		s.persistEvaluation(ctx, action, base(audit.ResultValidationFailed,
			audit.ActionActionRejected, audit.OutcomeDenied, action.Reason, nil))
		return action, fmt.Errorf("invalid response mode %q", req.Mode)
	}

	inc, err := s.store.GetIncident(ctx, req.IncidentID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			s.persistEvaluation(ctx, nil, base(audit.ResultValidationFailed,
				audit.ActionActionRejected, audit.OutcomeDenied,
				"The referenced incident does not exist.", nil))
			return nil, ErrIncidentNotFound
		}
		s.persistEvaluation(ctx, nil, base(audit.ResultInternalError,
			audit.ActionActionRejected, audit.OutcomeFailure,
			"The incident could not be loaded.", nil))
		return nil, fmt.Errorf("load incident: %w", err)
	}

	recommended := findRecommendation(inc, spec.Type)
	targetEntityID, targetsCritical := s.resolveActionTarget(inc, spec.Type, recommended)

	action.Reversible = spec.Reversible
	action.Destructive = spec.Destructive
	action.RollbackAction = spec.RollbackAction
	action.TargetEntityID = targetEntityID

	input := policy.Input{
		Action: policy.ActionInput{
			Type:                 spec.Type,
			Mode:                 string(mode),
			Known:                true,
			Destructive:          spec.Destructive,
			Reversible:           spec.Reversible,
			RollbackAction:       spec.RollbackAction,
			TargetsCriticalAsset: targetsCritical,
			Isolation:            spec.Isolation,
			TargetEntityID:       targetEntityID,
		},
		Incident: policy.IncidentInput{
			ID:                 inc.ID,
			RiskScore:          inc.RiskScore,
			Confidence:         inc.Confidence,
			Severity:           string(inc.Severity),
			EvidenceCategories: categoryStrings(inc.EvidenceCategories()),
			FindingCount:       len(inc.Findings),
		},
		Request: policy.RequestInput{
			// Automated is derived, not accepted. It selects which corroboration
			// bar the policy applies, so a caller able to set it could choose
			// the bar it is judged against. A request carrying an operator is a
			// person pressing a button, by definition.
			Automated:   principal.Zero() && req.Automated,
			RequestedBy: actor,
		},
	}

	// The Policy Kernel is consulted OUTSIDE any database transaction. Holding
	// one open across a call to another service ties this database's connection
	// budget to that service's latency, and a slow policy engine becomes a
	// exhausted connection pool.
	decision, kernelErr := s.kernel.Evaluate(ctx, input)
	action.PolicyDecision = &decision
	s.metrics.PolicyDecisions.WithLabelValues(decision.Effect, decision.Engine, boolLabel(decision.FailClosed)).Inc()

	if kernelErr != nil {
		s.logger.ErrorContext(ctx, "policy kernel unavailable; action denied by fail-closed path",
			slog.String("request_id", requestID),
			slog.String("action_type", spec.Type),
			slog.String("error", kernelErr.Error()))
	}

	s.applyDecision(action, spec, inc, decision)

	result := evaluationResult(action.Status, decision, kernelErr)
	decisionDetails := map[string]any{
		"incident_id":      inc.ID,
		"action_type":      spec.Type,
		"effect":           decision.Effect,
		"fail_closed":      decision.FailClosed,
		"engine":           decision.Engine,
		"policy_version":   decision.PolicyVersion,
		"reversible":       spec.Reversible,
		"destructive":      spec.Destructive,
		"rollback_action":  spec.RollbackAction,
		"targets_critical": targetsCritical,
		"risk_score":       inc.RiskScore,
		"evidence_types":   input.Incident.EvidenceCategories,
	}

	// One transaction covers the action and both entries describing it.
	s.persistEvaluation(ctx, action,
		base(result, audit.ActionPolicyEvaluated, auditOutcomeFor(decision.Effect),
			joinReasons(decision.Reasons), decisionDetails),
		base(result, auditActionFor(action.Status), auditOutcomeFor(decision.Effect),
			action.Reason, nil),
	)

	return action, nil
}

// auditSystemActor names the platform itself, for work no operator asked for.
const auditSystemActor = "system:griefer"

// evaluationResult classifies what happened, beyond whether it was permitted.
func evaluationResult(status incidents.ActionStatus, decision incidents.PolicyDecision, kernelErr error) string {
	if kernelErr != nil {
		if errors.Is(kernelErr, context.DeadlineExceeded) {
			return audit.ResultPolicyTimeout
		}
		return audit.ResultPolicyUnavailable
	}
	switch status {
	case incidents.ActionSimulated:
		return audit.ResultAllowed
	case incidents.ActionRequiresApproval:
		return audit.ResultRequiresApproval
	default:
		return audit.ResultDenied
	}
}

// persistEvaluation writes the action and its audit entries as one unit.
//
// A failure here is loud and is NOT converted into a client error, which is a
// deliberate and uncomfortable choice. The alternative — failing the request —
// would mean an unreachable audit table takes the whole evaluation path down.
// Since v0.1 executes nothing, an evaluation that is not durably recorded has
// changed nothing in the world, so refusing to answer buys no safety. What it
// must never do is look successful while being invisible, so the failure is
// logged with the request id and the store's health is what /ready reports.
//
// When this platform gains an actuator, this is the first decision that has to
// be revisited: at that point an unrecorded action HAS changed something, and
// the request must fail instead.
func (s *Service) persistEvaluation(ctx context.Context, action *incidents.ResponseAction, entries ...audit.Entry) {
	prepared := make([]*audit.Entry, 0, len(entries))
	for _, entry := range entries {
		p, err := s.auditor.Prepare(entry)
		if err != nil {
			s.logger.ErrorContext(ctx, "failed to prepare audit entry",
				slog.String("request_id", httpx.RequestIDFromContext(ctx)),
				slog.String("audit_action", entry.Action),
				slog.String("error", err.Error()))
			continue
		}
		prepared = append(prepared, p)
	}
	if err := s.store.SaveActionWithAudit(ctx, action, prepared); err != nil {
		s.logger.ErrorContext(ctx, "failed to persist evaluation atomically",
			slog.String("request_id", httpx.RequestIDFromContext(ctx)),
			slog.String("error", err.Error()))
	}
}

// applyDecision turns a policy verdict into an action status and, when the
// verdict permits it, a simulated effect.
//
// The guard on ModeSimulate is load-bearing: it is the only place an action
// produces any effect at all, and it makes "v0.1 cannot touch a real system" a
// property of the control flow rather than a promise in a README.
func (s *Service) applyDecision(action *incidents.ResponseAction, spec incidents.ActionSpec, inc *incidents.Incident, decision incidents.PolicyDecision) {
	switch decision.Effect {
	case policy.EffectDeny:
		action.Status = incidents.ActionDenied
		action.Reason = joinReasons(decision.Reasons)
	case policy.EffectRequireApproval:
		action.Status = incidents.ActionRequiresApproval
		action.Reason = joinReasons(decision.Reasons)
	case policy.EffectAllow:
		if action.Mode != incidents.ModeSimulate {
			// Unreachable while the policy requires approval for every execute
			// request. Kept as a hard stop: GRIEFER v0.1 ships no actuator, and
			// a future policy change must not silently turn this into
			// execution.
			action.Status = incidents.ActionRequiresApproval
			action.Reason = "GRIEFER v0.1 implements simulation only; no actuator exists for mode \"execute\"."
			return
		}
		action.Status = incidents.ActionSimulated
		action.Reason = joinReasons(decision.Reasons)
		action.Simulated = buildSimulatedEffect(spec, inc, action.TargetEntityID)
	default:
		// An unrecognised effect is treated as a denial.
		action.Status = incidents.ActionDenied
		action.Reason = "Policy Kernel returned an unrecognised effect; GRIEFER denies by default."
	}
}

// buildSimulatedEffect describes what the action would have done, computed from
// the incident's own graph context. Nothing here reaches outside the process.
func buildSimulatedEffect(spec incidents.ActionSpec, inc *incidents.Incident, targetEntityID string) *incidents.SimulatedEffect {
	affected := affectedEntities(spec, inc, targetEntityID)
	rollback := spec.RollbackAction
	plan := fmt.Sprintf("Run %q to reverse this action.", rollback)
	if rollback == "" {
		plan = "No rollback exists for this action; it would require human approval before execution."
	}
	return &incidents.SimulatedEffect{
		Description:      fmt.Sprintf(spec.SimulationTemplate, len(affected)),
		AffectedEntities: affected,
		RollbackPlan:     plan,
	}
}

// affectedEntities returns the entities an action would touch: its explicit
// target, or the incident's entities of a matching type.
func affectedEntities(spec incidents.ActionSpec, inc *incidents.Incident, targetEntityID string) []string {
	if targetEntityID != "" {
		return []string{targetEntityID}
	}
	var out []string
	for _, e := range inc.Entities {
		out = append(out, e.ID)
	}
	_ = spec
	return out
}

// resolveActionTarget picks the entity an action applies to and reports whether
// it is classified critical. Criticality is read from the graph, never from the
// request.
func (s *Service) resolveActionTarget(inc *incidents.Incident, actionType string, recommended *incidents.RecommendedAction) (string, bool) {
	if recommended != nil && recommended.TargetEntityID != "" {
		if ent, ok := s.graph.Entity(recommended.TargetEntityID); ok {
			return ent.ID, ent.Criticality == graph.CriticalityCritical
		}
		return recommended.TargetEntityID, recommended.TargetsCriticalAsset
	}
	// The action was not among the engine's recommendations — a human may still
	// propose it. Fall back to the incident's most critical entity so the
	// critical-asset rule cannot be dodged by asking for an unrecommended
	// action.
	_ = actionType
	var (
		bestID       string
		bestCritical bool
		bestRank     = -1
	)
	for _, e := range inc.Entities {
		if e.Criticality.Rank() > bestRank {
			bestRank = e.Criticality.Rank()
			bestID = e.ID
			bestCritical = e.Criticality == graph.CriticalityCritical
		}
	}
	return bestID, bestCritical
}

func findRecommendation(inc *incidents.Incident, actionType string) *incidents.RecommendedAction {
	for i := range inc.RecommendedActions {
		if inc.RecommendedActions[i].ActionType == actionType {
			return &inc.RecommendedActions[i]
		}
	}
	return nil
}

func auditActionFor(status incidents.ActionStatus) string {
	switch status {
	case incidents.ActionSimulated:
		return audit.ActionActionSimulated
	case incidents.ActionRequiresApproval:
		return audit.ActionActionNeedsApproval
	case incidents.ActionRejected:
		return audit.ActionActionRejected
	default:
		return audit.ActionActionDenied
	}
}

func auditOutcomeFor(effect string) string {
	switch effect {
	case policy.EffectAllow:
		return audit.OutcomeSuccess
	case policy.EffectRequireApproval:
		return audit.OutcomePending
	default:
		return audit.OutcomeDenied
	}
}

func joinReasons(reasons []string) string {
	switch len(reasons) {
	case 0:
		return "No reason was recorded; GRIEFER treats this as a denial."
	case 1:
		return reasons[0]
	default:
		out := reasons[0]
		for _, r := range reasons[1:] {
			out += " " + r
		}
		return out
	}
}

func boolLabel(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
