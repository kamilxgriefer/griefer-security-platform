package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/graph"
	"github.com/kamilxgriefer/griefer-security-platform/internal/httpx"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
)

// Version identifies the API contract implemented by this build.
const Version = "0.1.0"

// healthCheckTimeout bounds each dependency probe so a hung dependency cannot
// hold the readiness endpoint open.
const healthCheckTimeout = 3 * time.Second

// handleHealth is a liveness probe: it reports that the process is running and
// answering. It deliberately checks no dependency — a liveness probe that fails
// on a database blip causes restart storms.
func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": Version,
		"time":    s.now().UTC(),
	})
}

// ComponentStatus reports one dependency's state.
type ComponentStatus struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Healthy bool   `json:"healthy"`
	// Required marks dependencies GRIEFER cannot serve without.
	Required bool   `json:"required"`
	Detail   string `json:"detail,omitempty"`
}

// ReadinessResponse is the body of /ready and /api/v1/system/status.
type ReadinessResponse struct {
	Status     string            `json:"status"`
	Version    string            `json:"version"`
	Time       time.Time         `json:"time"`
	Components []ComponentStatus `json:"components"`
	// ResponseMode is surfaced on every status payload so a console can never
	// display GRIEFER without also displaying that responses are simulated.
	ResponseMode   string `json:"response_mode"`
	SimulationOnly bool   `json:"simulation_only"`
}

// readinessCacheTTL bounds how often a probe reaches the dependencies.
//
// /ready is exempt from the service credential, because a platform has to be
// able to ask whether a container is ready before it holds one — and each call
// fans out to PostgreSQL, the Policy Kernel and the event bus. Unbounded, one
// address turns a cheap unauthenticated request into three backend round trips
// and can exhaust the connection pool, which then makes real evaluations time
// out and fail closed. docs/THREAT_MODEL.md T10 claimed request floods were
// bounded by a per-client token bucket; the limiter covers write endpoints and
// has never covered this one.
//
// A second is short enough that an orchestrator sees a state change
// immediately on any realistic probe interval, and long enough that a flood
// costs one probe per second instead of one per request.
const readinessCacheTTL = time.Second

func (s *Service) readiness(ctx context.Context) ReadinessResponse {
	now := s.now()
	s.readinessMu.Lock()
	if !s.readinessAt.IsZero() && now.Sub(s.readinessAt) < readinessCacheTTL {
		cached := s.readinessBody
		s.readinessMu.Unlock()
		// The timestamp is the caller's, not the probe's: a client must not be
		// told a stale time, only a recently-checked verdict.
		cached.Time = now.UTC()
		return cached
	}
	s.readinessMu.Unlock()

	body := s.probeReadiness(ctx)

	s.readinessMu.Lock()
	s.readinessAt, s.readinessBody = now, body
	s.readinessMu.Unlock()
	return body
}

func (s *Service) probeReadiness(ctx context.Context) ReadinessResponse {
	ctx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
	defer cancel()

	components := []ComponentStatus{
		s.checkStore(ctx),
		s.checkKernel(ctx),
		s.checkBus(ctx),
	}
	status := "ready"
	for _, c := range components {
		if c.Required && !c.Healthy {
			status = "degraded"
			break
		}
	}
	return ReadinessResponse{
		Status:         status,
		Version:        Version,
		Time:           s.now().UTC(),
		Components:     components,
		ResponseMode:   string(incidents.ModeSimulate),
		SimulationOnly: true,
	}
}

func (s *Service) checkStore(ctx context.Context) ComponentStatus {
	c := ComponentStatus{Name: "storage", Kind: s.store.Kind(), Required: true}
	if err := s.store.Ping(ctx); err != nil {
		c.Detail = "storage is unreachable"
		return c
	}
	c.Healthy = true
	return c
}

func (s *Service) checkKernel(ctx context.Context) ComponentStatus {
	c := ComponentStatus{Name: "policy_kernel", Kind: s.kernel.Engine(), Required: true}
	if err := s.kernel.Health(ctx); err != nil {
		// A dead Policy Kernel does not stop ingestion, but it does stop every
		// response action, so GRIEFER reports itself as not ready.
		c.Detail = "policy kernel cannot evaluate; response actions will fail closed"
		return c
	}
	c.Healthy = true
	return c
}

func (s *Service) checkBus(ctx context.Context) ComponentStatus {
	c := ComponentStatus{Name: "event_bus", Kind: s.publisher.Kind(), Required: false}
	if err := s.publisher.Health(ctx); err != nil {
		c.Detail = "event bus is unavailable; ingestion continues without fan-out"
		return c
	}
	c.Healthy = true
	return c
}

func (s *Service) handleReady(w http.ResponseWriter, r *http.Request) {
	body := s.readiness(r.Context())
	status := http.StatusOK
	if body.Status != "ready" {
		status = http.StatusServiceUnavailable
	}
	httpx.WriteJSON(w, r, status, body)
}

// SystemStatus extends readiness with pipeline counters for the console.
type SystemStatus struct {
	ReadinessResponse
	Events    int `json:"events_ingested"`
	Incidents int `json:"incidents_open"`
	Entities  int `json:"graph_entities"`
	Edges     int `json:"graph_edges"`
	Rules     int `json:"detection_rules"`
}

func (s *Service) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	body := SystemStatus{ReadinessResponse: s.readiness(r.Context())}
	if count, err := s.store.CountEvents(r.Context()); err == nil {
		body.Events = count
	}
	if _, total, err := s.store.ListIncidents(r.Context(), storage.IncidentFilter{Status: string(incidents.StatusOpen), Limit: 1}); err == nil {
		body.Incidents = total
	}
	body.Entities, body.Edges = s.graph.Size()
	body.Rules = s.ruleCount
	httpx.WriteJSON(w, r, http.StatusOK, body)
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

func (s *Service) handleIngestEvent(w http.ResponseWriter, r *http.Request) {
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	result, err := s.Ingest(r.Context(), raw)
	if err != nil {
		writeIngestError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusAccepted, result)
}

// BatchRequest is the payload of POST /api/v1/events/batch.
type BatchRequest struct {
	Events []json.RawMessage `json:"events"`
}

// BatchItemResult reports the outcome for one event in a batch.
type BatchItemResult struct {
	Index  int              `json:"index"`
	Status string           `json:"status"`
	Result *IngestResult    `json:"result,omitempty"`
	Error  *httpx.ErrorBody `json:"error,omitempty"`
}

// BatchResponse summarises a batch ingest.
type BatchResponse struct {
	Accepted int               `json:"accepted"`
	Rejected int               `json:"rejected"`
	Results  []BatchItemResult `json:"results"`
}

func (s *Service) handleIngestBatch(w http.ResponseWriter, r *http.Request) {
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	var req BatchRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeMalformedRequest,
			"Request body must be a JSON object with an \"events\" array.", nil)
		return
	}
	if len(req.Events) == 0 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"The \"events\" array must contain at least one event.", nil)
		return
	}
	if len(req.Events) > s.maxBatchEvents {
		httpx.WriteError(w, r, http.StatusRequestEntityTooLarge, httpx.CodePayloadTooLarge,
			fmt.Sprintf("A batch may contain at most %d events; received %d.", s.maxBatchEvents, len(req.Events)),
			map[string]any{"max_events": s.maxBatchEvents, "received": len(req.Events)})
		return
	}

	resp := BatchResponse{Results: make([]BatchItemResult, 0, len(req.Events))}
	for i, item := range req.Events {
		result, err := s.Ingest(r.Context(), item)
		if err != nil {
			resp.Rejected++
			resp.Results = append(resp.Results, BatchItemResult{
				Index: i, Status: "rejected", Error: ingestErrorBody(r, err),
			})
			continue
		}
		resp.Accepted++
		res := result
		resp.Results = append(resp.Results, BatchItemResult{Index: i, Status: "accepted", Result: &res})
	}

	switch {
	case resp.Rejected == 0:
		httpx.WriteJSON(w, r, http.StatusAccepted, resp)
	case resp.Accepted == 0:
		httpx.WriteJSON(w, r, http.StatusBadRequest, resp)
	default:
		// Partial success is genuinely multi-status: reporting 202 would hide
		// the rejects and 400 would hide the accepts.
		httpx.WriteJSON(w, r, http.StatusMultiStatus, resp)
	}
}

func (s *Service) handleListEvents(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	items, total, err := s.store.ListEvents(r.Context(), limit, offset)
	if err != nil {
		s.writeInternal(w, r, "list events", err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, httpx.Page[*events.SecurityEvent]{
		Items: items, Total: total, Limit: limit, Offset: offset,
	})
}

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

func (s *Service) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	filter := storage.IncidentFilter{
		Status:   r.URL.Query().Get("status"),
		Severity: r.URL.Query().Get("severity"),
		Limit:    limit,
		Offset:   offset,
	}
	if raw := r.URL.Query().Get("min_risk_score"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 0 || v > 100 {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
				"Query parameter \"min_risk_score\" must be an integer between 0 and 100.", nil)
			return
		}
		filter.MinRiskScore = v
	}
	if filter.Status != "" && !validIncidentStatus(filter.Status) {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Query parameter \"status\" must be one of: open, investigating, contained, closed.", nil)
		return
	}
	if filter.Severity != "" && !events.Severity(filter.Severity).Valid() {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Query parameter \"severity\" must be one of: informational, low, medium, high, critical.", nil)
		return
	}

	items, total, err := s.store.ListIncidents(r.Context(), filter)
	if err != nil {
		s.writeInternal(w, r, "list incidents", err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, httpx.Page[*incidents.Incident]{
		Items: items, Total: total, Limit: limit, Offset: offset,
	})
}

func (s *Service) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	inc, err := s.store.GetIncident(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.CodeNotFound, "Incident not found.", nil)
		return
	}
	if err != nil {
		s.writeInternal(w, r, "get incident", err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, inc)
}

func validIncidentStatus(status string) bool {
	switch incidents.Status(status) {
	case incidents.StatusOpen, incidents.StatusInvestigating, incidents.StatusContained, incidents.StatusClosed:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Entities
// ---------------------------------------------------------------------------

// EntityResponse is an entity plus its immediate graph context.
type EntityResponse struct {
	Entity      graph.Entity      `json:"entity"`
	Edges       []graph.Edge      `json:"edges"`
	BlastRadius graph.BlastRadius `json:"blast_radius"`
}

func (s *Service) handleGetEntity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	entity, ok := s.graph.Entity(id)
	if !ok {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.CodeNotFound,
			"Entity not found in the Security Graph.", nil)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, EntityResponse{
		Entity:      entity,
		Edges:       s.graph.Neighbours(id),
		BlastRadius: s.graph.EstimateBlastRadius([]string{id}, graph.DefaultMaxHops),
	})
}

// ---------------------------------------------------------------------------
// Response actions
// ---------------------------------------------------------------------------

func (s *Service) handleEvaluateAction(w http.ResponseWriter, r *http.Request) {
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	var req EvaluateRequest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeMalformedRequest,
			"Request body must be a JSON object with incident_id, action_type and optional mode, requested_by, automated.", nil)
		return
	}
	if strings.TrimSpace(req.IncidentID) == "" || strings.TrimSpace(req.ActionType) == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Fields \"incident_id\" and \"action_type\" are required.", nil)
		return
	}

	action, err := s.EvaluateAction(r.Context(), req)
	switch {
	case errors.Is(err, incidents.ErrUnknownActionType):
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Unknown action type.",
			map[string]any{"allowed_action_types": incidents.KnownActionTypes()})
		return
	case errors.Is(err, ErrIncidentNotFound):
		httpx.WriteError(w, r, http.StatusNotFound, httpx.CodeNotFound, "Incident not found.", nil)
		return
	case err != nil && action != nil && action.Status == incidents.ActionRejected:
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, action.Reason, nil)
		return
	case err != nil:
		s.writeInternal(w, r, "evaluate action", err)
		return
	}

	// A fail-closed denial is a definitive answer, not a server fault, so it is
	// returned as 200 with an explicit marker. The header lets an operator spot
	// a degraded Policy Kernel without parsing the body.
	if action.PolicyDecision != nil && action.PolicyDecision.FailClosed {
		w.Header().Set("X-Griefer-Policy-Degraded", "true")
	}
	httpx.WriteJSON(w, r, http.StatusOK, action)
}

func (s *Service) handleGetAction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	action, err := s.store.GetAction(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.CodeNotFound, "Response action not found.", nil)
		return
	}
	if err != nil {
		s.writeInternal(w, r, "get response action", err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, action)
}

func (s *Service) handleListActions(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	incidentID := r.URL.Query().Get("incident_id")
	items, total, err := s.store.ListActions(r.Context(), incidentID, limit, offset)
	if err != nil {
		s.writeInternal(w, r, "list response actions", err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, httpx.Page[*incidents.ResponseAction]{
		Items: items, Total: total, Limit: limit, Offset: offset,
	})
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

func (s *Service) handleListAudit(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	items, total, err := s.auditor.List(r.Context(), limit, offset)
	if err != nil {
		s.writeInternal(w, r, "list audit entries", err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, httpx.Page[*audit.Entry]{
		Items: items, Total: total, Limit: limit, Offset: offset,
	})
}

// handleVerifyAudit reports whether the audit trail is internally consistent.
//
// It answers 200 in every case, including a broken chain. A 5xx for "broken"
// would be indistinguishable from the endpoint being down, and an integrity
// check whose bad news looks like an outage is one nobody can act on. A 500
// here means only that the check could not be run.
//
// It writes no audit entry. Reads leave no trace by design, and a verification
// that appended would move the head of the chain it had just verified on every
// read of it.
func (s *Service) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	report, err := s.store.VerifyAuditChain(r.Context(), limit, offset)
	if err != nil {
		s.writeInternal(w, r, "verify audit chain", err)
		return
	}
	// Deliberately not an httpx.Page. It is not a collection, and giving it
	// invented total/limit/offset fields to look like the other list responses
	// would be a lie about what it is.
	httpx.WriteJSON(w, r, http.StatusOK, report)
}

// handleIssueAuditAnchor returns a commitment to the trail's current head.
//
// This is the half of tamper-evidence the chain cannot supply itself. The
// canonical form is public and no secret enters it, so a role that can write to
// audit_log can alter an entry and recompute every hash after it — and
// /audit/verify, reading only that database, reports the result intact. An
// anchor is one link copied somewhere that role does not reach.
//
// It writes nothing, including no audit entry: issuing one would move the head
// it had just committed to.
func (s *Service) handleIssueAuditAnchor(w http.ResponseWriter, r *http.Request) {
	anchor, err := s.store.IssueAuditAnchor(r.Context())
	if err != nil {
		// An empty chain is a 409 rather than a 500: nothing is broken, there is
		// simply nothing to commit to yet, and a caller can act on that.
		if strings.Contains(err.Error(), "no entries yet") {
			httpx.WriteError(w, r, http.StatusConflict, httpx.CodeNotFound,
				"The audit chain holds no entries yet, so there is nothing to anchor.", nil)
			return
		}
		s.writeInternal(w, r, "issue audit anchor", err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, anchor)
}

// handleCheckAuditAnchor compares an anchor the operator kept against the trail.
//
// 200 in every case, including a detected rewrite, for the reason
// /audit/verify answers 200 on a broken chain: bad news that looks like an
// outage is bad news nobody acts on. Read `verdict`.
func (s *Service) handleCheckAuditAnchor(w http.ResponseWriter, r *http.Request) {
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	var anchor storage.AuditAnchor
	if err := json.Unmarshal(raw, &anchor); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeMalformedRequest,
			"Anchor could not be parsed. Send the object returned by GET /api/v1/audit/anchor.", nil)
		return
	}
	report, err := s.store.CheckAuditAnchor(r.Context(), anchor)
	if err != nil {
		s.writeInternal(w, r, "check audit anchor", err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, report)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// readBody reads a request body that the MaxBytes middleware has already
// capped, converting an oversize body into a 413 rather than a 500.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			httpx.WriteError(w, r, http.StatusRequestEntityTooLarge, httpx.CodePayloadTooLarge,
				fmt.Sprintf("Request body exceeds the %d byte limit.", maxErr.Limit),
				map[string]any{"max_bytes": maxErr.Limit})
			return nil, false
		}
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeMalformedRequest,
			"Request body could not be read.", nil)
		return nil, false
	}
	if len(raw) == 0 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeMalformedRequest,
			"Request body is empty.", nil)
		return nil, false
	}
	return raw, true
}

func writeIngestError(w http.ResponseWriter, r *http.Request, err error) {
	body := ingestErrorBody(r, err)
	status := http.StatusBadRequest
	if body.Code == httpx.CodeInternal {
		status = http.StatusInternalServerError
	}
	httpx.WriteJSON(w, r, status, httpx.ErrorResponse{Error: *body})
}

// ingestErrorBody maps an ingest failure onto a client-safe error body.
func ingestErrorBody(r *http.Request, err error) *httpx.ErrorBody {
	requestID := httpx.RequestIDFromContext(r.Context())

	var verr *events.ValidationError
	if errors.As(err, &verr) {
		details := map[string]any{"errors": verr.Errors}
		if verr.Truncated {
			details["truncated"] = true
		}
		return &httpx.ErrorBody{
			Code:      httpx.CodeValidationFailed,
			Message:   "Event does not conform to the GRIEFER event schema.",
			RequestID: requestID,
			Details:   details,
		}
	}
	if errors.Is(err, events.ErrTimestampOutOfRange) {
		return &httpx.ErrorBody{
			Code:      httpx.CodeValidationFailed,
			Message:   err.Error(),
			RequestID: requestID,
		}
	}
	return &httpx.ErrorBody{
		Code:      httpx.CodeInternal,
		Message:   "The event could not be processed. Use the request_id when reporting this.",
		RequestID: requestID,
	}
}

// writeInternal logs the real error and returns an opaque one.
func (s *Service) writeInternal(w http.ResponseWriter, r *http.Request, operation string, err error) {
	s.logger.ErrorContext(r.Context(), "request failed",
		"request_id", httpx.RequestIDFromContext(r.Context()),
		"operation", operation, "error", err.Error())
	httpx.WriteError(w, r, http.StatusInternalServerError, httpx.CodeInternal,
		"The request could not be completed. Use the request_id when reporting this.", nil)
}

// pagination reads limit/offset, clamping rather than rejecting so a client
// cannot turn a typo into an unbounded query.
func pagination(r *http.Request) (limit, offset int) {
	limit = storage.ClampLimit(atoiOr(r.URL.Query().Get("limit"), storage.DefaultPageSize))
	offset = atoiOr(r.URL.Query().Get("offset"), 0)
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func atoiOr(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}
