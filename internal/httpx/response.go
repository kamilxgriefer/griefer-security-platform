// Package httpx holds GRIEFER's HTTP plumbing: request identity, body limits,
// rate limiting, panic recovery, structured access logging and the error
// envelope shared by every endpoint.
package httpx

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// Error codes returned by the API. They are stable identifiers a client can
// branch on; the human-readable message is not.
const (
	CodeValidationFailed = "validation_failed"
	CodeMalformedRequest = "malformed_request"
	CodeNotFound         = "not_found"
	CodeUnauthorized     = "unauthorized"
	// CodeForbidden is authenticated-but-not-permitted, as distinct from
	// CodeUnauthorized. Collapsing the two would tell a caller with a valid
	// credential to go and authenticate again, which is advice that cannot help.
	CodeForbidden          = "forbidden"
	CodePayloadTooLarge    = "payload_too_large"
	CodeRateLimited        = "rate_limited"
	CodeUnsupportedMedia   = "unsupported_media_type"
	CodeMethodNotAllowed   = "method_not_allowed"
	CodeInternal           = "internal_error"
	CodeDependencyDegraded = "dependency_degraded"
	CodeNotImplemented     = "not_implemented"
)

// ErrorBody is the error envelope returned by every endpoint.
//
// It carries a stable code, a message safe to show a user, the request id for
// correlating with server logs, and optional structured details. It never
// carries a stack trace, an internal path, a driver error or a SQL fragment:
// anything that would help an attacker map the inside of the system stays in
// the log, keyed by request id.
type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
	Details   any    `json:"details,omitempty"`
}

// ErrorResponse wraps ErrorBody.
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// WriteJSON serialises v as JSON with the given status code.
func WriteJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		// The status line is already sent, so this cannot become an error
		// response. Record it and let the client see a truncated body.
		slog.ErrorContext(r.Context(), "failed to encode response body",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("error", err.Error()))
	}
}

// WriteError sends a structured error response.
func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string, details any) {
	WriteJSON(w, r, status, ErrorResponse{Error: ErrorBody{
		Code:      code,
		Message:   message,
		RequestID: RequestIDFromContext(r.Context()),
		Details:   details,
	}})
}

// Page is the envelope for paginated collections.
type Page[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}
