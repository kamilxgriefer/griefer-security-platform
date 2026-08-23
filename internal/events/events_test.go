package events_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
)

func mustValidator(t *testing.T) *events.Validator {
	t.Helper()
	v, err := events.NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error = %v", err)
	}
	return v
}

const validEvent = `{
  "schema_version": "0.1",
  "timestamp": "2026-08-23T09:14:22Z",
  "source_type": "identity_provider",
  "source_name": "synthetic-idp-lab",
  "event_type": "user_signin",
  "category": "authentication",
  "severity": "medium",
  "actor": {"type": "identity", "id": "u-1042"}
}`

func TestValidatorAcceptsWellFormedEvent(t *testing.T) {
	v := mustValidator(t)
	if err := v.Validate([]byte(validEvent)); err != nil {
		t.Fatalf("Validate() rejected a valid event: %v", err)
	}
}

func TestValidatorRejectsMalformedEvents(t *testing.T) {
	v := mustValidator(t)

	tests := []struct {
		name      string
		body      string
		wantField string
	}{
		{
			name:      "missing required category",
			body:      `{"schema_version":"0.1","timestamp":"2026-08-23T09:14:22Z","source_type":"identity_provider","source_name":"s","event_type":"user_signin","severity":"medium"}`,
			wantField: "/",
		},
		{
			name:      "unknown severity",
			body:      `{"schema_version":"0.1","timestamp":"2026-08-23T09:14:22Z","source_type":"identity_provider","source_name":"s","event_type":"user_signin","category":"authentication","severity":"apocalyptic"}`,
			wantField: "/severity",
		},
		{
			name:      "unknown top-level field is rejected, closing the smuggling channel",
			body:      `{"schema_version":"0.1","timestamp":"2026-08-23T09:14:22Z","source_type":"identity_provider","source_name":"s","event_type":"user_signin","category":"authentication","severity":"low","execute_action":"isolate_endpoint"}`,
			wantField: "/",
		},
		{
			name:      "unsupported schema version",
			body:      `{"schema_version":"9.9","timestamp":"2026-08-23T09:14:22Z","source_type":"identity_provider","source_name":"s","event_type":"user_signin","category":"authentication","severity":"low"}`,
			wantField: "/schema_version",
		},
		{
			name:      "timestamp is not RFC 3339",
			body:      `{"schema_version":"0.1","timestamp":"yesterday afternoon","source_type":"identity_provider","source_name":"s","event_type":"user_signin","category":"authentication","severity":"low"}`,
			wantField: "/timestamp",
		},
		{
			name:      "event_type violates the naming pattern",
			body:      `{"schema_version":"0.1","timestamp":"2026-08-23T09:14:22Z","source_type":"identity_provider","source_name":"s","event_type":"User SignIn; DROP TABLE","category":"authentication","severity":"low"}`,
			wantField: "/event_type",
		},
		{
			name:      "actor without an id",
			body:      `{"schema_version":"0.1","timestamp":"2026-08-23T09:14:22Z","source_type":"identity_provider","source_name":"s","event_type":"user_signin","category":"authentication","severity":"low","actor":{"type":"identity"}}`,
			wantField: "/actor",
		},
		{
			name:      "not JSON at all",
			body:      `this is not json`,
			wantField: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate([]byte(tt.body))
			if err == nil {
				t.Fatalf("Validate() accepted an invalid event")
			}
			var verr *events.ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("Validate() error = %T, want *events.ValidationError", err)
			}
			if len(verr.Errors) == 0 {
				t.Fatal("ValidationError carries no field errors; a client cannot act on that")
			}
			found := false
			for _, fe := range verr.Errors {
				if strings.HasPrefix(fe.Field, tt.wantField) {
					found = true
				}
			}
			if !found {
				t.Errorf("no field error under %q; got %+v", tt.wantField, verr.Errors)
			}
		})
	}
}

func TestValidationErrorsAreBoundedAndSafe(t *testing.T) {
	v := mustValidator(t)
	// A document that violates many constraints at once must not produce an
	// unbounded error list.
	labels := map[string]string{}
	for i := 0; i < 200; i++ {
		labels["INVALID KEY "+strings.Repeat("x", i%40)] = strings.Repeat("v", 300)
	}
	body, err := json.Marshal(map[string]any{
		"schema_version": "0.1",
		"timestamp":      "2026-08-23T09:14:22Z",
		"source_type":    "identity_provider",
		"source_name":    "s",
		"event_type":     "user_signin",
		"category":       "authentication",
		"severity":       "low",
		"labels":         labels,
	})
	if err != nil {
		t.Fatalf("marshal test document: %v", err)
	}
	err = v.Validate(body)
	var verr *events.ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("Validate() error = %v, want *events.ValidationError", err)
	}
	if len(verr.Errors) > 20 {
		t.Errorf("reported %d field errors; the cap of 20 makes validation an amplification primitive otherwise", len(verr.Errors))
	}
	for _, fe := range verr.Errors {
		if strings.Contains(fe.Message, "griefer-security-platform") || strings.Contains(fe.Message, "/Users/") {
			t.Errorf("field error leaks a server path: %q", fe.Message)
		}
	}
}

func TestSanitizeQuarantinesControlPlaneLabels(t *testing.T) {
	tests := []struct {
		name          string
		labels        map[string]string
		wantRemoved   []string
		wantRemaining []string
	}{
		{
			name: "direct control verbs",
			labels: map[string]string{
				"action": "isolate_endpoint", "command": "rm -rf /",
				"execute": "true", "note": "kept",
			},
			wantRemoved:   []string{"action", "command", "execute"},
			wantRemaining: []string{"note"},
		},
		{
			name:          "griefer namespace is reserved",
			labels:        map[string]string{"griefer.policy": "allow", "griefer_override": "yes", "team": "finance"},
			wantRemoved:   []string{"griefer.policy", "griefer_override"},
			wantRemaining: []string{"team"},
		},
		{
			name:          "case is not a bypass",
			labels:        map[string]string{"ACTION": "isolate_endpoint", "Policy": "allow"},
			wantRemoved:   []string{"ACTION", "Policy"},
			wantRemaining: nil,
		},
		{
			name:          "benign labels survive untouched",
			labels:        map[string]string{"outcome": "success", "dataset": "synthetic"},
			wantRemoved:   nil,
			wantRemaining: []string{"outcome", "dataset"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &events.SecurityEvent{Labels: tt.labels}
			removed := events.Sanitize(ev)

			if len(removed) != len(tt.wantRemoved) {
				t.Fatalf("Sanitize() removed %v, want %v", removed, tt.wantRemoved)
			}
			for i, key := range tt.wantRemoved {
				if removed[i] != key {
					t.Errorf("removed[%d] = %q, want %q (output must be sorted for stable audit entries)", i, removed[i], key)
				}
			}
			for _, key := range tt.wantRemoved {
				if _, still := ev.Labels[key]; still {
					t.Errorf("label %q survived sanitization", key)
				}
			}
			for _, key := range tt.wantRemaining {
				if _, ok := ev.Labels[key]; !ok {
					t.Errorf("benign label %q was removed", key)
				}
			}
			if len(tt.wantRemoved) > 0 && len(ev.Quarantined) != len(tt.wantRemoved) {
				t.Errorf("Quarantined = %v; the attempt must stay visible as a signal", ev.Quarantined)
			}
		})
	}
}

func TestNormalizeAssignsServerOwnedFields(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	n := events.NewNormalizerWithClock(func() time.Time { return now })

	warsaw, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		t.Skipf("timezone database unavailable: %v", err)
	}
	ev := &events.SecurityEvent{
		Timestamp:  time.Date(2026, 8, 23, 13, 30, 0, 0, warsaw),
		ReceivedAt: time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC),
		SourceName: "  synthetic-idp-lab  ",
		EventType:  "user_signin",
		Category:   events.CategoryAuthentication,
		Severity:   events.SeverityLow,
		Actor:      &events.Actor{Type: "identity", ID: " u-1042 ", Domain: "HALBERD.EXAMPLE"},
		Target:     &events.Target{Type: "application", ID: "app-1"},
		Labels:     map[string]string{"action": "isolate_endpoint", "outcome": "success"},
	}

	got, err := n.Normalize(ev)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if got.ID == "" {
		t.Error("Normalize() did not assign an event id")
	}
	if got.Timestamp.Location() != time.UTC {
		t.Errorf("Timestamp location = %v, want UTC", got.Timestamp.Location())
	}
	if !got.ReceivedAt.Equal(now) {
		t.Errorf("ReceivedAt = %v, want the server clock %v; a producer must not be able to set it", got.ReceivedAt, now)
	}
	if got.SourceName != "synthetic-idp-lab" {
		t.Errorf("SourceName = %q, want trimmed value", got.SourceName)
	}
	if got.Actor.ID != "u-1042" {
		t.Errorf("Actor.ID = %q, want trimmed value", got.Actor.ID)
	}
	if got.Actor.Domain != "halberd.example" {
		t.Errorf("Actor.Domain = %q, want lowercased value", got.Actor.Domain)
	}
	if got.Target.Criticality != "medium" {
		t.Errorf("Target.Criticality = %q, want the medium default", got.Target.Criticality)
	}
	if _, still := got.Labels["action"]; still {
		t.Error("Normalize() did not run the control-plane guard")
	}
	if got.CorrelationID != got.ID {
		t.Errorf("CorrelationID = %q, want it to default to the event id", got.CorrelationID)
	}
}

func TestNormalizeRejectsTimestampsOutsideTheIngestWindow(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	n := events.NewNormalizerWithClock(func() time.Time { return now })

	tests := []struct {
		name string
		at   time.Time
	}{
		{"far future keeps an incident artificially fresh", now.Add(2 * time.Hour)},
		{"beyond the retention window allows replay of stale telemetry", now.Add(-31 * 24 * time.Hour)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := n.Normalize(&events.SecurityEvent{
				Timestamp: tt.at, Category: events.CategoryAuthentication, Severity: events.SeverityLow,
			})
			if !errors.Is(err, events.ErrTimestampOutOfRange) {
				t.Fatalf("Normalize() error = %v, want ErrTimestampOutOfRange", err)
			}
		})
	}

	t.Run("small clock skew is tolerated", func(t *testing.T) {
		if _, err := n.Normalize(&events.SecurityEvent{
			Timestamp: now.Add(2 * time.Minute), Category: events.CategoryAuthentication, Severity: events.SeverityLow,
		}); err != nil {
			t.Fatalf("Normalize() rejected a two-minute skew: %v", err)
		}
	})
}

func TestSeverityOrdering(t *testing.T) {
	if events.SeverityCritical.Rank() <= events.SeverityHigh.Rank() {
		t.Error("critical must outrank high")
	}
	if events.Severity("bogus").Valid() {
		t.Error("an unknown severity must not validate")
	}
	if events.Severity("bogus").Rank() != 0 {
		t.Error("an unknown severity must rank lowest so it cannot be read as an escalation")
	}
	if got := events.SeverityLow.Max(events.SeverityHigh); got != events.SeverityHigh {
		t.Errorf("Max() = %v, want high", got)
	}
}
