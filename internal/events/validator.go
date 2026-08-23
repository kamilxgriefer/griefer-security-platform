package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/kamilxgriefer/griefer-security-platform/schemas"
)

// maxFieldErrors bounds how many individual schema violations are reported back
// to a client. An attacker-supplied document can produce thousands of causes;
// echoing all of them turns validation into an amplification primitive.
const maxFieldErrors = 20

// FieldError is a single, client-safe schema violation.
type FieldError struct {
	// Field is a JSON Pointer into the submitted document ("/actor/id").
	Field string `json:"field"`
	// Message describes the violation in terms of the schema only. It never
	// contains server paths, stack traces or the offending value.
	Message string `json:"message"`
}

// ValidationError reports that a document failed schema validation.
type ValidationError struct {
	Errors []FieldError
	// Truncated is true when more violations existed than were reported.
	Truncated bool
}

func (e *ValidationError) Error() string {
	if len(e.Errors) == 0 {
		return "event failed schema validation"
	}
	parts := make([]string, 0, len(e.Errors))
	for _, fe := range e.Errors {
		parts = append(parts, fe.Field+": "+fe.Message)
	}
	return "event failed schema validation: " + strings.Join(parts, "; ")
}

// Validator validates raw event documents against the embedded JSON Schema.
// It is safe for concurrent use.
type Validator struct {
	schema  *jsonschema.Schema
	version string
}

// NewValidator compiles the embedded event schema. It fails at construction
// time rather than on the request path so a malformed schema can never be
// mistaken for a malformed event.
func NewValidator() (*Validator, error) {
	raw, err := schemas.FS.ReadFile(schemas.EventSchemaPath)
	if err != nil {
		return nil, fmt.Errorf("read embedded event schema: %w", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse embedded event schema: %w", err)
	}

	const schemaURL = "https://griefer.dev/schemas/events/security-event.v0.1.schema.json"
	c := jsonschema.NewCompiler()
	// format is annotation-only by default in draft 2020-12; GRIEFER needs
	// date-time actually enforced at the trust boundary.
	c.AssertFormat()
	if err := c.AddResource(schemaURL, doc); err != nil {
		return nil, fmt.Errorf("register event schema: %w", err)
	}
	sch, err := c.Compile(schemaURL)
	if err != nil {
		return nil, fmt.Errorf("compile event schema: %w", err)
	}
	return &Validator{schema: sch, version: schemas.EventSchemaVersion}, nil
}

// SchemaVersion returns the schema version this validator enforces.
func (v *Validator) SchemaVersion() string { return v.version }

// Validate checks raw against the event schema. It returns a *ValidationError
// for schema violations and a plain error only for input that is not JSON at
// all.
func (v *Validator) Validate(raw []byte) error {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return &ValidationError{Errors: []FieldError{{
			Field:   "/",
			Message: "document is not valid JSON",
		}}}
	}
	if err := v.schema.Validate(inst); err != nil {
		var verr *jsonschema.ValidationError
		// errors.As rather than a type assertion, so a future wrapped error
		// still produces field-level detail instead of an opaque failure.
		if errors.As(err, &verr) {
			return toValidationError(verr)
		}
		return &ValidationError{Errors: []FieldError{{
			Field:   "/",
			Message: "document failed schema validation",
		}}}
	}
	return nil
}

// Decode validates raw and, on success, unmarshals it into a SecurityEvent.
// Decoding after validation guarantees that the Go struct can only ever hold
// schema-approved shapes.
func (v *Validator) Decode(raw []byte) (*SecurityEvent, error) {
	if err := v.Validate(raw); err != nil {
		return nil, err
	}
	var ev SecurityEvent
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		// Unreachable for schema-valid input; treated as a validation failure
		// rather than a server fault so a client can never induce a 500.
		return nil, &ValidationError{Errors: []FieldError{{
			Field:   "/",
			Message: "document could not be decoded into the event model",
		}}}
	}
	return &ev, nil
}

// toValidationError flattens the schema library's error tree into a bounded,
// deterministic, client-safe list.
func toValidationError(verr *jsonschema.ValidationError) *ValidationError {
	seen := map[string]string{}
	collectCauses(verr, seen)

	fields := make([]FieldError, 0, len(seen))
	for field, msg := range seen {
		fields = append(fields, FieldError{Field: field, Message: msg})
	}
	sort.Slice(fields, func(i, j int) bool {
		if fields[i].Field != fields[j].Field {
			return fields[i].Field < fields[j].Field
		}
		return fields[i].Message < fields[j].Message
	})

	out := &ValidationError{}
	if len(fields) > maxFieldErrors {
		out.Errors = fields[:maxFieldErrors]
		out.Truncated = true
		return out
	}
	out.Errors = fields
	return out
}

func collectCauses(e *jsonschema.ValidationError, into map[string]string) {
	if len(e.Causes) == 0 {
		field := "/" + strings.Join(e.InstanceLocation, "/")
		if len(e.InstanceLocation) == 0 {
			field = "/"
		}
		msg := e.ErrorKind.LocalizedString(englishPrinter())
		if _, exists := into[field]; !exists {
			into[field] = msg
		}
		return
	}
	for _, cause := range e.Causes {
		collectCauses(cause, into)
	}
}
