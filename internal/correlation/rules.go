// Package correlation evaluates GRIEFER's declarative detection rules over
// normalized events, promotes matches into findings, and groups findings that
// share a subject into a single incident.
package correlation

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kamilxgriefer/griefer-security-platform/detections"
	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
)

// ruleFile is the on-disk shape of a correlation rule pack.
type ruleFile struct {
	Version string `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// Rule is a declarative detection.
type Rule struct {
	ID          string                `yaml:"id"`
	Title       string                `yaml:"title"`
	Description string                `yaml:"description"`
	Category    events.Category       `yaml:"category"`
	Severity    events.Severity       `yaml:"severity"`
	Confidence  float64               `yaml:"confidence"`
	Techniques  []incidents.Technique `yaml:"techniques"`
	Match       Match                 `yaml:"match"`
	Threshold   *Threshold            `yaml:"threshold"`
}

// Match is the closed set of conditions a rule may test.
type Match struct {
	EventType  []string    `yaml:"event_type"`
	Conditions []Condition `yaml:"conditions"`
}

// Condition compares one allowlisted event field against a literal.
type Condition struct {
	Field     string   `yaml:"field"`
	Equals    string   `yaml:"equals"`
	NotEquals string   `yaml:"not_equals"`
	In        []string `yaml:"in"`
	Exists    *bool    `yaml:"exists"`
}

// Threshold makes a rule stateful: the finding is emitted only once Count
// matching events have been seen for the same subject inside Window.
type Threshold struct {
	Count  int           `yaml:"count"`
	Window time.Duration `yaml:"window"`
}

// Technique tactic/name fields are decoded straight into incidents.Technique.

// allowedFields is the complete set of event fields a rule may reference.
// Anything else fails rule loading. A closed allowlist means a rule can never
// be pointed at data it was not designed to read, and rule content cannot
// become a path traversal into the event object.
var allowedFields = map[string]func(*events.SecurityEvent) (string, bool){
	"event_type":  func(e *events.SecurityEvent) (string, bool) { return e.EventType, e.EventType != "" },
	"category":    func(e *events.SecurityEvent) (string, bool) { return string(e.Category), e.Category != "" },
	"severity":    func(e *events.SecurityEvent) (string, bool) { return string(e.Severity), e.Severity != "" },
	"source_type": func(e *events.SecurityEvent) (string, bool) { return e.SourceType, e.SourceType != "" },
	"source_name": func(e *events.SecurityEvent) (string, bool) { return e.SourceName, e.SourceName != "" },

	"actor.type":       func(e *events.SecurityEvent) (string, bool) { return actorField(e, "type") },
	"actor.domain":     func(e *events.SecurityEvent) (string, bool) { return actorField(e, "domain") },
	"actor.privileged": func(e *events.SecurityEvent) (string, bool) { return actorField(e, "privileged") },

	"target.type":        func(e *events.SecurityEvent) (string, bool) { return targetField(e, "type") },
	"target.criticality": func(e *events.SecurityEvent) (string, bool) { return targetField(e, "criticality") },

	"device.os":        func(e *events.SecurityEvent) (string, bool) { return deviceField(e, "os") },
	"device.managed":   func(e *events.SecurityEvent) (string, bool) { return deviceField(e, "managed") },
	"device.compliant": func(e *events.SecurityEvent) (string, bool) { return deviceField(e, "compliant") },

	"network.first_seen_for_actor": func(e *events.SecurityEvent) (string, bool) {
		if e.Network == nil {
			return "", false
		}
		return boolStr(e.Network.FirstSeenForActor), true
	},
	"network.country": func(e *events.SecurityEvent) (string, bool) {
		if e.Network == nil || e.Network.Country == "" {
			return "", false
		}
		return e.Network.Country, true
	},

	"cloud.provider": func(e *events.SecurityEvent) (string, bool) {
		if e.Cloud == nil || e.Cloud.Provider == "" {
			return "", false
		}
		return e.Cloud.Provider, true
	},
	"cloud.resource_type": func(e *events.SecurityEvent) (string, bool) {
		if e.Cloud == nil || e.Cloud.ResourceType == "" {
			return "", false
		}
		return e.Cloud.ResourceType, true
	},
}

// labelFieldPrefix allows rules to read a specific label by name. Labels are
// attacker-influenced, so rules may only compare them — a label can never
// select an action or change a rule's severity.
const labelFieldPrefix = "labels."

func actorField(e *events.SecurityEvent, f string) (string, bool) {
	if e.Actor == nil {
		return "", false
	}
	switch f {
	case "type":
		return e.Actor.Type, e.Actor.Type != ""
	case "domain":
		return e.Actor.Domain, e.Actor.Domain != ""
	case "privileged":
		return boolStr(e.Actor.Privileged), true
	}
	return "", false
}

func targetField(e *events.SecurityEvent, f string) (string, bool) {
	if e.Target == nil {
		return "", false
	}
	switch f {
	case "type":
		return e.Target.Type, e.Target.Type != ""
	case "criticality":
		return e.Target.Criticality, e.Target.Criticality != ""
	}
	return "", false
}

func deviceField(e *events.SecurityEvent, f string) (string, bool) {
	if e.Device == nil {
		return "", false
	}
	switch f {
	case "os":
		return e.Device.OS, e.Device.OS != ""
	case "managed":
		if e.Device.Managed == nil {
			return "", false
		}
		return boolStr(*e.Device.Managed), true
	case "compliant":
		if e.Device.Compliant == nil {
			return "", false
		}
		return boolStr(*e.Device.Compliant), true
	}
	return "", false
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// resolveField reads an allowlisted field from an event.
func resolveField(ev *events.SecurityEvent, field string) (string, bool) {
	if fn, ok := allowedFields[field]; ok {
		return fn(ev)
	}
	if key, ok := strings.CutPrefix(field, labelFieldPrefix); ok {
		if ev.Labels == nil {
			return "", false
		}
		v, present := ev.Labels[key]
		return v, present
	}
	return "", false
}

// validField reports whether a rule may reference field.
func validField(field string) bool {
	if _, ok := allowedFields[field]; ok {
		return true
	}
	key, ok := strings.CutPrefix(field, labelFieldPrefix)
	return ok && key != "" && !strings.ContainsAny(key, " \t")
}

// Matches reports whether ev satisfies the rule's non-stateful conditions.
func (r *Rule) Matches(ev *events.SecurityEvent) bool {
	if len(r.Match.EventType) > 0 && !containsFold(r.Match.EventType, ev.EventType) {
		return false
	}
	for _, cond := range r.Match.Conditions {
		if !cond.eval(ev) {
			return false
		}
	}
	return true
}

func (c Condition) eval(ev *events.SecurityEvent) bool {
	value, present := resolveField(ev, c.Field)
	if c.Exists != nil {
		return present == *c.Exists
	}
	if c.Equals != "" {
		return present && strings.EqualFold(value, c.Equals)
	}
	if c.NotEquals != "" {
		return !present || !strings.EqualFold(value, c.NotEquals)
	}
	if len(c.In) > 0 {
		return present && containsFold(c.In, value)
	}
	// A condition with no operator is rejected at load time; reaching here
	// would mean loading was bypassed, so fail closed.
	return false
}

func containsFold(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

// LoadRules parses and validates every correlation rule pack in fsys.
func LoadRules(fsys fs.FS, dir string) ([]Rule, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read detection directory %q: %w", dir, err)
	}
	var all []Rule
	seen := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		path := dir + "/" + entry.Name()
		raw, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var file ruleFile
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		dec.KnownFields(true)
		if err := dec.Decode(&file); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		for i := range file.Rules {
			rule := file.Rules[i]
			if err := rule.validate(); err != nil {
				return nil, fmt.Errorf("%s: rule %q: %w", path, rule.ID, err)
			}
			if prev, dup := seen[rule.ID]; dup {
				return nil, fmt.Errorf("duplicate rule id %q in %s and %s", rule.ID, prev, path)
			}
			seen[rule.ID] = path
			all = append(all, rule)
		}
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no correlation rules found in %q", dir)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all, nil
}

// DefaultRules loads the rules embedded in the binary.
func DefaultRules() ([]Rule, error) {
	return LoadRules(detections.CorrelationFS, detections.CorrelationDir)
}

func (r *Rule) validate() error {
	if r.ID == "" {
		return fmt.Errorf("id is required")
	}
	if r.Title == "" {
		return fmt.Errorf("title is required")
	}
	if !r.Severity.Valid() {
		return fmt.Errorf("invalid severity %q", r.Severity)
	}
	if r.Category == "" {
		return fmt.Errorf("category is required")
	}
	if r.Confidence <= 0 || r.Confidence > 1 {
		return fmt.Errorf("confidence must be within (0,1], got %v", r.Confidence)
	}
	if len(r.Match.EventType) == 0 && len(r.Match.Conditions) == 0 {
		return fmt.Errorf("match must constrain at least one field; an unconstrained rule matches all telemetry")
	}
	for _, cond := range r.Match.Conditions {
		if !validField(cond.Field) {
			return fmt.Errorf("condition references field %q which is not in the allowlist", cond.Field)
		}
		operators := 0
		if cond.Equals != "" {
			operators++
		}
		if cond.NotEquals != "" {
			operators++
		}
		if len(cond.In) > 0 {
			operators++
		}
		if cond.Exists != nil {
			operators++
		}
		if operators != 1 {
			return fmt.Errorf("condition on %q must use exactly one operator, found %d", cond.Field, operators)
		}
	}
	if r.Threshold != nil {
		if r.Threshold.Count < 2 {
			return fmt.Errorf("threshold count must be at least 2; use a plain rule for single events")
		}
		if r.Threshold.Window <= 0 {
			return fmt.Errorf("threshold window must be positive")
		}
	}
	for _, t := range r.Techniques {
		if t.ID == "" || t.Name == "" {
			return fmt.Errorf("technique entries require id and name")
		}
	}
	return nil
}
