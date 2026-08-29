package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/kamilxgriefer/griefer-security-platform/internal/httpx"
	"github.com/kamilxgriefer/griefer-security-platform/schemas"
)

// Bounds on the producer keyring.
//
// Every one of these is a limit on something an operator writes rather than
// something an attacker sends, so none of them is a security boundary. They are
// here because a configuration mistake should fail at startup with a sentence
// naming the variable, not at three in the morning as a refused sensor.
const (
	// MaxProducers caps the keyring. Thirty-two is far above what a deployment
	// this size runs and low enough that a runaway generated configuration
	// fails loudly.
	MaxProducers = 32
	// MaxProducerSources caps the pairs one producer may claim.
	MaxProducerSources = 8
	// MinProducerKeyBytes is the floor on a producer key.
	//
	// Thirty-two bytes, matching what `make secrets` generates. A short key is
	// the failure this floor exists for: the credential is presented on every
	// event, so a weak one is guessable at ingest volume.
	MinProducerKeyBytes = 32
	maxSourceNameBytes  = 128
)

// sourceNamePattern bounds a claimed source name.
//
// The schema bounds source_name in length and not in content, which is how a
// NUL byte in it once reached the audit trail. An ENTITLEMENT is written by the
// operator rather than by a producer, so this is a typo check rather than a
// defence — but an entitlement that cannot match any legal event is a silent
// misconfiguration, and refusing it costs nothing.
var sourceNamePattern = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,128}$`)

// Producer is one enrolled telemetry source.
type Producer struct {
	Name        string
	Key         string
	PreviousKey string
	Sources     []httpx.SourceRef
}

// producerEnvSuffix maps a producer name onto its environment-variable suffix.
//
// Two names that differ only where this substitution flattens them would read
// the same variable, so Validate refuses the collision rather than letting one
// producer silently inherit the other's key.
func producerEnvSuffix(name string) string {
	return strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(name))
}

// loadProducers reads the keyring from the environment.
//
//	GRIEFER_PRODUCERS=okta-prod,aws-cloudtrail
//	GRIEFER_PRODUCER_OKTA_PROD_KEY=...
//	GRIEFER_PRODUCER_OKTA_PROD_PREVIOUS_KEY=...        (optional, rotation)
//	GRIEFER_PRODUCER_OKTA_PROD_SOURCES=identity_provider:okta-prod
//
// Environment rather than a file or a table: Railway has no secret-file mount,
// and a table would put the credential store behind the database whose
// compromise the audit chain already treats as the worst case — and would add a
// startup dependency to a path that must work before the platform is ready.
// The cost is that revocation is a redeploy, which ADR 0009 states plainly
// rather than dressing up.
func loadProducers() ([]Producer, error) {
	raw := strings.TrimSpace(os.Getenv("GRIEFER_PRODUCERS"))
	if raw == "" {
		return nil, nil
	}
	allowedTypes, err := schemas.SourceTypes()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	known := make(map[string]bool, len(allowedTypes))
	for _, t := range allowedTypes {
		known[t] = true
	}

	names := splitList(raw)
	if len(names) > MaxProducers {
		return nil, fmt.Errorf("config: GRIEFER_PRODUCERS lists %d producers; the limit is %d",
			len(names), MaxProducers)
	}

	seenName := map[string]bool{}
	seenSuffix := map[string]string{}
	out := make([]Producer, 0, len(names))
	for _, name := range names {
		if !httpx.ValidProducerName(name) {
			return nil, fmt.Errorf("config: producer name %q is not acceptable; "+
				"lower-case letters, digits, dot, dash and underscore, starting alphanumeric, at most 64 characters", name)
		}
		if seenName[name] {
			return nil, fmt.Errorf("config: producer %q is listed twice in GRIEFER_PRODUCERS", name)
		}
		seenName[name] = true

		suffix := producerEnvSuffix(name)
		if other, clash := seenSuffix[suffix]; clash {
			return nil, fmt.Errorf("config: producers %q and %q both read GRIEFER_PRODUCER_%s_KEY; "+
				"rename one, or the second silently inherits the first's credential", other, name, suffix)
		}
		seenSuffix[suffix] = name

		p := Producer{
			Name:        name,
			Key:         strings.TrimSpace(os.Getenv("GRIEFER_PRODUCER_" + suffix + "_KEY")),
			PreviousKey: strings.TrimSpace(os.Getenv("GRIEFER_PRODUCER_" + suffix + "_PREVIOUS_KEY")),
		}
		if p.Key == "" {
			return nil, fmt.Errorf("config: producer %q is enrolled but GRIEFER_PRODUCER_%s_KEY is empty",
				name, suffix)
		}
		if len(p.Key) < MinProducerKeyBytes {
			return nil, fmt.Errorf("config: GRIEFER_PRODUCER_%s_KEY is %d bytes; the minimum is %d. "+
				"Run `make secrets` to generate one", suffix, len(p.Key), MinProducerKeyBytes)
		}
		sources, err := parseSources(name, suffix, known)
		if err != nil {
			return nil, err
		}
		p.Sources = sources
		out = append(out, p)
	}
	return out, nil
}

func parseSources(name, suffix string, known map[string]bool) ([]httpx.SourceRef, error) {
	raw := strings.TrimSpace(os.Getenv("GRIEFER_PRODUCER_" + suffix + "_SOURCES"))
	if raw == "" {
		return nil, fmt.Errorf("config: producer %q has no GRIEFER_PRODUCER_%s_SOURCES. "+
			"A producer with no entitlement could claim any source, which is the hole "+
			"authenticating it exists to close", name, suffix)
	}
	pairs := splitList(raw)
	if len(pairs) > MaxProducerSources {
		return nil, fmt.Errorf("config: producer %q claims %d source pairs; the limit is %d",
			name, len(pairs), MaxProducerSources)
	}
	out := make([]httpx.SourceRef, 0, len(pairs))
	for _, pair := range pairs {
		sourceType, sourceName, ok := strings.Cut(pair, ":")
		if !ok {
			return nil, fmt.Errorf("config: producer %q source %q is not <source_type>:<source_name>", name, pair)
		}
		sourceType, sourceName = strings.TrimSpace(sourceType), strings.TrimSpace(sourceName)
		if !known[sourceType] {
			return nil, fmt.Errorf("config: producer %q claims source type %q, which the event schema "+
				"does not accept; an entitlement no event can match is a typo, not a policy", name, sourceType)
		}
		if len(sourceName) > maxSourceNameBytes || !sourceNamePattern.MatchString(sourceName) {
			return nil, fmt.Errorf("config: producer %q claims a source name that is empty, over %d bytes, "+
				"or carries a control character", name, maxSourceNameBytes)
		}
		out = append(out, httpx.SourceRef{Type: sourceType, Name: sourceName})
	}
	return out, nil
}

func splitList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
