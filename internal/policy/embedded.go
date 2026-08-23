package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
	"github.com/kamilxgriefer/griefer-security-platform/policies"
)

// EmbeddedKernel evaluates the Rego policy in-process using the Open Policy
// Agent Go library.
//
// It exists so that policy is enforceable without a running sidecar: tests, CI
// and single-binary deployments evaluate byte-identical Rego to the OPA
// container used by the Compose stack.
type EmbeddedKernel struct {
	query rego.PreparedEvalQuery
	now   func() time.Time
}

// NewEmbeddedKernel compiles the embedded policy. Compilation happens once, at
// construction, so a broken policy fails startup rather than the first
// incident.
func NewEmbeddedKernel() (*EmbeddedKernel, error) {
	return NewEmbeddedKernelFromFS(policies.FS, policies.Dir)
}

// NewEmbeddedKernelFromFS compiles every .rego file under dir in fsys.
func NewEmbeddedKernelFromFS(fsys fs.FS, dir string) (*EmbeddedKernel, error) {
	modules, err := collectModules(fsys, dir)
	if err != nil {
		return nil, err
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("policy: no rego modules found under %q", dir)
	}

	opts := []func(*rego.Rego){rego.Query(policies.Query)}
	for path, src := range modules {
		opts = append(opts, rego.Module(path, src))
	}
	// Compilation is bounded: a policy that cannot compile promptly is a build
	// error, not something to wait on at runtime.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	prepared, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: compile embedded policy: %w", err)
	}
	return &EmbeddedKernel{
		query: prepared,
		now:   func() time.Time { return time.Now().UTC() },
	}, nil
}

func collectModules(fsys fs.FS, dir string) (map[string]string, error) {
	modules := map[string]string{}
	err := fs.WalkDir(fsys, dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}
		raw, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("read policy %s: %w", path, err)
		}
		modules[path] = string(raw)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("policy: walk %q: %w", dir, err)
	}
	return modules, nil
}

// Engine implements Kernel.
func (k *EmbeddedKernel) Engine() string { return EngineEmbedded }

// Close implements Kernel. The embedded kernel holds no external resources.
func (k *EmbeddedKernel) Close() error { return nil }

// Health implements Kernel by evaluating a known-good probe input. A kernel
// that compiles but cannot produce a decision is not healthy.
func (k *EmbeddedKernel) Health(ctx context.Context) error {
	_, err := k.evaluate(ctx, probeInput())
	return err
}

// Evaluate implements Kernel.
func (k *EmbeddedKernel) Evaluate(ctx context.Context, in Input) (incidents.PolicyDecision, error) {
	decision, err := k.evaluate(ctx, in)
	if err != nil {
		return failClosed(EngineEmbedded,
			"Policy Kernel could not evaluate this request; GRIEFER fails closed and denies the action. "+err.Error(),
			time.Now()), err
	}
	return decision, nil
}

func (k *EmbeddedKernel) evaluate(ctx context.Context, in Input) (incidents.PolicyDecision, error) {
	results, err := k.query.Eval(ctx, rego.EvalInput(in))
	if err != nil {
		return incidents.PolicyDecision{}, fmt.Errorf("evaluate policy: %w", err)
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return incidents.PolicyDecision{}, fmt.Errorf("policy produced no decision document")
	}
	encoded, err := json.Marshal(results[0].Expressions[0].Value)
	if err != nil {
		return incidents.PolicyDecision{}, fmt.Errorf("encode policy decision: %w", err)
	}
	var raw rawDecision
	if err := json.Unmarshal(encoded, &raw); err != nil {
		return incidents.PolicyDecision{}, fmt.Errorf("decode policy decision: %w", err)
	}
	decision, ok := raw.toDecision(EngineEmbedded, k.now())
	if !ok {
		return incidents.PolicyDecision{}, fmt.Errorf("policy returned a malformed decision (effect=%q, reasons=%d)", raw.Effect, len(raw.Reasons))
	}
	return decision, nil
}

// probeInput is a minimal, definitely-valid decision request used for health
// checks. It must never be treated as a real authorization.
func probeInput() Input {
	return Input{
		Action: ActionInput{
			Type: "preserve_evidence", Mode: "simulate", Known: true,
			Destructive: false, Reversible: true,
			RollbackAction: "release_evidence_hold",
		},
		Incident: IncidentInput{ID: "healthcheck", RiskScore: 0, EvidenceCategories: []string{}},
		Request:  RequestInput{Automated: true, RequestedBy: "healthcheck"},
	}
}
