package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
)

// maxPolicyResponseBytes bounds how much a policy endpoint may return. The
// Policy Kernel is a trusted component, but "trusted" is a deployment
// assumption, not a memory-safety guarantee.
const maxPolicyResponseBytes = 256 << 10

// RemoteKernel evaluates policy against an Open Policy Agent server over HTTP.
//
// This is the deployment shape used by the local Compose stack: OPA runs as its
// own container with the policy tree mounted read-only, so policy can be
// reloaded and audited independently of the GRIEFER binary.
type RemoteKernel struct {
	client      *http.Client
	decisionURL string
	healthURL   string
	timeout     time.Duration
	now         func() time.Time
}

// RemoteOptions configures a RemoteKernel.
type RemoteOptions struct {
	// BaseURL is the OPA server root, e.g. http://localhost:8181.
	BaseURL string
	// DecisionPath is the data path of the decision document, e.g.
	// "griefer/response/decision".
	DecisionPath string
	// Timeout bounds a single evaluation. A policy decision that takes longer
	// than this is treated as unavailable and fails closed.
	Timeout time.Duration
	// Client is optional; a bounded default is used when nil.
	Client *http.Client
}

// NewRemoteKernel builds a kernel that talks to an OPA server.
func NewRemoteKernel(opts RemoteOptions) (*RemoteKernel, error) {
	if opts.BaseURL == "" {
		return nil, fmt.Errorf("policy: remote kernel requires a base URL")
	}
	base, err := url.Parse(strings.TrimSuffix(opts.BaseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("policy: invalid OPA base URL: %w", err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("policy: OPA base URL must be http or https, got %q", base.Scheme)
	}
	path := strings.Trim(opts.DecisionPath, "/")
	if path == "" {
		return nil, fmt.Errorf("policy: remote kernel requires a decision path")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &RemoteKernel{
		client:      client,
		decisionURL: base.String() + "/v1/data/" + path,
		healthURL:   base.String() + "/health",
		timeout:     timeout,
		now:         func() time.Time { return time.Now().UTC() },
	}, nil
}

// Engine implements Kernel.
func (k *RemoteKernel) Engine() string { return EngineRemote }

// Close implements Kernel.
func (k *RemoteKernel) Close() error {
	k.client.CloseIdleConnections()
	return nil
}

// Health implements Kernel by querying OPA's health endpoint.
func (k *RemoteKernel) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, k.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.healthURL, nil)
	if err != nil {
		return fmt.Errorf("policy: build health request: %w", err)
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("policy: OPA health request failed: %w", err)
	}
	defer func() {
		// Drain before closing so the connection can be reused rather than
		// torn down after every probe.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxPolicyResponseBytes))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("policy: OPA health returned status %d", resp.StatusCode)
	}
	return nil
}

// Evaluate implements Kernel. Every failure path returns a fail-closed deny.
func (k *RemoteKernel) Evaluate(ctx context.Context, in Input) (incidents.PolicyDecision, error) {
	decision, err := k.evaluate(ctx, in)
	if err != nil {
		return failClosed(EngineUnavailable,
			"Policy Kernel is unreachable or returned an unusable decision; GRIEFER fails closed and denies the action. "+err.Error(),
			k.now()), err
	}
	return decision, nil
}

func (k *RemoteKernel) evaluate(ctx context.Context, in Input) (incidents.PolicyDecision, error) {
	body, err := json.Marshal(struct {
		Input Input `json:"input"`
	}{Input: in})
	if err != nil {
		return incidents.PolicyDecision{}, fmt.Errorf("encode policy input: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, k.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.decisionURL, bytes.NewReader(body))
	if err != nil {
		return incidents.PolicyDecision{}, fmt.Errorf("build policy request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return incidents.PolicyDecision{}, fmt.Errorf("policy request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxPolicyResponseBytes))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return incidents.PolicyDecision{}, fmt.Errorf("policy endpoint returned status %d", resp.StatusCode)
	}

	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicyResponseBytes))
	if err != nil {
		return incidents.PolicyDecision{}, fmt.Errorf("read policy response: %w", err)
	}

	var envelope struct {
		Result *rawDecision `json:"result"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return incidents.PolicyDecision{}, fmt.Errorf("decode policy response: %w", err)
	}
	if envelope.Result == nil {
		// OPA returns 200 with an empty body when the document is undefined,
		// for example because the policy was not loaded. Undefined is not
		// permission.
		return incidents.PolicyDecision{}, fmt.Errorf("policy document is undefined at the configured decision path")
	}
	decision, ok := envelope.Result.toDecision(EngineRemote, k.now())
	if !ok {
		return incidents.PolicyDecision{}, fmt.Errorf("policy returned a malformed decision (effect=%q, reasons=%d)",
			envelope.Result.Effect, len(envelope.Result.Reasons))
	}
	return decision, nil
}
