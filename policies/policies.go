// Package policies embeds the Rego source evaluated by GRIEFER's Policy Kernel.
//
// The same files are mounted into the OPA sidecar by the local Compose stack, so
// the embedded kernel used in tests and the remote kernel used at runtime
// evaluate byte-identical policy.
package policies

import "embed"

// FS holds the Rego policy tree.
//
//go:embed rego/griefer/*.rego
var FS embed.FS

// Constants describing the response-authorization entrypoint.
const (
	// Dir is the embedded policy root.
	Dir = "rego"
	// Package is the Rego package implementing response authorization.
	Package = "griefer.response"
	// Query is the fully-qualified decision document.
	Query = "data.griefer.response.decision"
	// DecisionPath is the OPA REST path to the same document.
	DecisionPath = "griefer/response/decision"
	// Version must track policy_version in response.rego.
	Version = "0.1.0"
)
