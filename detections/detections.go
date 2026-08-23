// Package detections embeds GRIEFER's detection content so that a built binary
// carries the same rules that were reviewed in the repository.
package detections

import "embed"

// CorrelationFS holds the declarative correlation rules evaluated by
// internal/correlation.
//
//go:embed correlation/*.yaml
var CorrelationFS embed.FS

// SigmaFS holds Sigma rules published for export to external SIEM/EDR
// platforms. GRIEFER v0.1 does NOT evaluate Sigma rules internally; they are
// shipped as portable detection content and validated for well-formedness by
// the test suite. Native Sigma evaluation is tracked as milestone M5.
//
//go:embed sigma/*.yaml
var SigmaFS embed.FS

// CorrelationDir and SigmaDir name the embedded directories.
const (
	CorrelationDir = "correlation"
	SigmaDir       = "sigma"
)
