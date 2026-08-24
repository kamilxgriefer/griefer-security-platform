// Package policies embeds the Rego source evaluated by GRIEFER's Policy Kernel.
//
// The same files are mounted into the OPA sidecar by the local Compose stack, so
// the embedded kernel used in tests and the remote kernel used at runtime
// evaluate byte-identical policy.
package policies

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

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

// Revision identifies the policy tree that produced a decision.
//
// It is a SHA-256 over the embedded Rego source: every non-test file, visited
// in sorted path order, with the path mixed in alongside the bytes so that
// renaming a file changes the revision even when its contents do not.
//
// Why a content hash rather than the Version constant above: Version is a
// string somebody has to remember to change. It has read "0.1.0" through every
// edit the policy has ever had, so an audit entry stamped with it cannot tell
// you which rules were in force. A content hash cannot be forgotten.
//
// Test files are excluded deliberately. They are not evaluated, and including
// them would move the revision when nothing about the rules changed — which
// trains people to ignore the field.
//
// Determinism is the whole point, so the walk is explicitly sorted rather than
// relying on filesystem order: embed.FS happens to be sorted today, and a
// revision that silently depended on that would be a revision that changes
// when the standard library does.
func Revision() string {
	paths := make([]string, 0, 8)
	err := fs.WalkDir(FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") || strings.HasSuffix(path, "_test.rego") {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		// Unreachable for an embedded FS, which cannot fail to be read. A
		// sentinel rather than a panic: an audit entry that says the revision
		// is unknown is far better than a platform that will not start.
		return "sha256:unavailable"
	}
	sort.Strings(paths)

	sum := sha256.New()
	for _, path := range paths {
		content, readErr := FS.ReadFile(path)
		if readErr != nil {
			return "sha256:unavailable"
		}
		// Length-prefixing the path stops two different file layouts hashing
		// the same way by running their names and contents together.
		//
		// The errors are discarded deliberately: hash.Hash documents that Write
		// never returns one, so checking them would add a branch that cannot be
		// taken and cannot be tested.
		_, _ = fmt.Fprintf(sum, "%d:%s\n", len(path), path)
		_, _ = fmt.Fprintf(sum, "%d:\n", len(content))
		_, _ = sum.Write(content)
	}
	return "sha256:" + hex.EncodeToString(sum.Sum(nil))
}
