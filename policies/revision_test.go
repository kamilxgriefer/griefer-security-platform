package policies_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"testing"

	"github.com/kamilxgriefer/griefer-security-platform/policies"
)

// regoFile is one (path, content) pair as the revision algorithm sees it.
type regoFile struct {
	path    string
	content []byte
}

// digestInOrder hashes files in exactly the order given, WITHOUT sorting them.
//
// This is the inner half of a local reimplementation of policies.Revision().
// Keeping the sort out of it is what lets the tests below prove two separate
// things: that visit order changes the digest when it is not normalised (so the
// sort in Revision is load-bearing, not decoration), and that Revision's own
// output is order-independent because it sorts first.
func digestInOrder(t *testing.T, files []regoFile) string {
	t.Helper()
	sum := sha256.New()
	for _, f := range files {
		// Mirrors Revision(): path length-prefixed, then content
		// length-prefixed, then the bytes.
		fmt.Fprintf(sum, "%d:%s\n", len(f.path), f.path)
		fmt.Fprintf(sum, "%d:\n", len(f.content))
		sum.Write(f.content)
	}
	return "sha256:" + hex.EncodeToString(sum.Sum(nil))
}

// digestOf is the full local reimplementation of policies.Revision(): sort by
// path, then hash.
//
// Tests use this rather than editing .rego files on disk. A test that mutated
// the real policy tree to prove the revision moves would be a test that can
// leave the working tree broken when it fails partway through, and the policy
// tree is the one thing in this repo that must never be edited by accident.
func digestOf(t *testing.T, files []regoFile) string {
	t.Helper()
	sorted := make([]regoFile, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].path < sorted[j].path })
	return digestInOrder(t, sorted)
}

// embeddedRegoFiles reads the real embedded policy tree. With includeTests
// false it applies the same "_test.rego is not policy" filter Revision uses.
func embeddedRegoFiles(t *testing.T, includeTests bool) []regoFile {
	t.Helper()
	var files []regoFile
	err := fs.WalkDir(policies.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}
		if !includeTests && strings.HasSuffix(path, "_test.rego") {
			return nil
		}
		content, readErr := policies.FS.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		files = append(files, regoFile{path: path, content: content})
		return nil
	})
	if err != nil {
		t.Fatalf("walking policies.FS: %v", err)
	}
	return files
}

// syntheticTree is a three-file stand-in used wherever a case needs more files
// than the embedded tree happens to contain, or needs content the real policy
// must not be edited to provide.
func syntheticTree() []regoFile {
	return []regoFile{
		{path: "rego/griefer/response.rego", content: []byte("package griefer.response\ndefault allow := false\n")},
		{path: "rego/griefer/isolation.rego", content: []byte("package griefer.isolation\ndefault allow := false\n")},
		{path: "rego/griefer/evidence.rego", content: []byte("package griefer.evidence\ncategories := 2\n")},
	}
}

func TestRevisionReturnsTheSameValueOnRepeatedCalls(t *testing.T) {
	// Every audit entry written during a process's lifetime is stamped with
	// this string. If it drifted between calls, two entries recorded seconds
	// apart would claim different policy was in force, and the audit trail
	// would be useless for answering "which rules denied this action?".
	first := policies.Revision()
	for i := 0; i < 5; i++ {
		if got := policies.Revision(); got != first {
			t.Fatalf("Revision() call %d = %q, want the stable %q", i+2, got, first)
		}
	}
}

func TestRevisionIsPrefixedSHA256WithLowercaseHexDigest(t *testing.T) {
	rev := policies.Revision()

	const prefix = "sha256:"
	if !strings.HasPrefix(rev, prefix) {
		t.Fatalf("Revision() = %q, want the %q prefix that names the hash function", rev, prefix)
	}
	digest := strings.TrimPrefix(rev, prefix)

	// The sentinel Revision returns when the embedded FS cannot be read. It is
	// well-formed enough to store but is not a digest, so catch it explicitly
	// rather than letting it fail the hex check with a confusing message.
	if digest == "unavailable" {
		t.Fatal("Revision() = sha256:unavailable; the embedded policy tree could not be read")
	}

	if len(digest) != sha256.Size*2 {
		t.Errorf("digest %q is %d chars, want %d for a full SHA-256", digest, len(digest), sha256.Size*2)
	}
	// Lowercase specifically: the value is compared as a string in audit
	// queries and diffed across deployments, so a case flip would read as a
	// policy change that never happened.
	for i, r := range digest {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			t.Errorf("digest %q has %q at index %d, want only lowercase hex", digest, r, i)
			break
		}
	}
	if _, err := hex.DecodeString(digest); err != nil {
		t.Errorf("hex.DecodeString(%q) error = %v", digest, err)
	}
}

func TestRevisionIsNotTheHandMaintainedVersionConstant(t *testing.T) {
	// The whole reason Revision exists: Version is a string a human has to
	// remember to bump, and it has read the same through every policy edit so
	// far. A revision that merely echoed it would give auditors false
	// confidence that the field tracks the rules.
	rev := policies.Revision()
	if rev == policies.Version {
		t.Fatalf("Revision() = %q, the same as the Version constant; it must be derived from content", rev)
	}
	if strings.Contains(rev, policies.Version) {
		t.Errorf("Revision() = %q embeds the Version constant %q", rev, policies.Version)
	}
}

func TestRevisionMatchesAnIndependentHashOfTheEmbeddedPolicy(t *testing.T) {
	files := embeddedRegoFiles(t, false)

	// Guard against a vacuous suite. If the //go:embed pattern ever stops
	// matching, Revision would happily return the digest of an empty file set
	// — a perfectly valid-looking hash for no policy at all — and every test
	// below would still pass.
	if len(files) == 0 {
		t.Fatal("the embedded FS contains no non-test .rego files; the //go:embed pattern matches nothing")
	}
	if rev := policies.Revision(); rev == digestOf(t, nil) {
		t.Fatalf("Revision() = %q, the digest of an empty policy set", rev)
	}

	// Establishes that the local reimplementation is faithful, which is what
	// licenses the mutation cases below to draw conclusions about Revision.
	if got, want := policies.Revision(), digestOf(t, files); got != want {
		t.Errorf("Revision() = %q, independently computed digest = %q", got, want)
	}
}

func TestRevisionAlgorithmChangesWhenPolicyContentChanges(t *testing.T) {
	baseline := embeddedRegoFiles(t, false)
	if len(baseline) == 0 {
		t.Fatal("the embedded FS contains no non-test .rego files")
	}
	baselineDigest := digestOf(t, baseline)
	if baselineDigest != policies.Revision() {
		t.Fatalf("local reimplementation disagrees with Revision(): %q vs %q", baselineDigest, policies.Revision())
	}

	// mutate receives a deep copy, so a case cannot corrupt the baseline for
	// the next one.
	tests := []struct {
		name   string
		mutate func([]regoFile) []regoFile
	}{
		{
			name: "a single flipped byte in a rule",
			mutate: func(files []regoFile) []regoFile {
				files[0].content[len(files[0].content)-1] ^= 0x01
				return files
			},
		},
		{
			name: "a rule appended to an existing file",
			mutate: func(files []regoFile) []regoFile {
				files[0].content = append(files[0].content, []byte("\nallow if { true }\n")...)
				return files
			},
		},
		{
			name: "a byte removed from an existing file",
			mutate: func(files []regoFile) []regoFile {
				files[0].content = files[0].content[:len(files[0].content)-1]
				return files
			},
		},
		{
			name: "a whole new policy file added",
			mutate: func(files []regoFile) []regoFile {
				return append(files, regoFile{
					path:    "rego/griefer/shadow.rego",
					content: []byte("package griefer.shadow\nallow := true\n"),
				})
			},
		},
		{
			name: "a policy file removed",
			mutate: func(files []regoFile) []regoFile {
				return files[1:]
			},
		},
		{
			name: "a file renamed with its contents untouched",
			mutate: func(files []regoFile) []regoFile {
				// Path is mixed into the hash on purpose: moving a rule to a
				// different package changes which decisions it participates
				// in, even though not one byte of it changed.
				files[0].path = "rego/griefer/renamed.rego"
				return files
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := tt.mutate(copyFiles(baseline))
			if got := digestOf(t, mutated); got == baselineDigest {
				t.Errorf("digest after %s = %q, unchanged from the baseline; the change would be invisible in the audit trail", tt.name, got)
			}
		})
	}
}

func TestRevisionAlgorithmDistinguishesContentMovedAcrossFileBoundaries(t *testing.T) {
	// Without the length prefixes, concatenating path and content would let
	// two genuinely different policy trees hash identically: an attacker who
	// could add or rename files could split the same bytes differently and
	// keep the recorded revision stable while changing which package each rule
	// lands in. The two trees below hold identical bytes, split differently.
	left := []regoFile{
		{path: "rego/griefer/a.rego", content: []byte("packag")},
		{path: "rego/griefer/b.rego", content: []byte("e griefer.a\n")},
	}
	right := []regoFile{
		{path: "rego/griefer/a.rego", content: []byte("package")},
		{path: "rego/griefer/b.rego", content: []byte(" griefer.a\n")},
	}
	if digestOf(t, left) == digestOf(t, right) {
		t.Error("two different file layouts holding the same bytes produced the same digest; the length prefixes are not separating them")
	}
}

func TestRevisionAlgorithmIgnoresFileVisitOrder(t *testing.T) {
	files := syntheticTree()
	perms := permutations(files)
	if len(perms) != 6 {
		t.Fatalf("permutations() produced %d orderings of 3 files, want 6", len(perms))
	}

	// Revision does not rely on embed.FS or fs.WalkDir handing paths back in
	// any particular order — those are implementation details of the standard
	// library. A revision that silently depended on them would change when the
	// toolchain changed, which reads as a policy edit that never happened.
	want := digestOf(t, files)
	for _, perm := range perms {
		if got := digestOf(t, perm); got != want {
			t.Errorf("digest of ordering %v = %q, want the order-independent %q", pathsOf(perm), got, want)
		}
	}

	// Proves the previous loop is not vacuous: order genuinely matters to the
	// hash, and it is the sort inside the algorithm that neutralises it.
	unsorted := make(map[string]bool)
	for _, perm := range perms {
		unsorted[digestInOrder(t, perm)] = true
	}
	if len(unsorted) < 2 {
		t.Error("hashing without sorting produced one digest for every ordering; the sort in Revision() is untested by this case")
	}
}

func TestRevisionExcludesRegoTestFiles(t *testing.T) {
	withTests := embeddedRegoFiles(t, true)
	withoutTests := embeddedRegoFiles(t, false)

	// Without a real _test.rego in the embedded tree this test proves nothing,
	// so say so loudly rather than passing by default.
	if len(withTests) == len(withoutTests) {
		t.Fatal("the embedded FS contains no _test.rego files; the exclusion cannot be observed")
	}

	if got, want := policies.Revision(), digestOf(t, withoutTests); got != want {
		t.Errorf("Revision() = %q, want the digest over only non-test .rego files %q", got, want)
	}
	// Rego tests are never evaluated at runtime. Folding them in would move
	// the revision whenever someone added a test case, which trains reviewers
	// to ignore revision churn — exactly the habit this field must not create.
	if got := digestOf(t, withTests); got == policies.Revision() {
		t.Errorf("Revision() = %q equals the digest computed WITH _test.rego files included", got)
	}
}

func copyFiles(files []regoFile) []regoFile {
	out := make([]regoFile, len(files))
	for i, f := range files {
		content := make([]byte, len(f.content))
		copy(content, f.content)
		out[i] = regoFile{path: f.path, content: content}
	}
	return out
}

// permutations returns every ordering of files, so the order-independence case
// is exhaustive and deterministic rather than a random shuffle that might
// happen to reproduce sorted order.
func permutations(files []regoFile) [][]regoFile {
	if len(files) <= 1 {
		return [][]regoFile{copyFiles(files)}
	}
	var out [][]regoFile
	for i := range files {
		rest := make([]regoFile, 0, len(files)-1)
		rest = append(rest, files[:i]...)
		rest = append(rest, files[i+1:]...)
		for _, tail := range permutations(rest) {
			out = append(out, append([]regoFile{files[i]}, tail...))
		}
	}
	return out
}

func pathsOf(files []regoFile) []string {
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = f.path
	}
	return paths
}
