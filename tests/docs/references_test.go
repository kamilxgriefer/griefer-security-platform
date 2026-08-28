// Package docs_test checks that the documentation's references point at things
// that exist.
//
// This is the cheap half of binding a claim to a check, and it exists because
// the expensive half missed something obvious. Two source files pointed at
// docs/DEMO_SECURITY.md for the limits of the console access gate, and that file
// had never been written — so the caveats of a security control lived nowhere,
// and nothing noticed for as long as the reference stood.
//
// A named test is the same shape of promise. docs/SAFETY_MODEL.md cites tests
// beside the rules they protect; a rename turns that citation into a claim
// about a guard nobody can find, and the document goes on looking rigorous.
//
// What this does NOT check is whether a cited test asserts what the prose says
// it does. That is the harder half and a different mechanism. Existence is the
// floor, not the ceiling — see the isolation-rule case in
// policies/rego/griefer/response_test.rego, where the cited test existed and
// would not have noticed the rule being deleted.
package docs_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRoot is two levels up from tests/docs.
const repoRoot = "../.."

// goTestName matches an exported Go test identifier as it appears in prose.
// Anchored on the Test prefix and an upper-case letter after it, so ordinary
// words are not mistaken for identifiers.
var goTestName = regexp.MustCompile(`\bTest[A-Z][A-Za-z0-9_]{3,}\b`)

// regoTestName matches a Rego test rule, which is lower_snake_case by convention.
var regoTestName = regexp.MustCompile(`\btest_[a-z0-9_]{4,}\b`)

// markdownLink matches [text](target), which is the only link form used here.
var markdownLink = regexp.MustCompile(`\[[^\]]*\]\(([^)]+)\)`)

// documentedFiles are the files whose references this test holds to account.
func documentedFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	roots := []string{"docs", "README.md", "SECURITY.md", "CONTRIBUTING.md"}
	for _, root := range roots {
		path := filepath.Join(repoRoot, root)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if !info.IsDir() {
			out = append(out, path)
			continue
		}
		err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(p, ".md") {
				out = append(out, p)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", path, err)
		}
	}
	if len(out) == 0 {
		t.Fatal("no documentation files found; this test is not checking anything")
	}
	return out
}

// declaredTests collects every test identifier the repository actually defines.
func declaredTests(t *testing.T) (goTests, regoTests map[string]bool) {
	t.Helper()
	goTests, regoTests = map[string]bool{}, map[string]bool{}
	goFunc := regexp.MustCompile(`func\s+(Test[A-Za-z0-9_]+)\s*\(`)
	regoRule := regexp.MustCompile(`(?m)^(test_[a-z0-9_]+)\s+if\s*\{`)

	err := filepath.WalkDir(repoRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", ".next":
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasSuffix(p, "_test.go"):
			body, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, m := range goFunc.FindAllStringSubmatch(string(body), -1) {
				goTests[m[1]] = true
			}
		case strings.HasSuffix(p, "_test.rego"):
			body, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, m := range regoRule.FindAllStringSubmatch(string(body), -1) {
				regoTests[m[1]] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
	if len(goTests) == 0 || len(regoTests) == 0 {
		t.Fatalf("found %d Go tests and %d Rego tests; the scan is broken, not the docs",
			len(goTests), len(regoTests))
	}
	return goTests, regoTests
}

// namesSomething reports whether a cited identifier addresses at least one real
// test.
//
// A prefix counts. The documents legitimately cite a family — `go test -run
// TestSafetyContract` and `TestSafetyContract_*` both address nine real tests —
// and demanding an exact match would fail those while teaching nobody anything.
// A name that prefixes nothing still fails, which is the case worth catching.
func namesSomething(cited string, declared map[string]bool) bool {
	if declared[cited] {
		return true
	}
	for name := range declared {
		if strings.HasPrefix(name, cited) {
			return true
		}
	}
	return false
}

// TestEveryTestNamedInProseExists.
//
// A citation is a promise that something is guarded. A rename leaves the promise
// standing and the guard unfindable, and the document goes on reading as though
// the control were pinned.
func TestEveryTestNamedInProseExists(t *testing.T) {
	goTests, regoTests := declaredTests(t)

	for _, doc := range documentedFiles(t) {
		body, err := os.ReadFile(doc)
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		text := string(body)
		rel, _ := filepath.Rel(repoRoot, doc)

		for _, name := range goTestName.FindAllString(text, -1) {
			if !namesSomething(name, goTests) {
				t.Errorf("%s names Go test %s, which does not exist.\n"+
					"Either the test was renamed and the citation is now a claim about a "+
					"guard nobody can find, or the guard was never written.", rel, name)
			}
		}
		for _, name := range regoTestName.FindAllString(text, -1) {
			if !namesSomething(name, regoTests) {
				t.Errorf("%s names Rego test %s, which does not exist.", rel, name)
			}
		}
	}
}

// TestEveryDocumentReferenceResolves.
//
// docs/DEMO_SECURITY.md was cited from two source files for the limits of the
// console access gate and had never been written, so those limits lived nowhere
// while the citation made it look as though they were written down.
func TestEveryDocumentReferenceResolves(t *testing.T) {
	for _, doc := range documentedFiles(t) {
		body, err := os.ReadFile(doc)
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		rel, _ := filepath.Rel(repoRoot, doc)
		dir := filepath.Dir(doc)

		for _, m := range markdownLink.FindAllStringSubmatch(string(body), -1) {
			target := strings.TrimSpace(m[1])
			// External links and pure anchors are somebody else's problem.
			if target == "" || strings.HasPrefix(target, "#") ||
				strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			// A trailing anchor addresses a heading inside the file.
			if i := strings.Index(target, "#"); i >= 0 {
				target = target[:i]
			}
			if target == "" {
				continue
			}
			resolved := filepath.Join(dir, target)
			if strings.HasPrefix(target, "/") {
				resolved = filepath.Join(repoRoot, strings.TrimPrefix(target, "/"))
			}
			if _, err := os.Stat(resolved); err != nil {
				t.Errorf("%s links to %q, which does not exist.\n"+
					"A reference to a document nobody wrote reads exactly like one to a "+
					"document somebody did.", rel, m[1])
			}
		}
	}
}
