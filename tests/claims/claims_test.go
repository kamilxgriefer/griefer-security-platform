// Package claims_test binds a numeric claim in the documentation to the
// constant in the code that makes it true.
//
// # WHY THIS EXISTS
//
// An adversarial review of this repository found eight places where a document
// and the code had drifted apart. Two were plain arithmetic: T10 credited
// "Graph growth" to limits that bound an edge's evidence and a query's depth
// while the entity count had no bound at all, and T9 said "five Go modules,
// three npm runtime packages" against nine and four. Nothing in CI noticed, and
// nothing would have noticed them coming back.
//
// # THE RULE THAT MAKES THIS WORTH HAVING
//
// A binding names a LOCATION, never a VALUE:
//
//	value "Unbounded queries" go:internal/storage/store.go#MaxPageSize
//
// It does not say 200. There is therefore no edit to the annotation that makes
// a false sentence pass — the only two ways to green are to fix the prose or to
// fix the code. An annotation carrying the expected number would be one more
// place for the same drift to hide, and a reviewer would read it as
// configuration rather than as a safety claim.
//
// # WHAT IS DELIBERATELY ABSENT
//
// There is no `guard` directive binding a claim to a test. It was designed and
// left out, because "this claim has a test" is exactly the assurance that
// failed here already: docs/SAFETY_MODEL.md cited
// TestSafetyContract_SingleWeakSignalDoesNotIsolate for the isolation-class
// rule, and that test accepted either reason string — so it passed with the
// rule deleted. A mechanism certifying that a test exists would have called
// that binding green and manufactured the same false confidence one layer up.
//
// Binding a claim to a test is only worth doing if the test is verified to DIE
// when the guarded behaviour is removed. That needs a mutation runner, it is
// the right next step, and it is not this.
package claims_test

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const repoRoot = "../.."

// annotatedFiles are the documents carrying claim blocks. Listed rather than
// discovered, so that deleting every annotation from a file is a visible change
// to this list and not a silently smaller check.
var annotatedFiles = []string{
	"docs/THREAT_MODEL.md",
	"docs/SAFETY_MODEL.md",
}

var claimBlock = regexp.MustCompile(`(?s)<!--\s*griefer:claims\s*(.*?)-->`)

// directive is one line of a claim block.
type directive struct {
	kind   string // value | count
	key    string // a literal substring locating the claimed sentence
	target string
	line   int
}

func parseBlocks(t *testing.T, doc string, body string) []directive {
	t.Helper()
	var out []directive
	for _, block := range claimBlock.FindAllStringSubmatch(body, -1) {
		for i, raw := range strings.Split(block[1], "\n") {
			line := strings.TrimSpace(raw)
			if line == "" {
				continue
			}
			// <kind> "<key>" <target>
			m := regexp.MustCompile(`^(\w+)\s+"([^"]+)"\s+(\S+)$`).FindStringSubmatch(line)
			if m == nil {
				t.Errorf("%s: cannot parse claim directive %q", doc, line)
				continue
			}
			switch m[1] {
			case "value", "count":
			default:
				t.Errorf("%s: unknown directive %q. This checker deliberately supports only "+
					"value and count; see the package comment for why there is no guard.", doc, m[1])
				continue
			}
			out = append(out, directive{kind: m[1], key: m[2], target: m[3], line: i})
		}
	}
	return out
}

// locate finds the single line of the document containing the key.
//
// Zero matches and more than one both fail. A reworded sentence must break its
// binding loudly rather than drift away from it quietly, and a key matching two
// places is a key that no longer identifies one claim.
func locate(t *testing.T, doc, body, key string) (string, bool) {
	t.Helper()
	var found []string
	for _, line := range strings.Split(body, "\n") {
		// The directives themselves are not the prose they bind.
		trimmed := strings.TrimSpace(line)
		if strings.Contains(line, "griefer:claims") ||
			strings.HasPrefix(trimmed, "value ") || strings.HasPrefix(trimmed, "count ") {
			continue
		}
		if strings.Contains(line, key) {
			found = append(found, line)
		}
	}
	switch len(found) {
	case 1:
		return found[0], true
	case 0:
		t.Errorf("%s: claim key %q matches no line. The sentence was reworded or removed, "+
			"and its binding is now pointing at nothing.", doc, key)
	default:
		t.Errorf("%s: claim key %q matches %d lines; it no longer identifies one claim.",
			doc, key, len(found))
	}
	return "", false
}

// resolve turns a target into the value the code actually holds.
func resolve(t *testing.T, target string) (string, bool) {
	t.Helper()
	switch {
	case strings.HasPrefix(target, "go:"):
		spec := strings.TrimPrefix(target, "go:")
		file, name, ok := strings.Cut(spec, "#")
		if !ok {
			t.Errorf("malformed go target %q, want go:<file>#<symbol>", target)
			return "", false
		}
		return resolveGoConst(t, filepath.Join(repoRoot, file), name)
	case strings.HasPrefix(target, "rego:"):
		spec := strings.TrimPrefix(target, "rego:")
		file, name, ok := strings.Cut(spec, "#")
		if !ok {
			t.Errorf("malformed rego target %q, want rego:<file>#<rule>", target)
			return "", false
		}
		return resolveRegoScalar(t, filepath.Join(repoRoot, file), name)
	case target == "gomod:direct":
		return strconv.Itoa(countDirectGoModules(t)), true
	case strings.HasPrefix(target, "npm:"):
		spec := strings.TrimPrefix(target, "npm:")
		file, section, _ := strings.Cut(spec, "#")
		return strconv.Itoa(countNPM(t, filepath.Join(repoRoot, file), section)), true
	}
	t.Errorf("unknown target kind %q", target)
	return "", false
}

// resolveRegoScalar reads a scalar rule assignment out of a Rego file.
//
// A regex rather than an evaluation: running `opa eval` would make this test
// require a tool the Go suite otherwise does not, and would fail for the wrong
// reason on a machine that lacks it. The cost is that this matches the SOURCE
// rather than the evaluated value, so it catches the drift it exists to catch —
// prose quoting a threshold the policy no longer holds — and not a rule whose
// value is computed. Every threshold worth binding here is a literal, and the
// error below says so if one stops being one.
func resolveRegoScalar(t *testing.T, path, name string) (string, bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Errorf("read %s: %v", path, err)
		return "", false
	}
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `\s*:=\s*(.+?)\s*$`)
	m := re.FindSubmatch(data)
	if m == nil {
		t.Errorf("no rule %q assigned in %s", name, path)
		return "", false
	}
	value := string(m[1])
	if _, err := strconv.ParseFloat(value, 64); err != nil {
		t.Errorf("rule %q in %s is %q, which is not a scalar this binding can check", name, path, value)
		return "", false
	}
	return value, true
}

func resolveGoConst(t *testing.T, path, name string) (string, bool) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Errorf("parse %s: %v", path, err)
		return "", false
	}
	var found ast.Expr
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, id := range vs.Names {
			if id.Name == name && i < len(vs.Values) {
				found = vs.Values[i]
			}
		}
		return true
	})
	if found == nil {
		t.Errorf("%s declares no constant %q. A binding pointing at a symbol that does not "+
			"exist is a claim nobody can check.", path, name)
		return "", false
	}
	v, ok := evalExpr(found)
	if !ok {
		t.Errorf("%s: cannot evaluate the expression bound to %q", path, name)
		return "", false
	}
	return v, true
}

// evalExpr handles the literal forms these constants actually use.
func evalExpr(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind == token.INT {
			n, err := strconv.ParseInt(strings.ReplaceAll(x.Value, "_", ""), 0, 64)
			if err != nil {
				return "", false
			}
			return strconv.FormatInt(n, 10), true
		}
		return strings.Trim(x.Value, "`\""), true
	case *ast.BinaryExpr:
		l, lok := evalExpr(x.X)
		r, rok := evalExpr(x.Y)
		if !lok || !rok {
			return "", false
		}
		li, lerr := strconv.ParseInt(l, 10, 64)
		ri, rerr := strconv.ParseInt(r, 10, 64)
		if lerr != nil || rerr != nil {
			return "", false
		}
		switch x.Op {
		case token.SHL:
			return strconv.FormatInt(li<<uint(ri), 10), true
		case token.MUL:
			return strconv.FormatInt(li*ri, 10), true
		case token.ADD:
			return strconv.FormatInt(li+ri, 10), true
		case token.SUB:
			return strconv.FormatInt(li-ri, 10), true
		}
		return "", false
	case *ast.SelectorExpr:
		// time.Second and friends, rendered as a duration.
		if pkg, ok := x.X.(*ast.Ident); ok && pkg.Name == "time" {
			switch x.Sel.Name {
			case "Nanosecond":
				return "duration:" + time.Nanosecond.String(), true
			case "Second":
				return "duration:" + time.Second.String(), true
			case "Minute":
				return "duration:" + time.Minute.String(), true
			case "Hour":
				return "duration:" + time.Hour.String(), true
			}
		}
		return "", false
	}
	return "", false
}

func countDirectGoModules(t *testing.T) int {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	n, inBlock := 0, false
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "require ("):
			inBlock = true
		case inBlock && trimmed == ")":
			inBlock = false
		case inBlock && trimmed != "" && !strings.Contains(trimmed, "// indirect"):
			n++
		}
	}
	if n == 0 {
		t.Fatal("counted zero direct Go modules; the scan is broken, not go.mod")
	}
	return n
}

func countNPM(t *testing.T, path, section string) int {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var pkg map[string]json.RawMessage
	if err := json.Unmarshal(body, &pkg); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	raw, ok := pkg[section]
	if !ok {
		t.Fatalf("%s has no %q section", path, section)
	}
	var deps map[string]string
	if err := json.Unmarshal(raw, &deps); err != nil {
		t.Fatalf("parse %s %s: %v", path, section, err)
	}
	if len(deps) == 0 {
		t.Fatalf("counted zero entries in %s %s; the scan is broken", path, section)
	}
	return len(deps)
}

var numberWords = map[int64]string{
	1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
	7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve",
}

// renderings are every spelling of a value a document may legitimately use.
func renderings(value string) []string {
	if rest, ok := strings.CutPrefix(value, "duration:"); ok {
		out := []string{rest}
		if d, err := time.ParseDuration(rest); err == nil {
			switch {
			case d == time.Second:
				out = append(out, "1 second", "one second")
			case d == time.Minute:
				out = append(out, "1 minute", "one minute")
			case d%time.Minute == 0:
				n := int64(d / time.Minute)
				out = append(out, fmt.Sprintf("%d minutes", n))
				if w, ok := numberWords[n]; ok {
					out = append(out, w+" minutes")
				}
			}
		}
		return out
	}
	out := []string{value}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return out
	}
	if w, ok := numberWords[n]; ok {
		out = append(out, w)
	}
	if n >= 1000 {
		grouped := groupThousands(value)
		out = append(out, grouped, strings.ReplaceAll(grouped, " ", ","), strings.ReplaceAll(grouped, " ", "_"))
	}
	return out
}

func groupThousands(s string) string {
	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	return strings.Join(append([]string{s}, parts...), " ")
}

// TestEveryBoundClaimMatchesTheCode.
//
// The binding names where the number lives. This resolves it and asserts the
// claimed sentence still spells it, so the two cannot drift apart without one
// of them being edited deliberately.
func TestEveryBoundClaimMatchesTheCode(t *testing.T) {
	total := 0
	for _, doc := range annotatedFiles {
		path := filepath.Join(repoRoot, doc)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		text := string(body)

		directives := parseBlocks(t, doc, text)
		if len(directives) == 0 {
			t.Errorf("%s is listed as annotated and carries no claim directives. "+
				"Either the annotations were removed or the block syntax stopped matching — "+
				"and a checker that silently checks nothing is worse than no checker.", doc)
			continue
		}
		for _, d := range directives {
			total++
			line, ok := locate(t, doc, text, d.key)
			if !ok {
				continue
			}
			value, ok := resolve(t, d.target)
			if !ok {
				continue
			}
			matched := false
			for _, r := range renderings(value) {
				if regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(r) + `\b`).MatchString(line) {
					matched = true
					break
				}
			}
			if !matched {
				t.Errorf("%s: the claim keyed %q does not state the value the code holds.\n"+
					"  code says: %s (%s)\n  prose says: %s\n"+
					"Either the bound changed and the document was not updated, or the document "+
					"was always wrong.", doc, d.key, value, d.target, strings.TrimSpace(line))
			}
		}
	}
	if total == 0 {
		t.Fatal("no claim directives were checked at all; this test is not guarding anything")
	}
	t.Logf("checked %d bound claims", total)
}

// TestEveryClaimBlockIsChecked closes the trap the list above would otherwise set.
//
// annotatedFiles is deliberate rather than discovered, for the reason stated
// where it is declared. The cost of that choice is a silent one: a claim block
// added to a document nobody listed is never read, and its author sees a green
// suite and believes their number is bound. That is a worse position than
// having no binding, because it is a binding they now trust.
//
// This test was added after exactly that happened — a block landed in
// SAFETY_MODEL.md, the value it bound was changed by hand to a wrong number,
// and the suite stayed green.
func TestEveryClaimBlockIsChecked(t *testing.T) {
	listed := make(map[string]bool, len(annotatedFiles))
	for _, doc := range annotatedFiles {
		listed[filepath.Clean(doc)] = true
	}

	err := filepath.WalkDir(filepath.Join(repoRoot, "docs"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".md") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !claimBlock.Match(body) {
			return nil
		}
		rel, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}
		if !listed[filepath.Clean(rel)] {
			t.Errorf("%s carries a griefer:claims block and is not in annotatedFiles, "+
				"so nothing checks it. Add it to the list, or delete the block — a "+
				"binding nobody reads is worse than none, because its author trusts it.", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk docs: %v", err)
	}
}
