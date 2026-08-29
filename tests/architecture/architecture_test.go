// Package architecture_test holds structural properties: facts about the SHAPE
// of the code that no runtime test can hold shut.
//
// A runtime test proves the door that exists is locked. These prove no second
// door was cut — which is the failure mode a security control actually dies of,
// months later, when someone adds a plausible new entry point and every existing
// test still passes.
package architecture_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

const repoRoot = "../.."

// TestEventsEnterThroughExactlyOneDoor holds the producer bar's foundation.
//
// ADR 0010 lets the Policy Kernel automate on "two distinct producers", and
// every producer name on an incident is server-owned: set in the ingest handler
// from the credential the keyring verified, and never from the request body.
//
// That reasoning holds only while ingest is the ONLY way an event reaches
// storage. A second path — a NATS consumer, a demo seeder, a backfill command,
// an admin import — would write events carrying NO producer, and an incident
// built entirely from them has a producer count of zero. Zero does not fire the
// bar. So a new door does not merely bypass authentication; it silently returns
// that deployment to the weaker gate it thinks it left behind, and every test in
// this repository still passes.
//
// If this test fails because you added a legitimate ingest path, the fix is to
// give that path a producer identity — not to add it to the list below.
func TestEventsEnterThroughExactlyOneDoor(t *testing.T) {
	// The one caller, and the storage layer's own definitions of the method.
	allowed := map[string]bool{
		"internal/api/service.go":      true,
		"internal/storage/memory.go":   true,
		"internal/storage/postgres.go": true,
		"internal/storage/store.go":    true,
	}

	callers := callSites(t, "SaveEvent")
	for file, count := range callers {
		if !allowed[file] {
			t.Errorf("%s calls SaveEvent %d time(s).\n"+
				"Events must enter through the ingest handler, which is the only place a "+
				"producer credential is verified and the only place ProducerID is set. "+
				"An event stored around it carries no producer, and an incident built from "+
				"such events has a producer count of zero — which does not fire the "+
				"corroboration bar (ADR 0010).", file, count)
		}
	}
	if callers["internal/api/service.go"] == 0 {
		t.Error("nothing in internal/api/service.go calls SaveEvent; this test has stopped " +
			"watching the thing it was written to watch")
	}
}

// TestProducerIDIsNeverReadFromARequestBody holds the other half.
//
// One door is worth nothing if the doorman copies the name off the visitor's own
// badge. ProducerID is assigned from the verified credential and zeroed during
// normalisation; a json tag on the field would let a caller name itself.
func TestProducerIDIsNeverReadFromARequestBody(t *testing.T) {
	path := filepath.Join(repoRoot, "internal/events/event.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var checked bool
	ast.Inspect(f, func(n ast.Node) bool {
		field, ok := n.(*ast.Field)
		if !ok || len(field.Names) != 1 || field.Names[0].Name != "ProducerID" {
			return true
		}
		checked = true
		if field.Tag == nil {
			return false
		}
		tag := field.Tag.Value
		if strings.Contains(tag, `json:"-"`) {
			return false
		}
		// A named, non-ignored json tag is only safe while normalisation zeroes
		// the field. That it does is asserted at runtime elsewhere; what this
		// test refuses is the tag losing its omitempty/ignore shape unnoticed.
		if !strings.Contains(tag, "producer_id") {
			t.Errorf("ProducerID carries an unexpected json tag %s; a producer must not be "+
				"able to name itself in a request body", tag)
		}
		return false
	})
	if !checked {
		t.Fatal("no ProducerID field found in internal/events/event.go; this test is " +
			"watching a field that moved")
	}
}

// callSites counts calls to a method name per repo-relative file, skipping
// tests and vendored code.
func callSites(t *testing.T, method string) map[string]int {
	t.Helper()
	out := map[string]int{}
	roots := []string{"internal", "cmd"}
	for _, root := range roots {
		err := filepath.WalkDir(filepath.Join(repoRoot, root), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, parseErr := parser.ParseFile(fset, path, nil, 0)
			if parseErr != nil {
				return parseErr
			}
			rel, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				return relErr
			}
			rel = filepath.ToSlash(rel)
			ast.Inspect(f, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CallExpr:
					if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == method {
						out[rel]++
					}
				case *ast.FuncDecl:
					// A definition or an interface method counts as presence, so
					// the storage layer's own files are named in the allow list
					// rather than being invisible.
					if node.Name.Name == method {
						out[rel]++
					}
				case *ast.InterfaceType:
					for _, m := range node.Methods.List {
						for _, name := range m.Names {
							if name.Name == method {
								out[rel]++
							}
						}
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	return out
}
