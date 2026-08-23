package incidents_test

import (
	"errors"
	"testing"

	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
)

func TestCatalogInvariants(t *testing.T) {
	for _, actionType := range incidents.KnownActionTypes() {
		spec, err := incidents.Lookup(actionType)
		if err != nil {
			t.Fatalf("Lookup(%q) error = %v", actionType, err)
		}
		t.Run(actionType, func(t *testing.T) {
			if spec.Type != actionType {
				t.Errorf("Type = %q, want %q", spec.Type, actionType)
			}
			if spec.Title == "" || spec.Description == "" {
				t.Error("every action needs a title and a description an analyst can read")
			}
			// The load-bearing invariant: "reversible" is only meaningful if
			// something actually reverses it. Without this, an action could
			// claim reversibility and slip past the approval gate.
			if spec.Reversible && spec.RollbackAction == "" {
				t.Error("action claims to be reversible but names no rollback action")
			}
			if spec.Destructive && spec.Reversible {
				t.Error("a destructive action cannot also be reversible")
			}
			if !spec.Destructive && spec.SimulationTemplate == "" {
				t.Error("a proposable action needs a simulation template")
			}
		})
	}
}

func TestDestructiveActionsAreNeverRecommendable(t *testing.T) {
	recommendable := map[string]bool{}
	for _, t := range incidents.RecommendableActionTypes() {
		recommendable[t] = true
	}
	found := 0
	for _, actionType := range incidents.KnownActionTypes() {
		spec, err := incidents.Lookup(actionType)
		if err != nil {
			t.Fatalf("Lookup(%q) error = %v", actionType, err)
		}
		if spec.Destructive {
			found++
			if recommendable[actionType] {
				t.Errorf("destructive action %q appears in the recommendable set", actionType)
			}
		}
	}
	if found == 0 {
		t.Error("the catalog defines no destructive action; the deny path would only ever be exercised by a test double")
	}
}

func TestLookupRejectsUnknownActions(t *testing.T) {
	for _, name := range []string{"", "launch_missiles", "PRESERVE_EVIDENCE", "preserve_evidence "} {
		if _, err := incidents.Lookup(name); !errors.Is(err, incidents.ErrUnknownActionType) {
			t.Errorf("Lookup(%q) error = %v, want ErrUnknownActionType", name, err)
		}
	}
}

func TestKnownActionTypesIsSortedAndStable(t *testing.T) {
	first := incidents.KnownActionTypes()
	second := incidents.KnownActionTypes()
	if len(first) != len(second) {
		t.Fatal("KnownActionTypes() is not stable")
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("ordering differed at %d", i)
		}
		if i > 0 && first[i-1] >= first[i] {
			t.Fatalf("not sorted at %d: %q then %q", i, first[i-1], first[i])
		}
	}
}

func TestEvidenceCategoriesAreDistinctAndSorted(t *testing.T) {
	inc := &incidents.Incident{Findings: []incidents.Finding{
		{Category: events.CategoryPrivilegeEscalation},
		{Category: events.CategoryAuthentication},
		{Category: events.CategoryAuthentication},
		{Category: events.CategoryCloudAccess},
	}}
	got := inc.EvidenceCategories()
	want := []events.Category{
		events.CategoryAuthentication, events.CategoryCloudAccess, events.CategoryPrivilegeEscalation,
	}
	if len(got) != len(want) {
		t.Fatalf("EvidenceCategories() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestModeValidation(t *testing.T) {
	if !incidents.ModeSimulate.Valid() || !incidents.ModeExecute.Valid() {
		t.Error("defined modes must validate")
	}
	if incidents.Mode("yolo").Valid() {
		t.Error("an undefined mode must not validate")
	}
}
