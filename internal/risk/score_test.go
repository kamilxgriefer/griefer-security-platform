package risk_test

import (
	"testing"

	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
	"github.com/kamilxgriefer/griefer-security-platform/internal/risk"
)

func finding(category events.Category, severity events.Severity, confidence float64) incidents.Finding {
	return incidents.Finding{Category: category, Severity: severity, Confidence: confidence}
}

func TestAssessScoresTheDemoChainProgressively(t *testing.T) {
	// The five steps of scenario-01, added one at a time. The property under
	// test is that risk rises with every new piece of evidence — an analyst who
	// watches a score fall while an attack progresses stops trusting it.
	chain := []incidents.Finding{
		finding(events.CategoryAuthentication, events.SeverityMedium, 0.55),
		finding(events.CategorySessionAnomaly, events.SeverityMedium, 0.60),
		finding(events.CategoryPrivilegeEscalation, events.SeverityHigh, 0.75),
		finding(events.CategoryCredentialAccess, events.SeverityHigh, 0.80),
		finding(events.CategoryCloudAccess, events.SeverityCritical, 0.70),
	}
	blast := []int{20, 30, 45, 70, 96}

	prev := -1
	for i := range chain {
		got := risk.Assess(risk.Input{
			Findings:        chain[:i+1],
			BlastScore:      blast[i],
			TouchesCritical: i >= 3,
		})
		if got.Score <= prev {
			t.Fatalf("step %d: score %d did not increase over %d", i+1, got.Score, prev)
		}
		if got.Score < 0 || got.Score > 100 {
			t.Fatalf("step %d: score %d out of range", i+1, got.Score)
		}
		prev = got.Score
	}
	final := risk.Assess(risk.Input{Findings: chain, BlastScore: 96, TouchesCritical: true})
	if final.Severity != events.SeverityCritical {
		t.Errorf("final severity = %v, want critical for a five-category chain touching a critical asset", final.Severity)
	}
	if final.EvidenceCategories != 5 {
		t.Errorf("EvidenceCategories = %d, want 5", final.EvidenceCategories)
	}
}

func TestAssessIsMonotonic(t *testing.T) {
	base := []incidents.Finding{finding(events.CategoryAuthentication, events.SeverityLow, 0.3)}
	additions := []incidents.Finding{
		finding(events.CategoryAuthentication, events.SeverityLow, 0.2),
		finding(events.CategoryNetworkActivity, events.SeverityMedium, 0.5),
		finding(events.CategoryDataAccess, events.SeverityHigh, 0.9),
		finding(events.CategoryProcessExecution, events.SeverityInformational, 0.1),
	}
	prev := risk.Assess(risk.Input{Findings: base}).Score
	for i, add := range additions {
		base = append(base, add)
		got := risk.Assess(risk.Input{Findings: base}).Score
		if got < prev {
			t.Fatalf("addition %d dropped the score from %d to %d", i, prev, got)
		}
		prev = got
	}
}

func TestAssessSaturatesBelow100(t *testing.T) {
	var flood []incidents.Finding
	for i := 0; i < 200; i++ {
		flood = append(flood, finding(events.CategoryCloudAccess, events.SeverityCritical, 1.0))
	}
	got := risk.Assess(risk.Input{Findings: flood, BlastScore: 100, TouchesCritical: true})
	if got.Score > 100 {
		t.Fatalf("score %d exceeded the scale", got.Score)
	}
	if got.Confidence > 0.95 {
		t.Errorf("confidence = %v; GRIEFER must never display certainty", got.Confidence)
	}
}

func TestAssessDoesNotManufactureConfidenceFromRepetition(t *testing.T) {
	// Ten sign-in anomalies for one identity are largely one observation
	// restated. Repetition inside a category must not read as corroboration.
	var repeated []incidents.Finding
	for i := 0; i < 10; i++ {
		repeated = append(repeated, finding(events.CategoryAuthentication, events.SeverityMedium, 0.6))
	}
	single := risk.Assess(risk.Input{Findings: repeated[:1]})
	many := risk.Assess(risk.Input{Findings: repeated})

	if many.Confidence != single.Confidence {
		t.Errorf("confidence changed from %v to %v by repeating one category", single.Confidence, many.Confidence)
	}
	if many.EvidenceCategories != 1 {
		t.Errorf("EvidenceCategories = %d, want 1", many.EvidenceCategories)
	}

	twoCategories := risk.Assess(risk.Input{Findings: []incidents.Finding{
		finding(events.CategoryAuthentication, events.SeverityMedium, 0.6),
		finding(events.CategoryPrivilegeEscalation, events.SeverityMedium, 0.6),
	}})
	if twoCategories.Confidence <= single.Confidence {
		t.Error("a second independent category must raise confidence")
	}
	if twoCategories.Score <= many.Score {
		t.Errorf("two independent categories (%d) should outscore ten repeats of one (%d)", twoCategories.Score, many.Score)
	}
}

func TestAssessHandlesDegenerateInput(t *testing.T) {
	tests := []struct {
		name string
		in   risk.Input
	}{
		{"no findings", risk.Input{}},
		{"negative confidence", risk.Input{Findings: []incidents.Finding{finding(events.CategoryAuthentication, events.SeverityHigh, -5)}}},
		{"confidence above one", risk.Input{Findings: []incidents.Finding{finding(events.CategoryAuthentication, events.SeverityHigh, 42)}}},
		{"unknown severity", risk.Input{Findings: []incidents.Finding{finding(events.CategoryAuthentication, events.Severity("catastrophic"), 0.5)}}},
		{"blast score out of range", risk.Input{Findings: []incidents.Finding{finding(events.CategoryAuthentication, events.SeverityLow, 0.5)}, BlastScore: 5000}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := risk.Assess(tt.in)
			if got.Score < 0 || got.Score > 100 {
				t.Errorf("Score = %d, want 0..100", got.Score)
			}
			if got.Confidence < 0 || got.Confidence > 0.95 {
				t.Errorf("Confidence = %v, want 0..0.95", got.Confidence)
			}
			if !got.Severity.Valid() {
				t.Errorf("Severity = %q is not a defined level", got.Severity)
			}
		})
	}
}

func TestSeverityForScoreBoundaries(t *testing.T) {
	tests := []struct {
		score int
		want  events.Severity
	}{
		{0, events.SeverityInformational},
		{1, events.SeverityLow},
		{19, events.SeverityLow},
		{20, events.SeverityMedium},
		{44, events.SeverityMedium},
		{45, events.SeverityHigh},
		{69, events.SeverityHigh},
		{70, events.SeverityCritical},
		{100, events.SeverityCritical},
	}
	for _, tt := range tests {
		if got := risk.SeverityForScore(tt.score); got != tt.want {
			t.Errorf("SeverityForScore(%d) = %v, want %v", tt.score, got, tt.want)
		}
	}
}
