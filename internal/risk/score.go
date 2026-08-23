// Package risk turns an incident's accumulated evidence into a bounded score,
// a severity and a confidence value.
//
// Two properties are treated as requirements rather than implementation
// details, and both are covered by tests:
//
//  1. Monotonicity — adding evidence to an incident never lowers its risk
//     score. An analyst who watches a score drop while an attack progresses
//     stops trusting the number.
//  2. Saturation — the score approaches but never reaches 100. Beyond a point,
//     "worse" is not an actionable distinction, and a linear score would let a
//     flood of low-value findings outrank a single critical one.
package risk

import (
	"math"

	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/incidents"
)

// severityWeight is the evidential weight of one finding at each severity.
var severityWeight = map[events.Severity]float64{
	events.SeverityInformational: 1,
	events.SeverityLow:           3,
	events.SeverityMedium:        7,
	events.SeverityHigh:          13,
	events.SeverityCritical:      20,
}

// Scoring constants. They are named rather than inlined because they are the
// parameters an operator would want to tune, and because the tests assert on
// the shape they produce rather than on magic numbers.
const (
	// categoryBoost is the extra weight given per additional independent
	// evidence category. Corroboration across categories is the strongest
	// signal GRIEFER has that something is genuinely wrong.
	categoryBoost = 0.18
	// criticalAssetBoost applies when the incident touches a critical asset.
	criticalAssetBoost = 0.15
	// blastWeight converts blast-radius score into evidential weight.
	blastWeight = 0.12
	// saturation controls how quickly the score approaches 100.
	saturation = 55.0
	// maxConfidence caps reported confidence. GRIEFER is never certain, and a
	// displayed 100% invites an analyst to stop thinking.
	maxConfidence = 0.95
	// repetitionCeiling bounds how much repetition WITHIN one evidence category
	// can add beyond that category's strongest finding.
	//
	// Without this bound, a single noisy rule firing twenty times outscores a
	// genuinely corroborated two-category incident — which inverts the entire
	// safety model, since the Policy Kernel gates automation on the number of
	// independent categories. Ten sign-in anomalies for one identity are one
	// observation restated, so they may add at most 50%.
	repetitionCeiling = 0.5
	// repetitionHalfLife controls how quickly repetition approaches the ceiling.
	repetitionHalfLife = 3.0
)

// Assessment is the result of scoring an incident.
type Assessment struct {
	Score      int
	Severity   events.Severity
	Confidence float64
	// EvidenceCategories is the number of distinct categories that contributed.
	EvidenceCategories int
}

// Input carries everything scoring depends on. Keeping it explicit means the
// scorer has no hidden inputs, which is what makes the result reproducible for
// an audit entry.
type Input struct {
	Findings        []incidents.Finding
	BlastScore      int
	TouchesCritical bool
}

// Assess scores an incident.
func Assess(in Input) Assessment {
	if len(in.Findings) == 0 {
		return Assessment{Score: 0, Severity: events.SeverityInformational, Confidence: 0}
	}

	// Findings are aggregated per category, not per finding, so that the score
	// is driven by how many independent kinds of evidence exist rather than by
	// how loud any one of them is.
	type categoryEvidence struct {
		bestWeighted   float64
		bestConfidence float64
		count          int
	}
	byCategory := make(map[events.Category]*categoryEvidence)
	for _, f := range in.Findings {
		w, ok := severityWeight[f.Severity]
		if !ok {
			// An unrecognised severity contributes the lowest weight rather
			// than zero: unknown is not the same as harmless.
			w = severityWeight[events.SeverityLow]
		}
		conf := clamp01(f.Confidence)
		agg, seen := byCategory[f.Category]
		if !seen {
			agg = &categoryEvidence{}
			byCategory[f.Category] = agg
		}
		agg.count++
		if weighted := w * conf; weighted > agg.bestWeighted {
			agg.bestWeighted = weighted
		}
		if conf > agg.bestConfidence {
			agg.bestConfidence = conf
		}
	}

	var evidence float64
	bestByCategory := make(map[events.Category]float64, len(byCategory))
	for category, agg := range byCategory {
		evidence += agg.bestWeighted * repetitionFactor(agg.count)
		bestByCategory[category] = agg.bestConfidence
	}

	categories := len(byCategory)
	factor := 1 + categoryBoost*float64(categories-1)
	if in.TouchesCritical {
		factor += criticalAssetBoost
	}

	raw := evidence*factor + blastWeight*float64(clampInt(in.BlastScore, 0, 100))
	score := int(math.Round(100 * (1 - math.Exp(-raw/saturation))))
	score = clampInt(score, 0, 100)

	return Assessment{
		Score:              score,
		Severity:           SeverityForScore(score),
		Confidence:         aggregateConfidence(bestByCategory),
		EvidenceCategories: categories,
	}
}

// SeverityForScore maps a risk score onto the shared severity scale.
func SeverityForScore(score int) events.Severity {
	switch {
	case score >= 70:
		return events.SeverityCritical
	case score >= 45:
		return events.SeverityHigh
	case score >= 20:
		return events.SeverityMedium
	case score > 0:
		return events.SeverityLow
	default:
		return events.SeverityInformational
	}
}

// aggregateConfidence combines the strongest finding from each category using a
// noisy-OR.
//
// Only the best finding per category contributes. Ten sign-in anomalies for one
// identity are largely the same observation restated; treating them as ten
// independent confirmations would manufacture certainty out of repetition.
func aggregateConfidence(bestByCategory map[events.Category]float64) float64 {
	if len(bestByCategory) == 0 {
		return 0
	}
	remaining := 1.0
	for _, conf := range bestByCategory {
		remaining *= 1 - clamp01(conf)
	}
	confidence := 1 - remaining
	if confidence > maxConfidence {
		confidence = maxConfidence
	}
	return math.Round(confidence*1000) / 1000
}

// repetitionFactor returns the multiplier applied to a category's strongest
// finding given how many findings that category holds. It starts at 1 and
// approaches 1+repetitionCeiling, never reaching it.
func repetitionFactor(count int) float64 {
	if count <= 1 {
		return 1
	}
	return 1 + repetitionCeiling*(1-math.Exp(-float64(count-1)/repetitionHalfLife))
}

func clamp01(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
