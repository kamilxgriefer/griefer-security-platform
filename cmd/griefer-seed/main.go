// Command griefer-seed replays a synthetic scenario through the running
// GRIEFER ingest API.
//
// It deliberately goes over HTTP rather than reaching into the process: the
// demo should exercise the same validation, normalization, correlation and
// audit path that any real producer would.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kamilxgriefer/griefer-security-platform/fixtures"
	"github.com/kamilxgriefer/griefer-security-platform/internal/demo"
)

const (
	defaultAPI     = "http://127.0.0.1:8080"
	requestTimeout = 15 * time.Second
	maxResponse    = 1 << 20
)

func main() {
	var (
		apiURL   = flag.String("api", envOr("GRIEFER_API_BASE_URL", defaultAPI), "GRIEFER API base URL")
		scenario = flag.String("scenario", fixtures.ScenarioOne, "embedded scenario path to replay")
		pause    = flag.Duration("pause", 0, "delay between events, to watch risk accumulate in the console")
		wait     = flag.Duration("wait-for-api", 30*time.Second, "how long to wait for the API to become ready")
		once     = flag.Bool("once", false,
			"do nothing if the API already holds an incident. Makes the seed idempotent, so a container restart does not stack duplicate incidents.")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, *apiURL, *scenario, *pause, *wait, *once); err != nil {
		fmt.Fprintf(os.Stderr, "griefer-seed: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, apiURL, scenarioPath string, pause, wait time.Duration, once bool) error {
	sc, err := demo.LoadScenario(scenarioPath)
	if err != nil {
		return err
	}
	// Rebase so the scenario always lands inside the ingest window, ending
	// "now" rather than at whatever date the fixture was written.
	replay, err := sc.Rebase(time.Now().UTC())
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: requestTimeout}
	defer client.CloseIdleConnections()

	if err := waitForReady(ctx, client, apiURL, wait); err != nil {
		return err
	}

	if once {
		seeded, err := alreadySeeded(ctx, client, apiURL)
		if err != nil {
			return fmt.Errorf("check whether the scenario is already loaded: %w", err)
		}
		if seeded {
			fmt.Println("An incident already exists; nothing to seed.")
			return nil
		}
	}

	fmt.Printf("Replaying synthetic scenario %q (%d events) against %s\n", sc.ID, len(replay), apiURL)
	fmt.Printf("  %s\n\n", sc.Title)

	var lastIncident string
	for i, raw := range replay {
		result, err := postEvent(ctx, client, apiURL, raw)
		if err != nil {
			return fmt.Errorf("event %d: %w", i+1, err)
		}
		lastIncident = firstNonEmpty(result.IncidentID, lastIncident)
		fmt.Printf("  [%d/%d] accepted %s", i+1, len(replay), result.EventID)
		if result.IncidentID != "" {
			fmt.Printf("  ->  incident %s  risk %d", result.IncidentID, result.RiskScore)
		}
		if len(result.Degraded) > 0 {
			fmt.Printf("  (degraded: %v)", result.Degraded)
		}
		fmt.Println()

		if pause > 0 && i < len(replay)-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(pause):
			}
		}
	}

	if lastIncident == "" {
		return fmt.Errorf("scenario replayed but no incident was correlated; check the correlation engine")
	}
	fmt.Printf("\nIncident: %s/api/v1/incidents/%s\n", apiURL, lastIncident)
	fmt.Printf("Console:  http://localhost:3000/incidents/%s\n", lastIncident)
	fmt.Println("\nResponse actions are simulated. GRIEFER contacts no external system.")
	return nil
}

// alreadySeeded reports whether the API already holds an incident.
//
// The check is "is there any incident at all" rather than "is this specific
// scenario present", because the seed's purpose is to give an empty
// demonstration environment something to show. Anything already there — a
// replay, a manual submission — means that job is done, and adding a second
// identical incident would make the demo look broken.
func alreadySeeded(ctx context.Context, client *http.Client, apiURL string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/api/v1/incidents?limit=1", nil)
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	authorize(req)

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("send request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("API returned %d", resp.StatusCode)
	}
	var page struct {
		Total int `json:"total"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(&page); err != nil {
		return false, fmt.Errorf("decode response: %w", err)
	}
	return page.Total > 0, nil
}

// authorize attaches the service credential when one is configured.
//
// The seeder speaks to the API over the same authenticated path as the console,
// rather than through a privileged side door — a seeding tool that can bypass
// authentication is a backdoor with a friendly name.
func authorize(req *http.Request) {
	if token := os.Getenv("INTERNAL_API_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

type ingestResult struct {
	EventID    string   `json:"event_id"`
	IncidentID string   `json:"incident_id"`
	RiskScore  int      `json:"risk_score"`
	Degraded   []string `json:"degraded"`
}

func postEvent(ctx context.Context, client *http.Client, apiURL string, body []byte) (ingestResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/api/v1/events", bytes.NewReader(body))
	if err != nil {
		return ingestResult{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	authorize(req)

	resp, err := client.Do(req)
	if err != nil {
		return ingestResult{}, fmt.Errorf("send request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
		_ = resp.Body.Close()
	}()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return ingestResult{}, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		return ingestResult{}, fmt.Errorf("API returned %d: %s", resp.StatusCode, truncate(string(payload), 400))
	}
	var result ingestResult
	if err := json.Unmarshal(payload, &result); err != nil {
		return ingestResult{}, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}

// waitForReady polls /ready so `make demo` works immediately after `make up`
// without the caller guessing at startup time.
func waitForReady(ctx context.Context, client *http.Client, apiURL string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	var lastErr error
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/ready", nil)
		if err != nil {
			return fmt.Errorf("build readiness request: %w", err)
		}
		authorize(req)
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = fmt.Errorf("readiness returned %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("GRIEFER API at %s did not become ready within %s: %w", apiURL, wait, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
