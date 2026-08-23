package config_test

import (
	"strings"
	"testing"

	"github.com/kamilxgriefer/griefer-security-platform/internal/config"
)

// isolate clears every variable config.Load reads.
//
// Without it these tests describe the developer's shell rather than the code:
// sourcing a .env into the terminal before running `go test` silently changes
// what Load returns, and a test asserting "an unauthenticated public bind is
// refused" passes or fails depending on whether INTERNAL_API_TOKEN happens to
// be exported.
//
// envFirst treats an empty value as unset, so setting to "" is equivalent to
// unsetting — and t.Setenv restores the previous value when the test ends.
func isolate(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"APP_ENV", "GRIEFER_ENV",
		"PORT", "GRIEFER_HTTP_ADDR", "GRIEFER_ALLOW_PUBLIC_BIND",
		"DATABASE_URL", "GRIEFER_POSTGRES_DSN", "GRIEFER_STORAGE_POSTGRES",
		"NATS_URL", "GRIEFER_NATS_URL", "NATS_USER", "GRIEFER_NATS_USER",
		"NATS_PASSWORD", "GRIEFER_NATS_PASSWORD", "GRIEFER_NATS_ENABLED",
		"OPA_URL", "GRIEFER_OPA_URL", "GRIEFER_OPA_FAIL_CLOSED",
		"INTERNAL_API_TOKEN", "GRIEFER_INTERNAL_API_TOKEN",
		"RESPONSE_MODE", "GRIEFER_RESPONSE_MODE",
		"ALLOW_REAL_ACTIONS", "SYNTHETIC_DATA_ONLY", "SEED_SYNTHETIC_DEMO",
		"GRIEFER_LOG_LEVEL", "GRIEFER_LOG_FORMAT",
	} {
		t.Setenv(name, "")
	}
}

func TestLoadDefaultsToLoopback(t *testing.T) {
	isolate(t)

	cfg, warnings, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !strings.HasPrefix(cfg.HTTP.Addr, "127.0.0.1:") {
		t.Errorf("default bind = %q; GRIEFER v0.1 has no authentication and must default to loopback", cfg.HTTP.Addr)
	}
	if cfg.Response.Mode != "simulate" {
		t.Errorf("default response mode = %q, want simulate", cfg.Response.Mode)
	}
	if !cfg.OPA.FailClosed {
		t.Error("fail-closed must default to true")
	}
	// Running on the in-memory store is a real caveat and must be surfaced.
	found := false
	for _, w := range warnings {
		if w.Setting == "GRIEFER_STORAGE_POSTGRES" {
			found = true
		}
	}
	if !found {
		t.Error("no warning about the in-memory store")
	}
}

func TestValidateRejectsUnsafeConfiguration(t *testing.T) {
	isolate(t)

	valid := func() config.Config {
		cfg, _, err := config.Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		return cfg
	}

	tests := []struct {
		name    string
		mutate  func(*config.Config)
		wantErr string
	}{
		{
			name:    "public bind without explicit opt-in",
			mutate:  func(c *config.Config) { c.HTTP.Addr = "0.0.0.0:8080" },
			wantErr: "refusing to bind",
		},
		{
			name:    "fail-closed cannot be disabled",
			mutate:  func(c *config.Config) { c.OPA.FailClosed = false },
			wantErr: "cannot be disabled",
		},
		{
			name:    "execute mode is not implemented",
			mutate:  func(c *config.Config) { c.Response.Mode = "execute" },
			wantErr: "not implemented in v0.1",
		},
		{
			name:    "postgres enabled without a DSN",
			mutate:  func(c *config.Config) { c.Postgres.Enabled = true; c.Postgres.DSN = "" },
			wantErr: "requires GRIEFER_POSTGRES_DSN",
		},
		{
			name:    "malformed listen address",
			mutate:  func(c *config.Config) { c.HTTP.Addr = "not-an-address" },
			wantErr: "must be host:port",
		},
		{
			name:    "non-numeric port",
			mutate:  func(c *config.Config) { c.HTTP.Addr = "127.0.0.1:http" },
			wantErr: "not numeric",
		},
		{
			name:    "zero body limit",
			mutate:  func(c *config.Config) { c.HTTP.MaxRequestBytes = 0 },
			wantErr: "MAX_REQUEST_BYTES must be positive",
		},
		{
			name:    "zero batch limit",
			mutate:  func(c *config.Config) { c.HTTP.MaxBatchEvents = 0 },
			wantErr: "MAX_BATCH_EVENTS must be positive",
		},
		{
			name:    "non-positive timeout",
			mutate:  func(c *config.Config) { c.HTTP.ReadTimeout = 0 },
			wantErr: "READ_TIMEOUT must be positive",
		},
		{
			name:    "unknown log format",
			mutate:  func(c *config.Config) { c.Log.Format = "xml" },
			wantErr: "LOG_FORMAT",
		},
		{
			name:    "unknown log level",
			mutate:  func(c *config.Config) { c.Log.Level = "chatty" },
			wantErr: "LOG_LEVEL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid()
			tt.mutate(&cfg)
			_, err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate() accepted an unsafe configuration")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestPublicBindRequiresAuthenticationOrAnExplicitOptIn(t *testing.T) {
	isolate(t)

	base := func() config.Config {
		cfg, _, err := config.Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		cfg.HTTP.Addr = "0.0.0.0:8080"
		return cfg
	}

	t.Run("refused when neither is present", func(t *testing.T) {
		if _, err := base().Validate(); err == nil {
			t.Fatal("Validate() accepted an unauthenticated public bind")
		}
	})

	t.Run("allowed when the API authenticates its callers", func(t *testing.T) {
		cfg := base()
		cfg.Auth.InternalAPIToken = "a-real-token-value"

		warnings, err := cfg.Validate()
		if err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		// Even with a token, the platform still has to keep the service off the
		// internet — the warning is what says so.
		found := false
		for _, w := range warnings {
			if w.Setting == "GRIEFER_HTTP_ADDR" && strings.Contains(w.Message, "INTERNAL_API_TOKEN") {
				found = true
			}
		}
		if !found {
			t.Errorf("warnings = %+v, want one naming the token requirement", warnings)
		}
	})

	t.Run("allowed with an explicit opt-in, and warns loudly", func(t *testing.T) {
		cfg := base()
		cfg.HTTP.AllowPublicBind = true

		warnings, err := cfg.Validate()
		if err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		found := false
		for _, w := range warnings {
			if w.Setting == "GRIEFER_HTTP_ADDR" && strings.Contains(w.Message, "NO authentication") {
				found = true
			}
		}
		if !found {
			t.Errorf("warnings = %+v, want one stating there is no authentication", warnings)
		}
	})
}

func TestRealActionsCannotBeEnabled(t *testing.T) {
	isolate(t)

	// The whole safety story of v0.1 is that no actuator exists. A flag that
	// claims to enable one must fail startup rather than imply a capability.
	cfg, _, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.Response.AllowRealActions = true

	if _, err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted ALLOW_REAL_ACTIONS=true")
	} else if !strings.Contains(err.Error(), "ships no actuator") {
		t.Errorf("error = %q, want it to explain that no actuator exists", err)
	}
}

func TestSimulationModeSpellings(t *testing.T) {
	isolate(t)

	// A deployment manifest reads better with "simulation"; the internal value
	// is "simulate". Refusing one of them would be pedantry that costs an outage.
	for _, spelling := range []string{"simulate", "simulation", "SIMULATION"} {
		t.Setenv("RESPONSE_MODE", spelling)
		cfg, _, err := config.Load()
		if err != nil {
			t.Fatalf("Load() with RESPONSE_MODE=%q error = %v", spelling, err)
		}
		if cfg.Response.Mode != "simulate" {
			t.Errorf("RESPONSE_MODE=%q resolved to %q, want simulate", spelling, cfg.Response.Mode)
		}
	}
}

func TestPlatformEnvironmentVariablesAreHonoured(t *testing.T) {
	isolate(t)

	t.Setenv("PORT", "9123")
	t.Setenv("DATABASE_URL", "postgres://u:p@db.internal:5432/griefer")
	t.Setenv("OPA_URL", "http://opa.internal:8181")
	t.Setenv("NATS_URL", "nats://nats.internal:4222")
	t.Setenv("APP_ENV", "demo")
	t.Setenv("INTERNAL_API_TOKEN", "token-value")
	t.Setenv("GRIEFER_STORAGE_POSTGRES", "true")

	cfg, _, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// PORT implies a container: bind every interface, because inside a
	// container the container's own interface is not the internet.
	if cfg.HTTP.Addr != "0.0.0.0:9123" {
		t.Errorf("Addr = %q, want 0.0.0.0:9123", cfg.HTTP.Addr)
	}
	if cfg.Postgres.DSN != "postgres://u:p@db.internal:5432/griefer" {
		t.Errorf("DSN = %q, want the DATABASE_URL value", cfg.Postgres.DSN)
	}
	if cfg.OPA.URL != "http://opa.internal:8181" {
		t.Errorf("OPA.URL = %q", cfg.OPA.URL)
	}
	if cfg.NATS.URL != "nats://nats.internal:4222" {
		t.Errorf("NATS.URL = %q", cfg.NATS.URL)
	}
	if cfg.Env != "demo" {
		t.Errorf("Env = %q, want demo", cfg.Env)
	}
	if cfg.Auth.InternalAPIToken != "token-value" {
		t.Error("INTERNAL_API_TOKEN was not read")
	}
}

func TestExplicitAddrBeatsPort(t *testing.T) {
	isolate(t)

	t.Setenv("PORT", "9123")
	t.Setenv("GRIEFER_HTTP_ADDR", "127.0.0.1:7777")

	cfg, _, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTP.Addr != "127.0.0.1:7777" {
		t.Errorf("Addr = %q, want the explicit value to win", cfg.HTTP.Addr)
	}
}

func TestRedactedHidesTheDatabasePassword(t *testing.T) {
	isolate(t)

	cfg, _, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.Postgres.DSN = "postgres://user:hunter2@localhost:5432/griefer"
	cfg.Auth.InternalAPIToken = "internal-token-value"
	cfg.NATS.Password = "nats-password-value"

	got := cfg.Redacted()
	for name, value := range map[string]string{
		"DSN":              got.Postgres.DSN,
		"InternalAPIToken": got.Auth.InternalAPIToken,
		"NATS password":    got.NATS.Password,
	} {
		for _, secret := range []string{"hunter2", "internal-token-value", "nats-password-value"} {
			if strings.Contains(value, secret) {
				t.Errorf("Redacted() leaked %s in %s: %q", secret, name, value)
			}
		}
	}
	if cfg.Postgres.DSN == got.Postgres.DSN {
		t.Error("Redacted() mutated or failed to copy the original")
	}
}
