package config_test

import (
	"strings"
	"testing"

	"github.com/kamilxgriefer/griefer-security-platform/internal/config"
)

func TestLoadDefaultsToLoopback(t *testing.T) {
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

func TestPublicBindIsAllowedWithAnExplicitOptInAndWarns(t *testing.T) {
	cfg, _, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.HTTP.Addr = "0.0.0.0:8080"
	cfg.HTTP.AllowPublicBind = true

	warnings, err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	found := false
	for _, w := range warnings {
		if w.Setting == "GRIEFER_HTTP_ADDR" && strings.Contains(w.Message, "no authentication") {
			found = true
		}
	}
	if !found {
		t.Error("an opted-in public bind must still warn loudly")
	}
}

func TestRedactedHidesTheDatabasePassword(t *testing.T) {
	cfg, _, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.Postgres.DSN = "postgres://user:hunter2@localhost:5432/griefer"
	got := cfg.Redacted()
	if strings.Contains(got.Postgres.DSN, "hunter2") {
		t.Errorf("Redacted() leaked the password: %q", got.Postgres.DSN)
	}
	if cfg.Postgres.DSN == got.Postgres.DSN {
		t.Error("Redacted() mutated or failed to copy the original")
	}
}
