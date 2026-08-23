// Package config loads GRIEFER's runtime configuration from the environment.
//
// Configuration is read once, at startup, and validated eagerly: a bad value
// fails the process rather than surfacing as a strange runtime behaviour hours
// later. Nothing here reads a secret from a file committed to the repository,
// and nothing here has a default that is unsafe outside a local lab.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the complete runtime configuration.
type Config struct {
	Env      string
	HTTP     HTTP
	Postgres Postgres
	NATS     NATS
	OPA      OPA
	Log      Log
	Response Response
}

// HTTP configures the API server.
type HTTP struct {
	Addr            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	MaxRequestBytes int64
	MaxBatchEvents  int
	RateLimitRPS    float64
	RateLimitBurst  int
	// AllowPublicBind must be set explicitly before GRIEFER will listen on a
	// non-loopback interface. v0.1 has no authentication; binding it to a
	// routable address exposes an unauthenticated ingest and audit API.
	AllowPublicBind bool
}

// Postgres configures the database connection.
type Postgres struct {
	Enabled         bool
	DSN             string
	MaxOpenConns    int32
	MaxIdleConns    int32
	ConnMaxLifetime time.Duration
}

// NATS configures the event bus.
type NATS struct {
	Enabled bool
	URL     string
	Stream  string
	Subject string
}

// OPA configures the Policy Kernel.
type OPA struct {
	// URL is the OPA server address. When empty, GRIEFER uses the embedded
	// kernel, which evaluates the same policy in-process.
	URL          string
	DecisionPath string
	Timeout      time.Duration
	// FailClosed is fixed to true. It is surfaced as configuration so the
	// guarantee is visible in `griefer-api -print-config`, and Validate rejects
	// any attempt to turn it off.
	FailClosed bool
}

// Log configures structured logging.
type Log struct {
	Level  string
	Format string
}

// Response configures the response engine.
type Response struct {
	// Mode is fixed to "simulate" in v0.1.
	Mode string
}

// Warning is a non-fatal configuration concern surfaced at startup.
type Warning struct {
	Setting string
	Message string
}

// Load reads configuration from the process environment.
func Load() (Config, []Warning, error) {
	cfg := Config{
		Env: envString("GRIEFER_ENV", "local"),
		HTTP: HTTP{
			Addr:            envString("GRIEFER_HTTP_ADDR", "127.0.0.1:8080"),
			ReadTimeout:     envDuration("GRIEFER_READ_TIMEOUT", 10*time.Second),
			WriteTimeout:    envDuration("GRIEFER_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:     envDuration("GRIEFER_IDLE_TIMEOUT", 120*time.Second),
			ShutdownTimeout: envDuration("GRIEFER_SHUTDOWN_TIMEOUT", 15*time.Second),
			MaxRequestBytes: int64(envInt("GRIEFER_MAX_REQUEST_BYTES", 1<<20)),
			MaxBatchEvents:  envInt("GRIEFER_MAX_BATCH_EVENTS", 500),
			RateLimitRPS:    envFloat("GRIEFER_RATE_LIMIT_RPS", 50),
			RateLimitBurst:  envInt("GRIEFER_RATE_LIMIT_BURST", 100),
			AllowPublicBind: envBool("GRIEFER_ALLOW_PUBLIC_BIND", false),
		},
		Postgres: Postgres{
			Enabled:         envBool("GRIEFER_STORAGE_POSTGRES", false),
			DSN:             envString("GRIEFER_POSTGRES_DSN", ""),
			MaxOpenConns:    int32(envInt("GRIEFER_DB_MAX_OPEN_CONNS", 20)),
			MaxIdleConns:    int32(envInt("GRIEFER_DB_MAX_IDLE_CONNS", 5)),
			ConnMaxLifetime: envDuration("GRIEFER_DB_CONN_MAX_LIFETIME", 30*time.Minute),
		},
		NATS: NATS{
			Enabled: envBool("GRIEFER_NATS_ENABLED", false),
			URL:     envString("GRIEFER_NATS_URL", "nats://localhost:4222"),
			Stream:  envString("GRIEFER_NATS_STREAM", "GRIEFER_EVENTS"),
			Subject: envString("GRIEFER_NATS_SUBJECT", "griefer.events.v1"),
		},
		OPA: OPA{
			URL:          envString("GRIEFER_OPA_URL", ""),
			DecisionPath: envString("GRIEFER_OPA_DECISION_PATH", "griefer/response/decision"),
			Timeout:      envDuration("GRIEFER_OPA_TIMEOUT", 3*time.Second),
			FailClosed:   envBool("GRIEFER_OPA_FAIL_CLOSED", true),
		},
		Log: Log{
			Level:  envString("GRIEFER_LOG_LEVEL", "info"),
			Format: envString("GRIEFER_LOG_FORMAT", "json"),
		},
		Response: Response{
			Mode: envString("GRIEFER_RESPONSE_MODE", "simulate"),
		},
	}
	warnings, err := cfg.Validate()
	return cfg, warnings, err
}

// Validate checks the configuration and returns any non-fatal warnings.
func (c Config) Validate() ([]Warning, error) {
	var warnings []Warning

	host, port, err := net.SplitHostPort(c.HTTP.Addr)
	if err != nil {
		return nil, fmt.Errorf("config: GRIEFER_HTTP_ADDR must be host:port, got %q", c.HTTP.Addr)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("config: GRIEFER_HTTP_ADDR port %q is not numeric", port)
	}
	if isPublicBind(host) {
		if !c.HTTP.AllowPublicBind {
			return nil, fmt.Errorf(
				"config: refusing to bind %q. GRIEFER v0.1 has no authentication, so a non-loopback bind exposes an unauthenticated ingest and audit API. "+
					"Set GRIEFER_ALLOW_PUBLIC_BIND=true only on an isolated lab network", c.HTTP.Addr)
		}
		warnings = append(warnings, Warning{
			Setting: "GRIEFER_HTTP_ADDR",
			Message: fmt.Sprintf("listening on non-loopback address %q with no authentication; restrict network access to this port", c.HTTP.Addr),
		})
	}

	if c.HTTP.MaxRequestBytes <= 0 {
		return nil, fmt.Errorf("config: GRIEFER_MAX_REQUEST_BYTES must be positive")
	}
	if c.HTTP.MaxRequestBytes > 32<<20 {
		warnings = append(warnings, Warning{
			Setting: "GRIEFER_MAX_REQUEST_BYTES",
			Message: "request body limit above 32 MiB; large bodies make memory exhaustion cheap for a caller",
		})
	}
	if c.HTTP.MaxBatchEvents <= 0 {
		return nil, fmt.Errorf("config: GRIEFER_MAX_BATCH_EVENTS must be positive")
	}
	if c.HTTP.RateLimitRPS <= 0 {
		return nil, fmt.Errorf("config: GRIEFER_RATE_LIMIT_RPS must be positive")
	}
	if c.HTTP.RateLimitBurst < 1 {
		return nil, fmt.Errorf("config: GRIEFER_RATE_LIMIT_BURST must be at least 1")
	}
	for name, d := range map[string]time.Duration{
		"GRIEFER_READ_TIMEOUT":     c.HTTP.ReadTimeout,
		"GRIEFER_WRITE_TIMEOUT":    c.HTTP.WriteTimeout,
		"GRIEFER_IDLE_TIMEOUT":     c.HTTP.IdleTimeout,
		"GRIEFER_SHUTDOWN_TIMEOUT": c.HTTP.ShutdownTimeout,
		"GRIEFER_OPA_TIMEOUT":      c.OPA.Timeout,
	} {
		if d <= 0 {
			return nil, fmt.Errorf("config: %s must be positive", name)
		}
	}

	if c.Postgres.Enabled && strings.TrimSpace(c.Postgres.DSN) == "" {
		return nil, fmt.Errorf("config: GRIEFER_STORAGE_POSTGRES=true requires GRIEFER_POSTGRES_DSN")
	}
	if !c.Postgres.Enabled {
		warnings = append(warnings, Warning{
			Setting: "GRIEFER_STORAGE_POSTGRES",
			Message: "running on the in-memory store; all events, incidents and audit entries are lost on restart",
		})
	}

	if !c.OPA.FailClosed {
		return nil, fmt.Errorf(
			"config: GRIEFER_OPA_FAIL_CLOSED cannot be disabled. An unreachable Policy Kernel must deny, never permit")
	}
	if c.NATS.Enabled && strings.TrimSpace(c.NATS.URL) == "" {
		return nil, fmt.Errorf("config: GRIEFER_NATS_ENABLED=true requires GRIEFER_NATS_URL")
	}

	switch c.Response.Mode {
	case "simulate":
	case "execute":
		return nil, fmt.Errorf(
			"config: GRIEFER_RESPONSE_MODE=execute is not implemented in v0.1. " +
				"No actuator exists, and pretending otherwise would misrepresent what the platform does")
	default:
		return nil, fmt.Errorf("config: GRIEFER_RESPONSE_MODE must be \"simulate\", got %q", c.Response.Mode)
	}

	switch c.Log.Format {
	case "json", "text":
	default:
		return nil, fmt.Errorf("config: GRIEFER_LOG_FORMAT must be \"json\" or \"text\", got %q", c.Log.Format)
	}
	switch strings.ToLower(c.Log.Level) {
	case "debug", "info", "warn", "error":
	default:
		return nil, fmt.Errorf("config: GRIEFER_LOG_LEVEL must be one of debug, info, warn, error; got %q", c.Log.Level)
	}
	return warnings, nil
}

// isPublicBind reports whether host would accept connections from outside the
// local machine.
func isPublicBind(host string) bool {
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		// A hostname that is not obviously loopback is treated as public.
		return !strings.EqualFold(host, "localhost")
	}
	return !ip.IsLoopback()
}

// Redacted returns a copy safe to log: the database DSN can carry a password.
func (c Config) Redacted() Config {
	out := c
	if out.Postgres.DSN != "" {
		out.Postgres.DSN = "[redacted]"
	}
	return out
}

func envString(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return fallback
	}
	return parsed
}

func envFloat(key string, fallback float64) float64 {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		return fallback
	}
	return parsed
}
