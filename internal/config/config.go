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
	Auth     Auth
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
	Enabled  bool
	URL      string
	Stream   string
	Subject  string
	User     string
	Password string
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
	// Mode is fixed to simulation in v0.1.
	Mode string
	// AllowRealActions must stay false. It is surfaced as configuration so the
	// guarantee is visible in `griefer-api -print-config`, and Validate rejects
	// any attempt to turn it on.
	AllowRealActions bool
	// SyntheticDataOnly records that this deployment carries invented data.
	SyntheticDataOnly bool
	// SeedSyntheticDemo asks the API to replay the synthetic scenario into an
	// empty database at startup. Idempotent: it is a no-op once an incident
	// exists.
	SeedSyntheticDemo bool
}

// Auth configures the service-to-service credential the API requires.
type Auth struct {
	// InternalAPIToken is the shared secret the console's server-side gateway
	// presents. Empty disables the check, which is only acceptable on a
	// loopback bind — Validate enforces that pairing.
	InternalAPIToken string
}

// PlaceholderSecretMarker appears in every placeholder value in .env.example.
//
// It is a marker rather than an exact-value list so that adding a placeholder
// to that file cannot quietly add a working credential: anything carrying it is
// refused, whatever else it says. console/lib/config.ts holds the same literal
// for the same reason, duplicated across a language boundary the way the role
// names are.
const PlaceholderSecretMarker = "run-make-secrets"

// Warning is a non-fatal configuration concern surfaced at startup.
type Warning struct {
	Setting string
	Message string
}

// Load reads configuration from the process environment.
func Load() (Config, []Warning, error) {
	cfg := Config{
		Env: envFirst("local", "APP_ENV", "GRIEFER_ENV"),
		HTTP: HTTP{
			Addr:            listenAddr(),
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
			DSN:             envFirst("", "DATABASE_URL", "GRIEFER_POSTGRES_DSN"),
			MaxOpenConns:    int32(envInt("GRIEFER_DB_MAX_OPEN_CONNS", 20)),
			MaxIdleConns:    int32(envInt("GRIEFER_DB_MAX_IDLE_CONNS", 5)),
			ConnMaxLifetime: envDuration("GRIEFER_DB_CONN_MAX_LIFETIME", 30*time.Minute),
		},
		NATS: NATS{
			Enabled:  envBool("GRIEFER_NATS_ENABLED", false),
			URL:      envFirst("nats://localhost:4222", "NATS_URL", "GRIEFER_NATS_URL"),
			User:     envFirst("", "NATS_USER", "GRIEFER_NATS_USER"),
			Password: envFirst("", "NATS_PASSWORD", "GRIEFER_NATS_PASSWORD"),
			Stream:   envString("GRIEFER_NATS_STREAM", "GRIEFER_EVENTS"),
			Subject:  envString("GRIEFER_NATS_SUBJECT", "griefer.events.v1"),
		},
		OPA: OPA{
			URL:          envFirst("", "OPA_URL", "GRIEFER_OPA_URL"),
			DecisionPath: envString("GRIEFER_OPA_DECISION_PATH", "griefer/response/decision"),
			Timeout:      envDuration("GRIEFER_OPA_TIMEOUT", 3*time.Second),
			FailClosed:   envBool("GRIEFER_OPA_FAIL_CLOSED", true),
		},
		Log: Log{
			Level:  envString("GRIEFER_LOG_LEVEL", "info"),
			Format: envString("GRIEFER_LOG_FORMAT", "json"),
		},
		Response: Response{
			Mode:              normalizeResponseMode(envFirst("simulate", "RESPONSE_MODE", "GRIEFER_RESPONSE_MODE")),
			AllowRealActions:  envBool("ALLOW_REAL_ACTIONS", false),
			SyntheticDataOnly: envBool("SYNTHETIC_DATA_ONLY", true),
			SeedSyntheticDemo: envBool("SEED_SYNTHETIC_DEMO", false),
		},
		Auth: Auth{
			InternalAPIToken: envFirst("", "INTERNAL_API_TOKEN", "GRIEFER_INTERNAL_API_TOKEN"),
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
		// A non-loopback bind is acceptable when the API actually authenticates
		// its callers. Before INTERNAL_API_TOKEN existed the only honest answer
		// was to refuse; now the operator has two ways to satisfy the check, and
		// exactly one of them is a real control.
		switch {
		case c.Auth.InternalAPIToken != "":
			warnings = append(warnings, Warning{
				Setting: "GRIEFER_HTTP_ADDR",
				Message: fmt.Sprintf("listening on %q; every application endpoint requires INTERNAL_API_TOKEN, but the platform must still keep this service off the public internet", c.HTTP.Addr),
			})
		case c.HTTP.AllowPublicBind:
			warnings = append(warnings, Warning{
				Setting: "GRIEFER_HTTP_ADDR",
				Message: fmt.Sprintf("listening on %q with NO authentication; this is acceptable only on an isolated network", c.HTTP.Addr),
			})
		default:
			return nil, fmt.Errorf(
				"config: refusing to bind %q with no authentication. Set INTERNAL_API_TOKEN so the API requires a credential, "+
					"or set GRIEFER_ALLOW_PUBLIC_BIND=true to accept an unauthenticated listener on an isolated lab network", c.HTTP.Addr)
		}
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

	// A value published in a public repository is not a secret. Every
	// placeholder in .env.example carries this marker precisely so that a
	// configuration copied from it fails loudly instead of running on a
	// credential anyone can read — which is the failure mode that file's own
	// instructions are trying to prevent, and instructions are not a control.
	for _, s := range []struct {
		setting string
		value   string
	}{
		{"INTERNAL_API_TOKEN", c.Auth.InternalAPIToken},
		{"NATS_PASSWORD", c.NATS.Password},
		{"GRIEFER_POSTGRES_DSN", c.Postgres.DSN},
	} {
		if strings.Contains(s.value, PlaceholderSecretMarker) {
			return nil, fmt.Errorf(
				"config: %s still holds the placeholder from .env.example, which is published and therefore not a secret. "+
					"Run `make secrets` to generate real values", s.setting)
		}
	}

	if c.Postgres.Enabled && strings.TrimSpace(c.Postgres.DSN) == "" {
		return nil, fmt.Errorf("config: GRIEFER_STORAGE_POSTGRES=true requires GRIEFER_POSTGRES_DSN")
	}
	// A DSN with the store switched off is a configuration that means two
	// things. The operator provided a database; the platform would quietly
	// ignore it and run every event, incident and audit entry in process
	// memory, losing all of it on the next restart — and the audit chain there
	// has no trigger and nothing durable behind it. Platforms inject
	// DATABASE_URL routinely, which is exactly how this happens by accident.
	if !c.Postgres.Enabled && strings.TrimSpace(c.Postgres.DSN) != "" {
		return nil, fmt.Errorf(
			"config: a database is configured (GRIEFER_POSTGRES_DSN or DATABASE_URL) but " +
				"GRIEFER_STORAGE_POSTGRES is false, so the platform would run entirely in memory and " +
				"discard it on restart. Set GRIEFER_STORAGE_POSTGRES=true, or unset the DSN to say " +
				"the in-memory store is intended")
	}
	if !c.Postgres.Enabled {
		warnings = append(warnings, Warning{
			Setting: "GRIEFER_STORAGE_POSTGRES",
			Message: "running on the in-memory store; all events, incidents and audit entries are lost on restart, and the audit chain there is recomputed by the process that wrote it — there is no trigger and nothing durable behind it",
		})
	}

	if !c.OPA.FailClosed {
		return nil, fmt.Errorf(
			"config: GRIEFER_OPA_FAIL_CLOSED cannot be disabled. An unreachable Policy Kernel must deny, never permit")
	}
	if c.NATS.Enabled && strings.TrimSpace(c.NATS.URL) == "" {
		return nil, fmt.Errorf("config: GRIEFER_NATS_ENABLED=true requires GRIEFER_NATS_URL")
	}

	if c.Response.AllowRealActions {
		return nil, fmt.Errorf(
			"config: ALLOW_REAL_ACTIONS=true is refused. GRIEFER v0.1 ships no actuator, so enabling it would " +
				"advertise a capability that does not exist while removing the guard that says so")
	}
	if !c.Response.SyntheticDataOnly {
		warnings = append(warnings, Warning{
			Setting: "SYNTHETIC_DATA_ONLY",
			Message: "set to false; GRIEFER v0.1 is a prototype and has no data-handling guarantees for real telemetry",
		})
	}
	if c.NATS.Enabled && c.NATS.User != "" && c.NATS.Password == "" {
		return nil, fmt.Errorf("config: NATS_USER is set without NATS_PASSWORD")
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

// listenAddr resolves the address the API listens on.
//
// Precedence: an explicit GRIEFER_HTTP_ADDR always wins. Otherwise, if the
// platform injected PORT — the convention every PaaS follows — bind every
// interface on that port, because inside a container the container's own
// interface is not the internet; what makes a service reachable is whether the
// platform gave it a public domain. Failing that, loopback.
func listenAddr() string {
	if addr := envString("GRIEFER_HTTP_ADDR", ""); addr != "" {
		return addr
	}
	if port := envString("PORT", ""); port != "" {
		return net.JoinHostPort("0.0.0.0", port)
	}
	return "127.0.0.1:8080"
}

// isPublicBind reports whether host would accept connections from outside the
// local machine.
// IsPublicBind reports whether a bind host is reachable from outside this
// machine. Exported so the router can refuse to serve role-gated endpoints in
// the one configuration where the role gate cannot work.
func IsPublicBind(host string) bool { return isPublicBind(host) }

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
	if out.Auth.InternalAPIToken != "" {
		out.Auth.InternalAPIToken = "[redacted]"
	}
	if out.NATS.Password != "" {
		out.NATS.Password = "[redacted]"
	}
	return out
}

// envFirst returns the first of names that is set to a non-empty value.
//
// GRIEFER's own variables are prefixed GRIEFER_, but a PaaS injects
// conventional names — PORT, DATABASE_URL — and a deployment manifest reads
// better using them. Accepting both means the manifest can use the platform's
// vocabulary without the code growing a second configuration path. The
// platform-conventional name is listed first and wins.
func envFirst(fallback string, names ...string) string {
	for _, name := range names {
		if v, ok := os.LookupEnv(name); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return fallback
}

// normalizeResponseMode accepts both spellings of the simulation mode.
// "simulate" is the internal value; "simulation" reads better in a deployment
// manifest, and rejecting it would be pedantry that costs an outage.
func normalizeResponseMode(mode string) string {
	if strings.EqualFold(mode, "simulation") {
		return "simulate"
	}
	return strings.ToLower(mode)
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
