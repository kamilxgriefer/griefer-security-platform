// Command griefer-api runs the GRIEFER modular monolith: ingest API,
// correlation engine, Security Graph, Policy Kernel and audit trail.
//
// GRIEFER v0.1 is a research and engineering prototype. It simulates response
// actions and never contacts an external system.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/kamilxgriefer/griefer-security-platform/fixtures"
	"github.com/kamilxgriefer/griefer-security-platform/internal/api"
	"github.com/kamilxgriefer/griefer-security-platform/internal/audit"
	"github.com/kamilxgriefer/griefer-security-platform/internal/bus"
	"github.com/kamilxgriefer/griefer-security-platform/internal/config"
	"github.com/kamilxgriefer/griefer-security-platform/internal/correlation"
	"github.com/kamilxgriefer/griefer-security-platform/internal/demo"
	"github.com/kamilxgriefer/griefer-security-platform/internal/events"
	"github.com/kamilxgriefer/griefer-security-platform/internal/graph"
	"github.com/kamilxgriefer/griefer-security-platform/internal/policy"
	"github.com/kamilxgriefer/griefer-security-platform/internal/storage"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false,
		"probe this instance's own /ready endpoint and exit 0 when it is ready. Used as the container health check, because the runtime image ships no shell and no curl.")
	printConfig := flag.Bool("print-config", false,
		"print the resolved configuration, with secrets redacted, and exit")
	flag.Parse()

	if *healthcheck {
		if err := runHealthcheck(); err != nil {
			fmt.Fprintf(os.Stderr, "griefer-api: healthcheck failed: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *printConfig {
		if err := runPrintConfig(); err != nil {
			fmt.Fprintf(os.Stderr, "griefer-api: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := run(); err != nil {
		// The logger may not exist yet when configuration fails, so the last
		// resort is stderr.
		fmt.Fprintf(os.Stderr, "griefer-api: fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, warnings, err := config.Load()
	if err != nil {
		return err
	}
	logger := newLogger(cfg.Log)
	slog.SetDefault(logger)

	logger.Info("starting GRIEFER",
		slog.String("version", api.Version),
		slog.String("env", cfg.Env),
		slog.String("addr", cfg.HTTP.Addr),
		slog.String("response_mode", cfg.Response.Mode),
	)
	logger.Warn("response actions are SIMULATION ONLY in v0.1; GRIEFER does not contact identity providers, endpoints or cloud platforms")
	for _, w := range warnings {
		logger.Warn("configuration warning", slog.String("setting", w.Setting), slog.String("detail", w.Message))
	}

	// A cancellable root context ties every subsystem's lifetime to the
	// process. Each dependency below registers its own cleanup so shutdown
	// unwinds in reverse order of construction.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var closers []func()
	defer func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}()

	// --- Storage -------------------------------------------------------------
	store, err := newStore(ctx, cfg, logger)
	if err != nil {
		return err
	}
	closers = append(closers, func() {
		if err := store.Close(); err != nil {
			logger.Error("failed to close store", slog.String("error", err.Error()))
		}
	})

	// --- Policy Kernel -------------------------------------------------------
	kernel, err := newKernel(cfg, logger)
	if err != nil {
		return err
	}
	closers = append(closers, func() {
		if err := kernel.Close(); err != nil {
			logger.Error("failed to close policy kernel", slog.String("error", err.Error()))
		}
	})
	// Startup is the right time to discover a broken policy: a kernel that
	// cannot decide means every response action would fail closed.
	if err := kernel.Health(ctx); err != nil {
		return fmt.Errorf("policy kernel is not usable at startup: %w", err)
	}

	// --- Event bus -----------------------------------------------------------
	publisher := newPublisher(ctx, cfg, logger)
	closers = append(closers, func() {
		if err := publisher.Close(); err != nil {
			logger.Error("failed to close event bus", slog.String("error", err.Error()))
		}
	})

	// --- Security Graph ------------------------------------------------------
	securityGraph := graph.New()
	inventory, err := demo.LoadInventory()
	if err != nil {
		return fmt.Errorf("load baseline asset inventory: %w", err)
	}
	if err := securityGraph.ApplyInventory(inventory, time.Now().UTC()); err != nil {
		return fmt.Errorf("apply baseline asset inventory: %w", err)
	}
	entityCount, edgeCount := securityGraph.Size()
	logger.Info("baseline Security Graph loaded",
		slog.Int("entities", entityCount), slog.Int("edges", edgeCount),
		slog.String("source", "synthetic asset inventory"))

	// --- Detection + correlation --------------------------------------------
	rules, err := correlation.DefaultRules()
	if err != nil {
		return fmt.Errorf("load correlation rules: %w", err)
	}
	engine, err := correlation.NewEngine(correlation.Options{
		Rules: rules, Graph: securityGraph, Store: store,
	})
	if err != nil {
		return fmt.Errorf("build correlation engine: %w", err)
	}
	logger.Info("correlation engine ready", slog.Int("rules", len(rules)))

	// --- Validation, audit, metrics ------------------------------------------
	validator, err := events.NewValidator()
	if err != nil {
		return fmt.Errorf("compile event schema: %w", err)
	}
	recorder, err := audit.NewRecorder(store)
	if err != nil {
		return fmt.Errorf("build audit recorder: %w", err)
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	metrics := api.NewMetrics(registry)

	svc, err := api.NewService(api.ServiceOptions{
		Store: store, Graph: securityGraph, Validator: validator,
		Normalizer: events.NewNormalizer(), Correlator: engine, Kernel: kernel,
		Auditor: recorder, Publisher: publisher, Metrics: metrics, Logger: logger,
		MaxBatchEvents: cfg.HTTP.MaxBatchEvents, RuleCount: len(rules),
	})
	if err != nil {
		return fmt.Errorf("build service: %w", err)
	}

	if _, err := recorder.Record(ctx, audit.Entry{
		Action: audit.ActionSystemStarted, SubjectType: audit.SubjectSystem,
		SubjectID: "griefer-api", Outcome: audit.OutcomeSuccess,
		Reason: "GRIEFER API started in simulation-only mode",
		Details: map[string]any{
			"version": api.Version, "storage": store.Kind(),
			"policy_engine": kernel.Engine(), "event_bus": publisher.Kind(),
			"rules": len(rules), "response_mode": cfg.Response.Mode,
		},
	}); err != nil {
		return fmt.Errorf("record startup audit entry: %w", err)
	}

	if cfg.Auth.InternalAPIToken == "" {
		logger.Warn("no INTERNAL_API_TOKEN is configured; the API accepts any caller that can reach it")
	} else {
		logger.Info("service authentication enabled",
			slog.String("scheme", "bearer"),
			slog.String("exempt", "/health,/ready"))
	}
	if cfg.Response.SeedSyntheticDemo {
		if err := seedSyntheticDemo(ctx, svc, store, logger); err != nil {
			return fmt.Errorf("seed synthetic demonstration data: %w", err)
		}
	}

	handler := api.NewRouter(svc, api.RouterOptions{
		Registry: registry, MaxRequestBytes: cfg.HTTP.MaxRequestBytes,
		RateLimitRPS: cfg.HTTP.RateLimitRPS, RateLimitBurst: cfg.HTTP.RateLimitBurst,
		Logger: logger, InternalAPIToken: cfg.Auth.InternalAPIToken,
	})

	server := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           handler,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		ReadHeaderTimeout: cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("HTTP server listening", slog.String("addr", cfg.HTTP.Addr))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	select {
	case err := <-serverErr:
		if err != nil {
			return fmt.Errorf("http server: %w", err)
		}
	case <-ctx.Done():
		logger.Info("shutdown signal received", slog.Duration("grace", cfg.HTTP.ShutdownTimeout))
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown did not complete", slog.String("error", err.Error()))
		_ = server.Close()
	}

	if _, err := recorder.Record(shutdownCtx, audit.Entry{
		Action: audit.ActionSystemStopped, SubjectType: audit.SubjectSystem,
		SubjectID: "griefer-api", Outcome: audit.OutcomeSuccess,
		Reason: "GRIEFER API stopped",
	}); err != nil {
		logger.Error("failed to record shutdown audit entry", slog.String("error", err.Error()))
	}
	logger.Info("GRIEFER stopped")
	return nil
}

// runHealthcheck probes the instance's own readiness endpoint.
//
// The runtime image is distroless: no shell, no curl, nothing to script a
// health check with. The binary probing itself is the smallest thing that can
// answer "is this container serving?" without adding an attack surface to the
// image.
func runHealthcheck() error {
	cfg, _, err := config.Load()
	if err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(cfg.HTTP.Addr)
	if err != nil {
		return fmt.Errorf("parse %s: %w", cfg.HTTP.Addr, err)
	}
	// A wildcard bind is not a dialable address.
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url := "http://" + net.JoinHostPort(host, port) + "/ready"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("probe %s: %w", url, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned status %d", url, resp.StatusCode)
	}
	return nil
}

// runPrintConfig prints the resolved configuration so an operator can see what
// the process actually decided, without starting it.
func runPrintConfig() error {
	cfg, warnings, err := config.Load()
	if err != nil {
		return err
	}
	fmt.Printf("%+v\n", cfg.Redacted())
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s: %s\n", w.Setting, w.Message)
	}
	return nil
}

// seedSyntheticDemo loads the synthetic scenario into an empty deployment.
//
// It runs BEFORE the HTTP server starts listening, so a demonstration
// environment is never briefly reachable with nothing in it.
//
// The events go through Service.Ingest — the same validation, normalization,
// control-plane guard, correlation and audit path any producer gets. A seeder
// that wrote rows directly would prove nothing about the pipeline and would be
// a way into the database that bypasses every check on it.
//
// Idempotent by design: if any incident already exists the seed is skipped, so
// a container restart does not stack duplicates.
func seedSyntheticDemo(ctx context.Context, svc *api.Service, store storage.Store, logger *slog.Logger) error {
	existing, _, err := store.ListIncidents(ctx, storage.IncidentFilter{Limit: 1})
	if err != nil {
		return fmt.Errorf("check for existing incidents: %w", err)
	}
	if len(existing) > 0 {
		logger.Info("synthetic demonstration data already present; skipping seed")
		return nil
	}

	scenario, err := demo.LoadScenario(fixtures.ScenarioOne)
	if err != nil {
		return err
	}
	// Rebased so the scenario lands inside the ingest window rather than being
	// rejected as stale on some future day.
	events, err := scenario.Rebase(time.Now().UTC())
	if err != nil {
		return err
	}

	for i, raw := range events {
		result, err := svc.Ingest(ctx, raw)
		if err != nil {
			return fmt.Errorf("ingest scenario event %d: %w", i+1, err)
		}
		logger.Debug("seeded synthetic event",
			slog.Int("step", i+1), slog.String("event_id", result.EventID),
			slog.Int("risk_score", result.RiskScore))
	}
	logger.Info("synthetic demonstration scenario loaded",
		slog.String("scenario", scenario.ID), slog.Int("events", len(events)))
	return nil
}

func newLogger(cfg config.Log) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.Format == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

func newStore(ctx context.Context, cfg config.Config, logger *slog.Logger) (storage.Store, error) {
	if !cfg.Postgres.Enabled {
		logger.Warn("using the in-memory store; all state is lost on restart")
		return storage.NewMemoryStore(0), nil
	}
	store, err := storage.NewPostgresStore(ctx, storage.PostgresOptions{
		DSN:             cfg.Postgres.DSN,
		MaxOpenConns:    cfg.Postgres.MaxOpenConns,
		MaxIdleConns:    cfg.Postgres.MaxIdleConns,
		ConnMaxLifetime: cfg.Postgres.ConnMaxLifetime,
	})
	if err != nil {
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	logger.Info("connected to PostgreSQL and applied schema")
	return store, nil
}

// newKernel selects the Policy Kernel implementation.
//
// Both implementations evaluate the same Rego. The remote kernel is used when
// an OPA URL is configured so that policy can be reloaded and audited
// independently of this binary; otherwise the embedded kernel keeps the
// platform enforceable as a single process.
func newKernel(cfg config.Config, logger *slog.Logger) (policy.Kernel, error) {
	if cfg.OPA.URL == "" {
		kernel, err := policy.NewEmbeddedKernel()
		if err != nil {
			return nil, fmt.Errorf("build embedded policy kernel: %w", err)
		}
		logger.Info("Policy Kernel ready", slog.String("engine", "embedded"))
		return kernel, nil
	}
	kernel, err := policy.NewRemoteKernel(policy.RemoteOptions{
		BaseURL: cfg.OPA.URL, DecisionPath: cfg.OPA.DecisionPath, Timeout: cfg.OPA.Timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("build remote policy kernel: %w", err)
	}
	logger.Info("Policy Kernel ready",
		slog.String("engine", "remote"), slog.String("url", cfg.OPA.URL),
		slog.Bool("fail_closed", cfg.OPA.FailClosed))
	return kernel, nil
}

// newPublisher connects the event bus, degrading to a no-op rather than
// failing startup. Telemetry capture must survive a bus outage.
func newPublisher(ctx context.Context, cfg config.Config, logger *slog.Logger) bus.Publisher {
	if !cfg.NATS.Enabled {
		logger.Info("event bus disabled; events are stored and correlated in-process")
		return bus.NewNoopPublisher()
	}
	publisher, err := bus.NewNATSPublisher(ctx, bus.NATSOptions{
		URL: cfg.NATS.URL, Stream: cfg.NATS.Stream, Subject: cfg.NATS.Subject,
		User: cfg.NATS.User, Password: cfg.NATS.Password,
	})
	if err != nil {
		logger.Error("event bus unavailable at startup; continuing without fan-out",
			slog.String("error", err.Error()))
		return bus.NewNoopPublisher()
	}
	logger.Info("event bus connected",
		slog.String("url", cfg.NATS.URL), slog.String("stream", cfg.NATS.Stream),
		slog.Bool("authenticated", cfg.NATS.User != ""))
	return publisher
}
