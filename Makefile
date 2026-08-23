# GRIEFER — developer entry points.
#
# `make help` lists everything. The two you need first:
#   make up     start the whole local stack
#   make demo   replay the synthetic scenario through the running API

SHELL := /bin/bash
.DEFAULT_GOAL := help

GO             ?= go
PNPM           ?= pnpm
DOCKER_COMPOSE ?= docker compose
BIN_DIR        := bin
API_BIN        := $(BIN_DIR)/griefer-api
SEED_BIN       := $(BIN_DIR)/griefer-seed
CONSOLE_DIR    := console
COMPOSE_FILE   := docker-compose.yml
# Local secrets live outside git. `make secrets` creates it.
COMPOSE_ENV    := .env.local
COMPOSE        := $(DOCKER_COMPOSE) -f $(COMPOSE_FILE) --env-file $(COMPOSE_ENV)

# Ports used by `make services-up` for native (non-Docker) local testing.
TEST_PG_PORT   ?= 55432
TEST_NATS_PORT ?= 54222
TEST_OPA_PORT  ?= 58181
TEST_STATE_DIR ?= .local

GO_LDFLAGS := -s -w

.PHONY: help
help: ## Show this help
	@echo "GRIEFER — Graph-based Resilient Intelligence Engine for Enforcement & Response"
	@echo "Response actions are SIMULATION ONLY in v0.1."
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

.PHONY: build
build: build-api build-console ## Build the backend and the console

.PHONY: build-api
build-api: ## Build the Go binaries
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags "$(GO_LDFLAGS)" -o $(API_BIN) ./cmd/griefer-api
	$(GO) build -trimpath -ldflags "$(GO_LDFLAGS)" -o $(SEED_BIN) ./cmd/griefer-seed
	@echo "built $(API_BIN) and $(SEED_BIN)"

.PHONY: build-console
build-console: console-install ## Build the Next.js console
	cd $(CONSOLE_DIR) && $(PNPM) build

.PHONY: console-install
console-install: ## Install console dependencies
	cd $(CONSOLE_DIR) && $(PNPM) install --frozen-lockfile

# ---------------------------------------------------------------------------
# Quality gates
# ---------------------------------------------------------------------------

.PHONY: fmt
fmt: ## Format Go and Rego sources
	$(GO) fmt ./...
	@command -v opa >/dev/null 2>&1 && opa fmt -w policies/rego || echo "opa not installed; skipped Rego formatting"

.PHONY: fmt-check
fmt-check: ## Fail if anything is unformatted
	@unformatted="$$(gofmt -l . | grep -v '^console/' || true)"; \
	if [ -n "$$unformatted" ]; then echo "unformatted Go files:"; echo "$$unformatted"; exit 1; fi
	@command -v opa >/dev/null 2>&1 && opa fmt --fail policies/rego >/dev/null || true
	@echo "formatting is clean"

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: lint
lint: ## Run golangci-lint if it is installed
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint is not installed; running go vet instead"; $(GO) vet ./...; \
	fi

.PHONY: policy-check
policy-check: ## Type-check and unit-test the Rego policy
	opa check policies/rego
	opa test policies/rego -v

.PHONY: test
test: ## Run the Go test suite
	$(GO) test -race -count=1 ./...

.PHONY: test-cover
test-cover: ## Run tests and write a coverage profile
	$(GO) test -race -count=1 -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: test-console
test-console: console-install ## Run the console test suite
	cd $(CONSOLE_DIR) && $(PNPM) test

.PHONY: typecheck
typecheck: console-install ## Type-check the console
	cd $(CONSOLE_DIR) && $(PNPM) typecheck

.PHONY: lint-console
lint-console: console-install ## Lint the console
	cd $(CONSOLE_DIR) && $(PNPM) lint

.PHONY: check
check: fmt-check vet policy-check test lint-console typecheck test-console ## Run every quality gate

# ---------------------------------------------------------------------------
# Local stack (Docker Compose)
# ---------------------------------------------------------------------------

.PHONY: secrets
secrets: ## Generate demo credentials and .env.local (never overwrites an existing file)
	@if [ -f $(COMPOSE_ENV) ]; then \
		echo "$(COMPOSE_ENV) already exists — leaving it untouched."; \
		echo "Delete it first if you really want new secrets."; \
		exit 0; \
	fi
	@node scripts/generate-demo-credentials.mjs > .env.generated
	@{ \
		echo "# GRIEFER — local environment. NEVER commit this file."; \
		echo ""; \
		echo "APP_ENV=development"; \
		echo "RESPONSE_MODE=simulation"; \
		echo "ALLOW_REAL_ACTIONS=false"; \
		echo "SYNTHETIC_DATA_ONLY=true"; \
		echo "SEED_SYNTHETIC_DEMO=true"; \
		echo "POSTGRES_PASSWORD=griefer_local_dev"; \
		echo ""; \
		grep -v '^#' .env.generated | grep -v '^$$'; \
	} > $(COMPOSE_ENV)
	@rm -f .env.generated
	@chmod 600 $(COMPOSE_ENV)
	@echo "Wrote $(COMPOSE_ENV) (mode 600). The login password is in ~/.config/griefer/demo-credentials.txt"

.PHONY: up
up: $(COMPOSE_ENV) ## Start PostgreSQL, NATS, OPA, the API and the console
	$(COMPOSE) up -d --build
	@echo ""
	@echo "GRIEFER is starting."
	@echo "  API      http://localhost:8080/health"
	@echo "  Console  http://localhost:3000"
	@echo ""
	@echo "Next:  make demo"

$(COMPOSE_ENV):
	@echo "error: $(COMPOSE_ENV) is missing. Run: make secrets" >&2
	@exit 1

.PHONY: down
down: ## Stop the stack, keeping volumes
	$(COMPOSE) down

.PHONY: down-volumes
down-volumes: ## Stop the stack and delete its volumes (synthetic data only)
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Follow stack logs
	$(COMPOSE) logs -f

.PHONY: ps
ps: ## Show stack status
	$(COMPOSE) ps

.PHONY: compose-config
compose-config: ## Validate the Compose file
	$(COMPOSE) config -q && echo "docker-compose.yml is valid"

.PHONY: demo
demo: build-api ## Replay the synthetic scenario through the running API
	$(SEED_BIN) -api $${GRIEFER_API_BASE_URL:-http://localhost:8080}

.PHONY: demo-slow
demo-slow: build-api ## Replay the scenario with a pause, to watch risk accumulate
	$(SEED_BIN) -api $${GRIEFER_API_BASE_URL:-http://localhost:8080} -pause 3s

# ---------------------------------------------------------------------------
# Native services (no Docker) — used by CI and by `make test-live`
# ---------------------------------------------------------------------------

.PHONY: services-up
services-up: ## Start PostgreSQL, NATS and OPA natively for integration tests
	@mkdir -p $(TEST_STATE_DIR)
	@scripts/local-services.sh up $(TEST_PG_PORT) $(TEST_NATS_PORT) $(TEST_OPA_PORT) $(TEST_STATE_DIR)

.PHONY: services-down
services-down: ## Stop the native test services
	@scripts/local-services.sh down $(TEST_PG_PORT) $(TEST_NATS_PORT) $(TEST_OPA_PORT) $(TEST_STATE_DIR)

.PHONY: test-live
test-live: ## Run the suite against real PostgreSQL, NATS and OPA
	GRIEFER_TEST_POSTGRES_DSN="postgres://griefer@127.0.0.1:$(TEST_PG_PORT)/griefer_test?sslmode=disable" \
	GRIEFER_TEST_NATS_URL="nats://127.0.0.1:$(TEST_NATS_PORT)" \
	GRIEFER_TEST_OPA_URL="http://127.0.0.1:$(TEST_OPA_PORT)" \
	$(GO) test -race -count=1 ./...

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------

.PHONY: tidy
tidy: ## Tidy Go module requirements
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove build output
	rm -rf $(BIN_DIR) coverage.out coverage.html $(CONSOLE_DIR)/.next
