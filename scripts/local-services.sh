#!/usr/bin/env bash
#
# Start or stop PostgreSQL, NATS JetStream and OPA natively, for integration
# tests on a machine without Docker (and for CI, where native services start
# faster than containers).
#
# Usage: scripts/local-services.sh <up|down> <pg_port> <nats_port> <opa_port> <state_dir>
#
# Everything it creates lives under <state_dir> and is safe to delete.

set -euo pipefail

ACTION="${1:?usage: local-services.sh <up|down> <pg_port> <nats_port> <opa_port> <state_dir>}"
PG_PORT="${2:-55432}"
NATS_PORT="${3:-54222}"
OPA_PORT="${4:-58181}"
STATE_DIR="${5:-.local}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PGDATA="${STATE_DIR}/pgdata"
NATS_DATA="${STATE_DIR}/natsdata"
PID_DIR="${STATE_DIR}/pids"
LOG_DIR="${STATE_DIR}/logs"

# PostgreSQL refuses a Unix socket path longer than 103 bytes, which a nested
# checkout path can easily exceed. Keep the socket somewhere short.
PG_SOCKET_DIR="${TMPDIR:-/tmp}/griefer-pg-${PG_PORT}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: $1 is not installed." >&2
    echo "  macOS: brew install $2" >&2
    echo "  Linux: see docs/ARCHITECTURE.md for package names" >&2
    exit 1
  }
}

wait_for() {
  local name="$1" probe="$2" attempts="${3:-60}"
  for _ in $(seq 1 "$attempts"); do
    if eval "$probe" >/dev/null 2>&1; then
      echo "  $name is up"
      return 0
    fi
    sleep 0.5
  done
  echo "error: $name did not become ready" >&2
  return 1
}

start() {
  require pg_ctl "postgresql@17"
  require nats-server "nats-server"
  require opa "opa"

  mkdir -p "$PID_DIR" "$LOG_DIR" "$PG_SOCKET_DIR"

  # --- PostgreSQL ---------------------------------------------------------
  if [ ! -f "$PGDATA/PG_VERSION" ]; then
    echo "initialising PostgreSQL cluster in $PGDATA"
    # A C locale keeps initdb from spawning threads that PostgreSQL 17 refuses
    # to start with on macOS.
    LC_ALL=C LANG=C initdb -D "$PGDATA" -U griefer --auth=trust -E UTF8 >"$LOG_DIR/initdb.log" 2>&1
  fi
  if ! pg_ctl -D "$PGDATA" status >/dev/null 2>&1; then
    echo "starting PostgreSQL on 127.0.0.1:$PG_PORT"
    LC_ALL=C LANG=C pg_ctl -D "$PGDATA" \
      -o "-p $PG_PORT -k $PG_SOCKET_DIR -c listen_addresses=127.0.0.1" \
      -l "$LOG_DIR/postgres.log" start >/dev/null
  fi
  wait_for "PostgreSQL" "pg_isready -h 127.0.0.1 -p $PG_PORT -U griefer"
  createdb -h 127.0.0.1 -p "$PG_PORT" -U griefer griefer_test 2>/dev/null || true

  # --- NATS JetStream ------------------------------------------------------
  if [ ! -f "$PID_DIR/nats.pid" ] || ! kill -0 "$(cat "$PID_DIR/nats.pid")" 2>/dev/null; then
    echo "starting NATS JetStream on 127.0.0.1:$NATS_PORT"
    mkdir -p "$NATS_DATA"
    nats-server -js -sd "$NATS_DATA" -a 127.0.0.1 -p "$NATS_PORT" \
      >"$LOG_DIR/nats.log" 2>&1 &
    echo $! >"$PID_DIR/nats.pid"
  fi
  wait_for "NATS" "nc -z 127.0.0.1 $NATS_PORT"

  # --- OPA -----------------------------------------------------------------
  if [ ! -f "$PID_DIR/opa.pid" ] || ! kill -0 "$(cat "$PID_DIR/opa.pid")" 2>/dev/null; then
    echo "starting OPA on 127.0.0.1:$OPA_PORT"
    opa run --server --addr "127.0.0.1:$OPA_PORT" "$REPO_ROOT/policies/rego" \
      >"$LOG_DIR/opa.log" 2>&1 &
    echo $! >"$PID_DIR/opa.pid"
  fi
  wait_for "OPA" "curl -sf http://127.0.0.1:$OPA_PORT/health"

  cat <<INFO

Services ready. Export these to run the live integration tests:

  export GRIEFER_TEST_POSTGRES_DSN="postgres://griefer@127.0.0.1:$PG_PORT/griefer_test?sslmode=disable"
  export GRIEFER_TEST_NATS_URL="nats://127.0.0.1:$NATS_PORT"
  export GRIEFER_TEST_OPA_URL="http://127.0.0.1:$OPA_PORT"

Or simply: make test-live
INFO
}

stop() {
  for name in nats opa; do
    pidfile="$PID_DIR/$name.pid"
    if [ -f "$pidfile" ]; then
      pid="$(cat "$pidfile")"
      if kill -0 "$pid" 2>/dev/null; then
        echo "stopping $name (pid $pid)"
        kill "$pid" 2>/dev/null || true
      fi
      rm -f "$pidfile"
    fi
  done
  if command -v pg_ctl >/dev/null 2>&1 && pg_ctl -D "$PGDATA" status >/dev/null 2>&1; then
    echo "stopping PostgreSQL"
    pg_ctl -D "$PGDATA" -m fast stop >/dev/null 2>&1 || true
  fi
  echo "services stopped"
}

case "$ACTION" in
  up) start ;;
  down) stop ;;
  *) echo "usage: local-services.sh <up|down> ..." >&2; exit 2 ;;
esac
