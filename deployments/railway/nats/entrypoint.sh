#!/bin/sh
#
# Start NATS as an unprivileged user, with a writable JetStream store.
#
# A mounted volume arrives owned by root regardless of what the image declares,
# so a container that simply drops to a service account finds /data unwritable
# and NATS exits with "storage directory is not writable". The usual workaround
# is to run the server as root, which is worse.
#
# Instead: fix ownership while still privileged, then hand the server itself to
# an unprivileged uid via su-exec, which replaces this process rather than
# forking. The root phase lasts microseconds and never runs the network server.

set -eu

STORE_DIR="${GRIEFER_NATS_STORE_DIR:-/data}"
RUN_UID=10001
RUN_GID=10001

if [ "$(id -u)" = "0" ]; then
    mkdir -p "$STORE_DIR"
    chown -R "${RUN_UID}:${RUN_GID}" "$STORE_DIR"
    exec su-exec "${RUN_UID}:${RUN_GID}" /usr/local/bin/nats-server --config /etc/nats/nats.conf "$@"
fi

# Already unprivileged — the platform set a user, or a previous run fixed the
# volume. Nothing to do but start.
exec /usr/local/bin/nats-server --config /etc/nats/nats.conf "$@"
