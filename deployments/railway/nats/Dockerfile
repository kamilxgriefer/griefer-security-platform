# GRIEFER event bus — NATS with JetStream and mandatory authentication.
#
# Build context: repository root.
#   docker build -f deployments/railway/nats/Dockerfile .

FROM nats:2.12-alpine

COPY deployments/railway/nats/nats.conf /etc/nats/nats.conf

# The upstream image runs as root and defines no service account, so one is
# created here. A message bus carrying every security event GRIEFER has seen has
# no business running with more privilege than it needs.
#
# JetStream's store directory is created and owned by that account. The platform
# mounts a volume here; without one, stream state is lost on restart — which
# degrades the bus, and is why the GRIEFER API treats publishing as best-effort.
# su-exec replaces the current process rather than forking, so the server still
# runs as PID 1 and receives signals directly.
RUN apk add --no-cache su-exec \
    && addgroup -g 10001 -S griefer \
    && adduser -u 10001 -S -G griefer -H -s /sbin/nologin griefer \
    && mkdir -p /data \
    && chown -R 10001:10001 /data /etc/nats

COPY deployments/railway/nats/entrypoint.sh /usr/local/bin/griefer-nats-entrypoint.sh
RUN chmod 0755 /usr/local/bin/griefer-nats-entrypoint.sh

# The container starts as root ONLY to make the mounted volume writable, then
# drops to uid 10001 before the server starts. See entrypoint.sh — a mounted
# volume arrives root-owned whatever the image declares, and the alternative is
# running the network server as root.

EXPOSE 4222 8222

# The config names $NATS_USER and $NATS_PASSWORD; NATS expands them at load, so
# the credentials stay in the platform's secret store and never enter the image.
#
# The upstream entrypoint is bypassed: it rewrites arguments in ways that are
# convenient interactively and surprising in a deployment.
ENTRYPOINT ["/usr/local/bin/griefer-nats-entrypoint.sh"]
CMD []
