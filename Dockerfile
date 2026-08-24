# GRIEFER API — multi-stage build producing a minimal, non-root image.
#
# Everything the binary needs at runtime (event schema, Rego policy, detection
# rules, synthetic fixtures) is embedded at compile time, so the final stage
# carries no application files beyond the binary itself.

# --- Build ------------------------------------------------------------------
FROM golang:1.27-alpine AS build

WORKDIR /src

# Dependencies first so a source-only change does not invalidate the module
# cache layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO is off so the binary runs on a distroless base with no libc.
# -trimpath keeps build paths out of the binary and out of any panic output.
ARG VERSION=0.1.0
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w" \
        -o /out/griefer-api ./cmd/griefer-api \
    && CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w" \
        -o /out/griefer-seed ./cmd/griefer-seed

# --- Runtime ----------------------------------------------------------------
#
# This is the LAST stage in the file, and that is load-bearing rather than
# incidental: `docker build` with no --target produces whatever stage comes
# last. This file previously ended with a `test` stage, so a platform building
# it the plain way got the Go toolchain instead of the service. Railway did
# exactly that and deployed it as the console — the container started, nothing
# listened, and the only symptom was a 502 with no application log.
#
# The test stage has since been deleted rather than merely moved. Nothing
# targeted it, the Go suite already runs natively in CI and in a Linux
# container, and a stage that exists only to be skipped is a stage that can be
# reached by accident. scripts/verify-image-contract.sh fails the build if this
# stops being last.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

# Distroless "nonroot" runs as uid 65532 and contains no shell and no package
# manager: there is nothing for an attacker who reaches RCE to pivot into.
WORKDIR /app
COPY --from=build /out/griefer-api /app/griefer-api
COPY --from=build /out/griefer-seed /app/griefer-seed

USER nonroot:nonroot

# Loopback by default. The Compose stack overrides this and publishes the port
# to the host only.
ENV GRIEFER_HTTP_ADDR=0.0.0.0:8080 \
    GRIEFER_ALLOW_PUBLIC_BIND=true \
    GRIEFER_LOG_FORMAT=json \
    GRIEFER_RESPONSE_MODE=simulate

EXPOSE 8080

ENTRYPOINT ["/app/griefer-api"]
