# GRIEFER API — multi-stage build producing a minimal, non-root image.
#
# Everything the binary needs at runtime (event schema, Rego policy, detection
# rules, synthetic fixtures) is embedded at compile time, so the final stage
# carries no application files beyond the binary itself.

# --- Build ------------------------------------------------------------------
FROM golang:1.25-alpine AS build

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

# --- Test -------------------------------------------------------------------
# Opt-in: `docker build --target test .` runs the suite in the same environment
# the image is built in.
#
# This sits BEFORE the runtime stage, so that runtime is the last stage in the
# file and therefore what a build with no --target produces.
#
# That ordering is not cosmetic. Compose and CI both pin `target: runtime`, so
# the mistake is invisible locally — but a platform that builds the Dockerfile
# without a target gets whichever stage is last. Railway did exactly that, and
# deployed this Go build environment as the console: the container started,
# nothing listened, and the only symptom was a 502 from the edge.
#
# The cost is that a target-less build under the *classic* builder walks every
# stage in order and so also runs the tests, which is slow. BuildKit — Railway,
# CI, and any recent Docker — builds only what the target needs and skips this
# stage entirely. A slow build is visible the moment it happens; a test-stage
# image serving production is not, so the trade goes this way round.
FROM build AS test
RUN go vet ./... && go test -count=1 ./...

# --- Runtime ----------------------------------------------------------------
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
