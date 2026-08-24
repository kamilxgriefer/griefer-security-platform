#!/usr/bin/env bash
#
# Assert that the images CI builds are the images the platform deploys.
#
# This exists because of a real incident, not a hypothetical one. The root
# Dockerfile once ended with its `test` stage, so `docker build` with no
# --target produced the Go build environment. Compose and CI both pinned
# `target: runtime`, which is exactly why nobody noticed: every build run here
# was correct. Railway builds a Dockerfile the plain way, deployed that image as
# the console, and the only symptom was a 502 with no application log.
#
# The lesson was not "pin the target everywhere". It was that the deployed
# artifact must not depend on which stage happens to be last, and that the
# assumption must be checked by something that fails.
#
# Usage: scripts/verify-image-contract.sh
set -euo pipefail

fail=0
note() { printf '  %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; fail=1; }
ok() { printf '  ok    %s\n' "$*"; }

# --- 1. The final stage of every service Dockerfile is its runtime stage ------
#
# Parsed rather than eyeballed: `docker build` with no --target produces the
# LAST stage in the file, whatever it is called.
check_final_stage() {
    local file="$1" want="$2"
    local last
    last=$(grep -E '^[[:space:]]*FROM[[:space:]]' "$file" \
        | tail -1 \
        | sed -E 's/.*[[:space:]][Aa][Ss][[:space:]]+([A-Za-z0-9_.-]+).*/\1/')
    if [ "$last" = "$want" ]; then
        ok "$file final stage is '$want'"
    else
        bad "$file final stage is '$last', expected '$want' — a target-less build would deploy the wrong image"
    fi
}

echo "final build stage:"
check_final_stage Dockerfile runtime
check_final_stage console/Dockerfile runtime

# --- 2. No service Dockerfile ends on a stage that runs tests ----------------
#
# A test stage as the final stage is the specific shape of the original bug.
echo "test stages are not final:"
for file in Dockerfile console/Dockerfile deployments/railway/opa/Dockerfile deployments/railway/nats/Dockerfile; do
    [ -f "$file" ] || continue
    last=$(grep -E '^[[:space:]]*FROM[[:space:]]' "$file" | tail -1)
    if printf '%s' "$last" | grep -qiE '[[:space:]]as[[:space:]]+test'; then
        bad "$file ends on a test stage"
    else
        ok "$file does not end on a test stage"
    fi
done

# --- 3. Every service names the Dockerfile it builds from --------------------
#
# Railway builds whatever RAILWAY_DOCKERFILE_PATH points at, defaulting to
# ./Dockerfile relative to the service root. Leaving that implicit is how the
# console came to be built from the API's Dockerfile.
echo "deployment configuration is explicit:"
for cfg in deployments/railway/api.json deployments/railway/console.json \
           deployments/railway/opa.json deployments/railway/nats.json; do
    if [ -f "$cfg" ]; then
        ok "$cfg present"
        if ! grep -q '"dockerfilePath"' "$cfg"; then
            bad "$cfg does not name a dockerfilePath"
        fi
    else
        bad "$cfg is missing — the service's build would depend on a dashboard setting"
    fi
done

# --- 4. Compose pins the same target CI and Railway produce ------------------
echo "compose agrees with the deployed stage:"
if grep -qE 'target:[[:space:]]*runtime' docker-compose.yml; then
    ok "docker-compose.yml pins target: runtime"
else
    bad "docker-compose.yml does not pin target: runtime"
fi

echo
if [ "$fail" -ne 0 ]; then
    echo "image contract: FAILED"
    exit 1
fi
echo "image contract: all checks passed"
