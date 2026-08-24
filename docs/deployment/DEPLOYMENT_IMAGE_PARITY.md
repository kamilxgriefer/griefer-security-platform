# Deployment image parity

The image a platform deploys must be the image this repository intends to ship,
and that must be true without depending on anyone remembering to pass a flag.
This document records the incident that made the point, the fix that was chosen
over the obvious one, and the two mechanisms — a static contract check and a CI
job that builds each image the way the platform builds it — that now fail loudly
if the guarantee lapses.

---

## The incident

The console returned **502 from the edge and produced no application log**.

Nothing in the running system explained it, and that absence was itself the
signal: a service that crashes leaves a stack trace, a service that binds the
wrong port leaves a startup line. This left neither. The container had started
and stayed started; nothing inside it was ever going to listen.

The **build** log gave it away. The console's build was compiling `griefer-api`
inside `golang:alpine` — the Go toolchain, not a Next.js server. The deployed
image was the root `Dockerfile`'s **`build` stage lineage**, and specifically the
stage that happened to sit at the bottom of that file: a `test` stage, defined as
`FROM build AS test` running `go vet ./... && go test -count=1 ./...`.

The mechanism is unremarkable once stated. `docker build` with **no `--target`**
produces the **last stage in the file**. The root `Dockerfile` ended with `test`,
so a plain build produced a Go build environment. Railway builds a Dockerfile the
plain way. That image was deployed as the console. It ran, exited its build
command, and served nothing — hence a 502 with no application log to explain it.

The stage order was not careless. It was deliberate, and the reason was real: the
classic Docker builder walks stages in file order, so putting `test` earlier made
every ordinary build also run the suite. Putting it last kept builds fast under
that builder. The reasoning was sound and the consequence was a Go toolchain
serving production traffic.

**Why nobody caught it locally.** `docker-compose.yml` pinned `target: runtime`.
The CI container job pinned `target: runtime`. Every build anyone in this
repository ever ran was correct. The defect could only appear somewhere that
built the file without a target — which is to say, only in the one place where it
mattered.

---

## Why pinning `--target` everywhere was not the fix

The first instinct is to add `--target runtime` to every remaining build site,
including the platform's. That is precisely the wrong lesson, for two reasons.

**It treats the symptom as the cause.** The cause was not a missing flag. The
cause was that *correctness depended on which stage happened to be last in a
file* — a property no reviewer checks, that no test asserted, and that any future
commit appending a stage could silently invert. Pinning the target everywhere
leaves that property intact and merely adds one more place it is being papered
over. It also adds a new failure mode: a build site that is added later and
forgets the pin inherits the original bug, with the same silent signature.

**It was the pinning that hid the bug in the first place.** Compose and CI both
pinned, which is exactly why every local build was correct and the mistake was
invisible for as long as it was. More pinning would have made the repository
*better at hiding* the same class of defect, not better at deploying.

The requirement is therefore stated the other way round: **a target-less build of
any service Dockerfile must produce that service**. `--target` may then be used
for speed or for clarity, but nothing may depend on it. Compose still pins
`target: runtime` — not because the build needs it, but because the pin is a
declaration that can be compared against the Dockerfile, and a drift detector is
worth keeping once it costs nothing.

An intermediate commit (`d11fa9e`) moved `runtime` to the bottom. That fixed the
outage and left the shape of the problem untouched: the file was still one
appended stage away from being wrong again.

---

## The deleted test stage, and why deleting beat reordering

The `test` stage is **gone**, not moved.

Reordering leaves a stage in the file whose only purpose is to be skipped, and a
stage that exists only to be skipped is a stage something can reach by accident —
by a future `FROM` appended below it, by a platform that resolves targets
differently, by a copy of the file made for another service. The safest state for
that stage is non-existence.

Deletion cost nothing, which is what made it the right call rather than a
purist's one:

- **Nothing targeted it.** No workflow, no Compose service, no Makefile rule ever
  passed `--target test`.
- **The suite already runs elsewhere, and better.** The `Backend` CI job runs
  `go test -race -count=1 ./...` natively on `ubuntu-latest` against real
  PostgreSQL, NATS with JetStream, and OPA — a stronger test than the container
  stage ever performed, which had no dependencies at all. `make test` runs the
  same suite locally, and `Compose end-to-end` exercises the built images as a
  stack.
- **It was costing real build time.** Under the classic builder, a target-less
  build walks every stage in order, so once `runtime` moved last the test stage
  ran on every plain build.

The root `Dockerfile` now ends on `runtime`, and its comment says so in the file
rather than only here, because the next person to append a stage reads the file,
not the documentation.

---

## What each service builds

| Service | Dockerfile | Build context | Final stage | Entrypoint / command | Health probe |
|---|---|---|---|---|---|
| `api` | `Dockerfile` | repository root | `runtime` — `gcr.io/distroless/static-debian12:nonroot` | `ENTRYPOINT ["/app/griefer-api"]` | Railway: `GET /health`, 30 s timeout. Compose: `/app/griefer-api -healthcheck` |
| `console` | `console/Dockerfile` | `./console` | `runtime` — `node:22-alpine` | `CMD ["node", "server.js"]` | Railway: `GET /api/health`, 30 s timeout. Compose: `node -e` fetching `/api/health` on loopback |
| `opa` | `deployments/railway/opa/Dockerfile` | repository root | single stage — `openpolicyagent/opa:1.9.0-static` | `ENTRYPOINT ["/opa"]`, `CMD ["run", "--server", …]` | Railway: none. Compose: `opa eval` against the baked bundle |
| `nats` | `deployments/railway/nats/Dockerfile` | repository root | single stage — `nats:2.12-alpine` | `ENTRYPOINT ["/usr/local/bin/griefer-nats-entrypoint.sh"]`, `CMD []` | Railway: none. Compose: `wget --spider` on the monitoring port's `/healthz` |
| `postgres` | none — Railway's managed PostgreSQL | — | — | — | platform-managed |

Notes that matter when reading the table:

- **`opa` and `nats` are single-stage on purpose.** A file with one stage cannot
  have the wrong last stage, which removes this entire class of defect from them
  by construction. They still get checked (below) for the narrower case of ending
  on a test stage.
- **Contexts differ, and the difference is load-bearing.** `opa` and `nats` build
  from the **repository root** because they copy policy and configuration out of
  it — the Rego bundle and `nats.conf` are baked in rather than mounted, so the
  running policy is the policy that was reviewed in the commit that built the
  image. The console builds from `./console`, which is where its `package.json`,
  `pnpm-lock.yaml` and `pnpm-workspace.yaml` live.
- **`opa` and `nats` have no platform health probe.** That is a gap, not a
  decision: neither exposes an unauthenticated endpoint the platform is
  configured to poll, so their liveness is currently asserted only by Compose
  locally and by the API's own behaviour when they are unreachable.
- **Every runtime runs unprivileged.** `api` as distroless `nonroot` (uid 65532,
  no shell, no package manager); `console` as `node`, with npm, npx, corepack and
  yarn deleted from the image; `opa` as `1000:1000`; `nats` starts as root only
  long enough to make a mounted volume writable, then `su-exec`s to uid 10001 so
  the network server itself never runs as root.
- **The console's health route deliberately does not probe the API.** It answers
  "is the console serving?". A console that restarts whenever the backend blips
  is a console nobody can use to diagnose the blip.

---

## What `deployments/railway/*.json` pins

Four files — `api.json`, `console.json`, `opa.json`, `nats.json` — each commit
the same three things:

- **`build.builder: "DOCKERFILE"`** — the platform must not infer a build. A
  buildpack guess that succeeds is worse than one that fails, because it produces
  a plausible image nobody chose.
- **`build.dockerfilePath`** — the exact file. Railway builds whatever
  `RAILWAY_DOCKERFILE_PATH` points at, defaulting to `./Dockerfile` relative to
  the service root; leaving that implicit is *how the console came to be built
  from the API's Dockerfile in the first place*.
- **`deploy`** — restart policy (`ON_FAILURE`, max 10 retries) for all four, plus
  `healthcheckPath` and `healthcheckTimeout` for `api` (`/health`) and `console`
  (`/api/health`).

The point of committing them is reviewability. A dashboard setting has no diff,
no history and no reviewer; a file in the repository has all three, and a change
to which Dockerfile a service builds becomes a change someone can object to.

**Honest limit.** These files are committed and CI-enforced, but nothing in this
repository proves the platform is reading them. There is no `railway.json` at the
repository root, so each service must be pointed at its config file through its
own settings — and that setting lives on the platform, outside version control.
The JSON files are therefore a reviewable *declaration of intent* plus a CI
contract; they are not, by themselves, evidence of what production is configured
to do. The CI job below closes part of that gap by building from the declared
paths, so at minimum the declaration is known to be buildable and correct.

**A second limit, and a genuinely open finding.** The Railway services are not
connected to GitHub. They were deployed by uploading a directory with
`railway up`, so the platform records **no commit for any deployment**. Nothing
here can tell you which revision is running; that has to be established out of
band. `.railwayignore` exists because of the same upload path — it repeats the
exclusions that matter (`.env`, `.env.*`, `*.local`, `.git`, `node_modules`)
rather than inheriting them from `.gitignore`, because the cost of being wrong is
a secret leaving the machine.

---

## What `scripts/verify-image-contract.sh` checks

A static check, no Docker daemon required, four assertions:

1. **The final stage of each multi-stage service Dockerfile is `runtime`.** The
   file's `FROM` lines are parsed and the last one's `AS` name extracted, because
   this is exactly the property that cannot be eyeballed reliably — checked for
   `Dockerfile` and `console/Dockerfile`.
2. **No service Dockerfile ends on a test stage.** Applied to all four, including
   the single-stage `opa` and `nats` files. This is the specific shape the
   original bug took, matched by name rather than by position.
3. **Every service has a committed deployment configuration** at
   `deployments/railway/<service>.json`, and each one names a `dockerfilePath`. A
   missing file is reported as "the service's build would depend on a dashboard
   setting", which is the actual consequence.
4. **Compose has not drifted** off `target: runtime`.

Running it against the current tree passes all four.

### Both failure modes were verified by reintroducing them

A check nobody has seen fail is a check nobody knows works. Each failure mode was
reproduced against a copy of the tree:

- **Appending `FROM build AS test` to the root `Dockerfile`** — i.e. restoring
  the original stage order — trips checks 1 and 2 together, reporting
  `Dockerfile final stage is 'test', expected 'runtime'` and
  `Dockerfile ends on a test stage`, and exits `1`.
- **Deleting `deployments/railway/console.json`** trips check 3 and exits `1`.
- **Pointing Compose at a different target** trips check 4 and exits `1`.

---

## The CI job: `Deployment image contract`

Defined in `.github/workflows/ci.yml`. It runs the static script above, then
builds each image **exactly the way the platform builds it**: the Dockerfile
named in `deployments/railway/*.json`, that file's own context, and **no
`--target`**.

```
docker build -f Dockerfile -t griefer-api:contract     .
docker build -f Dockerfile -t griefer-console:contract ./console
```

Passing `--target` here would test something the platform never produces, which
is the exact mistake being defended against. This job is deliberately separate
from the existing `Container images` job, which *does* pin `target: runtime` and
checks different properties (non-root user, no package manager in the console
image). Two jobs, two questions: "is the intended image sound?" and "is the
image the platform gets the intended one?".

### Exact smoke-test expectations

**API image** — started as `api-contract`, port `18081` on the runner's loopback
mapped to container `8080`, with `GRIEFER_HTTP_ADDR=0.0.0.0:8080`,
`GRIEFER_ALLOW_PUBLIC_BIND=true` and a throwaway `INTERNAL_API_TOKEN` set by the
job itself. Readiness is polled up to 40 times at 1-second intervals against
`/health`.

| Assertion | Expected |
|---|---|
| `docker inspect -f '{{json .Config.Entrypoint}}'` | contains `griefer-api` |
| the same entrypoint string | must **not** match `go\b` or `/usr/local/go` — a Go toolchain as PID 1 is the original failure, named explicitly |
| `GET /health` with no token | `200` |
| `GET /ready` with no token | `200` |
| `GET /api/v1/incidents` with no token | `401` |
| `GET /metrics` with no token | `401` |
| `GET /api/v1/incidents` with `Authorization: Bearer <the job's token>` | `200` |
| `docker stop -t 20`, then `.State.ExitCode` | `0` |

Two of these are subtler than they look. The **authenticated 200** is what makes
the two 401s meaningful: without it, a service that had failed to start would
produce the same pair of refusals and pass. And **`/metrics` is expected to 401**
because it is not exempt — only `/health` and `/ready` are, so a platform can
probe liveness before it holds any credential. Metrics describe ingest volume,
incident counts and policy verdicts, which is enough to tell an attacker whether
they have been noticed.

The **exit code 0 on SIGTERM** check exists because `143` — killed after the
20-second grace period — is not a graceful shutdown, and a container that has to
be killed loses whatever it was in the middle of writing.

**Console image** — started as `console-contract`, port `18082` mapped to
container `3000`, with `NODE_ENV=production` and placeholder session and
administrator credentials supplied by the job (the console refuses every request
without an administrator configured, so it cannot be smoke-tested with none).
Readiness is polled up to 40 times at 1-second intervals against `/login`.

| Assertion | Expected |
|---|---|
| `/proc/1/cmdline` | contains `node` |
| `/proc/1/cmdline` | must **not** contain `griefer-api` — *this is the exact failure the job exists to catch* |
| `GET /login` | `200` |
| `GET /` unauthenticated | `307`, the redirect to `/login` |
| `.State.Running` after the checks | `true` |

The **still-running** assertion is not redundant. The original incident's image
started, did its work and exited; anything that only inspects logs or a single
response can miss that. And the `griefer-api`-as-PID-1 assertion is written as
its own failing condition rather than being implied by the `node` check, because
a regression here should say what happened, not merely that something was wrong.

Both containers are removed in an `always()` teardown step.

---

## What this does not guarantee

- **It does not prove what is running in production.** Railway records no commit
  for these deployments (see above), and the platform's own config-file settings
  are outside this repository. The contract guarantees that *building the
  declared files the plain way yields the right services*; matching that to a
  live deployment is still manual.
- **It checks stage names, not stage contents.** A stage named `runtime` that
  built the wrong thing would pass checks 1 and 2. The CI smoke tests are what
  actually catch that, and only for `api` and `console`.
- **`opa` and `nats` images are not smoke-tested by this job.** They are built
  and exercised by `Compose end-to-end`, which is a weaker guarantee than the
  per-image checks the other two get.
- **Two stale comments still describe the old world.** `docker-compose.yml`
  (above `target: runtime` on the `api` service) and the `Container images` job
  in `.github/workflows/ci.yml` both still say the test stage is last in the
  file. It no longer exists. The pins those comments justify are still wanted —
  as drift detection rather than as necessity — but the stated reason is now
  wrong, and a reader grepping for `target: runtime` will hit the contradiction
  before they reach this document.
