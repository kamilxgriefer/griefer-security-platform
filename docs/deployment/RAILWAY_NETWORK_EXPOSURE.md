# Railway network exposure

GRIEFER runs five things on Railway, and exactly one of them is meant to be
reachable from the internet. This document records what the intended shape is,
how it was **checked against the platform's own records** rather than guessed at
from the outside, what the check actually returned, and what the check still
cannot tell you.

It exists because the obvious ways of answering "is the database exposed?" —
open a browser, run `dig` — return confident-looking answers that are not
evidence. Getting that wrong is not a cosmetic error: the failure mode is a
managed PostgreSQL instance on a public port.

Verified 2026-08-24, project `griefer`, environment `production`.

---

## 1. The intended model

| Service | Public HTTP | Public TCP proxy | Private network | Expected |
|---|---|---|---|---|
| `console` | **yes** — `console-production-b3ea.up.railway.app` | none | yes | the sole public entry point |
| `api` | none | none | yes | no public address of any kind |
| `opa` | none | none | yes | no public address of any kind |
| `nats` | none | none | yes | no public address of any kind |
| `Postgres` | none | none | yes | no public address of any kind |

The rule behind the table is narrower than "keep internal services internal".
In v0.1 the API has no user authentication — it has a single shared service
credential (`INTERNAL_API_TOKEN`) and nothing else. Authorisation lives in the
console's session gate and in the policy engine, both of which sit *in front of*
the API. A public address on `api` does not weaken a control; it routes around
every control there is. The same argument applies to `opa`, whose verdicts the
API trusts, and to `nats`, which carries the event stream.

`Postgres` is the one where the consequence is unbounded rather than merely bad,
which is why it is listed in the table even though nothing in this repository
ever configures it.

---

## 2. Why the checks people reach for first prove nothing

### 2.1 An HTTP 404 is not evidence of anything

Asking `https://<service>.up.railway.app` and getting

```json
{"status":"error","code":404,"message":"Application not found"}
```

feels conclusive. It is not, for two separate reasons.

**It cannot distinguish the cases you care about.** That body is what Railway's
edge returns for *any* hostname with no HTTP route attached. Verified directly —
a hostname invented for the test, corresponding to no service in any account,
returns exactly the response above with HTTP 404. "No such service", "service
exists but has no domain", and "service exists, has a domain, and the edge is
briefly unhappy" are all the same 404 from outside.

**It is a test of the wrong control.** A TCP proxy is not HTTP routing. Railway
publishes it on a different hostname under a different domain and on a high
numbered port, and it forwards raw TCP — which is precisely why it is the
mechanism used to expose a database. A service can return "Application not
found" on its HTTP name all day while a proxy in front of it happily accepts
PostgreSQL connections. Probing HTTP and concluding "not exposed" is checking
the front door to find out whether the side gate is locked.

### 2.2 DNS resolves for every name, so resolution carries no information

`*.up.railway.app` is a wildcard. Verified:

| Name queried | Resolves |
|---|---|
| the real console hostname | yes |
| `definitely-not-a-real-service-x9q7z.up.railway.app` | yes |
| `another-nonsense-name-4482.up.railway.app` | yes |

Two of those three services do not exist. Every name under the suffix answers
with an address in Railway's edge pool, so a successful lookup says nothing
about whether a service is behind it — and, just as importantly, a lookup can
never *fail* in a way that would demonstrate absence. The test has no
discriminating power in either direction.

> **This invalidates an existing instruction.** `deployments/railway/README.md`
> currently ends its "Public exposure" section with *"After deploying, confirm
> it: every one of the four should fail to resolve."* That check cannot pass
> and cannot fail meaningfully; the wildcard guarantees resolution regardless.
> Anyone following it either concludes the deployment is broken or, worse, works
> out that resolution is normal and quietly stops checking. It should be
> replaced with a pointer to §5 of this document.

### 2.3 `railway domain` is not a read-only command

Worth stating before someone reaches for the CLI as a quicker check. From
`railway domain --help` (CLI 5.43.1):

> Running without a subcommand preserves the original create behavior:
> `railway domain` generates a Railway-provided service domain

Running the bare command against `api` to see whether it has a domain **gives it
one**. The read-only forms are `railway domain list` and `railway tcp-proxy
list`; the inspection commands and the mutating commands differ by a single
word.

---

## 3. What was actually done

Ask the control plane, not the network. Railway's public GraphQL API will state
what routes exist, which turns the question from an inference into a lookup.
Two queries per service, in every environment (schema confirmed by
introspection against the live API):

```graphql
domains(projectId: String!, environmentId: String!, serviceId: String!): AllDomains!
#   AllDomains { serviceDomains: [ServiceDomain!]!  customDomains: [CustomDomain!]! }

tcpProxies(environmentId: String!, serviceId: String!): [TCPProxy!]!
#   TCPProxy { domain  proxyPort  applicationPort  ... }
```

Both return lists, so an empty result is a positive statement by the platform
that no such route is configured — not the absence of a reply. `serviceDomains`
covers Railway-generated `*.up.railway.app` names and `customDomains` covers
anything pointed at the service by CNAME, which matters because the second kind
would never be guessed by probing the first.

A third field, `ServiceInstance.source { repo image }`, was read at the same
time; §6 explains why.

---

## 4. Result

Every service in the only environment that exists, queried individually:

| Service | `serviceDomains` | `customDomains` | `tcpProxies` |
|---|---|---|---|
| `console` | 1 — `console-production-b3ea.up.railway.app` | 0 | **0** |
| `api` | 0 | 0 | **0** |
| `nats` | 0 | 0 | **0** |
| `opa` | 0 | 0 | **0** |
| `Postgres` | 0 | 0 | **0** |

The deployment matches the intended model. No drift, and in particular no TCP
proxy anywhere — including on `Postgres`, where Railway offers public networking
as a one-click convenience and where enabling it would be the single most
damaging misconfiguration available in this project.

### What this result does not establish

Stating the limits, because a verification whose scope is unclear gets cited for
things it never checked:

- **It is a snapshot.** Anyone with project access can add a domain or a proxy
  in one click, and nothing in this repository would notice. The value of §5 is
  that it is repeatable, not that it was run once.
- **It says nothing about what a service binds.** The platform's routing table
  and the process's listening sockets are independent facts. `api` binding
  `0.0.0.0` is fine *because* no route reaches it; the two must be reasoned
  about together, never one from the other.
- **It says nothing about the private network's internal boundaries.** Every
  service in the project can reach every other service. There is no segmentation
  between `console` and `Postgres` beyond the fact that nothing tells the
  console to connect to it.
- **Egress is out of scope.** This covers what can reach in.

---

## 5. Re-verification

The check below resolves the project by name and discovers environment and
service identifiers at runtime, so nothing needs updating when identifiers
change and no identifier ends up committed. It iterates **every** environment,
not just `production`: a proxy on a throwaway environment still points at the
same managed database.

Requires the Railway CLI, an authenticated session (`railway whoami`), and
`python3`. Every call is read-only.

```bash
#!/usr/bin/env bash
# Assert that `console` is the only publicly reachable Railway service.
set -euo pipefail

PROJECT="${PROJECT:-griefer}"
BOOTSTRAP_ENV="${BOOTSTRAP_ENV:-production}"
PUBLIC_SERVICE="${PUBLIC_SERVICE:-console}"

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

# The project id is not committed anywhere, so resolve it from the name.
project_id=$(railway status --project "$PROJECT" --environment "$BOOTSTRAP_ENV" --json </dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

# Every environment, not just production: a proxy on a non-production
# environment still points at the same managed Postgres.
railway api 'query($p:String!){project(id:$p){environments{edges{node{id name serviceInstances{edges{node{serviceName serviceId source{repo image}}}}}}}}}' \
  --raw-var "p=$project_id" </dev/null \
  | python3 -c '
import json, sys
d = json.load(sys.stdin)["data"]["project"]
for e in d["environments"]["edges"]:
    env = e["node"]
    for si in env["serviceInstances"]["edges"]:
        n = si["node"]
        src = n.get("source") or {}
        print("\t".join([env["name"], env["id"], n["serviceName"], n["serviceId"],
                         src.get("repo") or "-", src.get("image") or "-"]))
' > "$work/targets.txt"

while IFS=$'\t' read -r env_name env_id svc_name svc_id repo image; do
    n_http=$(railway api 'query($p:String!,$e:String!,$s:String!){domains(projectId:$p,environmentId:$e,serviceId:$s){serviceDomains{domain}customDomains{domain}}}' \
      --raw-var "p=$project_id" --raw-var "e=$env_id" --raw-var "s=$svc_id" </dev/null \
      | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]["domains"]; print(len(d["serviceDomains"])+len(d["customDomains"]))')

    n_tcp=$(railway api 'query($e:String!,$s:String!){tcpProxies(environmentId:$e,serviceId:$s){domain proxyPort applicationPort}}' \
      --raw-var "e=$env_id" --raw-var "s=$svc_id" </dev/null \
      | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["data"]["tcpProxies"]))')

    want_http=0; [ "$svc_name" = "$PUBLIC_SERVICE" ] && want_http=1

    [ "$n_http" -eq "$want_http" ] \
      && echo "  ok    $env_name/$svc_name  public HTTP domains=$n_http" \
      || { echo "  FAIL  $env_name/$svc_name  public HTTP domains=$n_http, expected $want_http"; touch "$work/fail"; }

    [ "$n_tcp" -eq 0 ] \
      && echo "  ok    $env_name/$svc_name  public TCP proxies=0" \
      || { echo "  FAIL  $env_name/$svc_name  public TCP proxies=$n_tcp"; touch "$work/fail"; }

    if [ "$repo" != "-" ]; then
        echo "  ok    $env_name/$svc_name  source: GitHub $repo — deployments carry a commit"
    elif [ "$image" != "-" ]; then
        echo "  ok    $env_name/$svc_name  source: image $image — no repository expected"
    else
        echo "  note  $env_name/$svc_name  source: none — uploaded by \`railway up\`, no commit recorded"
    fi
done < "$work/targets.txt"

[ -e "$work/fail" ] && { echo "exposure: FAILED"; exit 1; }
echo "exposure: as intended"
```

Expected output today — one `ok` pair per service, `note` on the four uploaded
services, and exit status 0:

```
  ok    production/console  public HTTP domains=1
  ok    production/console  public TCP proxies=0
  note  production/console  source: none — uploaded by `railway up`, no commit recorded
  ok    production/api  public HTTP domains=0
  ok    production/api  public TCP proxies=0
  ...
  ok    production/Postgres  public TCP proxies=0
  ok    production/Postgres  source: image ghcr.io/railwayapp-templates/postgres-ssl:18 — no repository expected
exposure: as intended
```

Run it after any deployment that adds a service, after anyone else is granted
project access, and before any demonstration. If Railway's schema shifts under
it, `railway api describe Query.domains` and `railway api describe Query.tcpProxies`
report the current signatures.

This is deliberately **not** wired into CI. CI has no Railway credential, and
giving it one — a token that can enumerate and mutate the production project,
held by a system that executes code from branches — would create a worse problem
than the one being checked for.

---

## 6. How the console reaches the API without a public API

The API is unreachable from the internet, and the console still has to talk to
it. Both paths run **server-side inside the console container** and address the
API by its private network name (`<service>.railway.internal`; the concrete
values are in `deployments/railway/README.md` alongside the variables that set
them).

**Path one — React Server Components.** `console/lib/api.ts` opens with
`import "server-only"`, which makes the module a build error if anything in the
client bundle imports it. The base address comes from `GRIEFER_API_BASE_URL`,
and neither it nor any other value in `console/lib/config.ts` is prefixed
`NEXT_PUBLIC_`, so none of them can be inlined into client JavaScript. The
private address of the API is the one piece of configuration whose leak would
convert a locked console into a map of the internal network.

**Path two — the browser-facing gateway.** Browser-initiated calls land on
`console/app/api/griefer/[...path]/route.ts`, which is not a generic proxy. A
proxy that forwards whatever path it is handed is a server-side request forgery
primitive that happens to hold the service credential: the caller picks the
target, the gateway supplies the authorisation. Instead it matches an explicit
allowlist of method-and-path pairs, constrains identifiers to
`/^[A-Za-z0-9._:-]{1,256}$/` so they cannot smuggle a traversal or a second URL,
and permits only named query parameters with fixed shapes. The session cookie is
checked in middleware before any of it runs.

Only after that does the request acquire `INTERNAL_API_TOKEN` and cross the
private network.

One consequence worth spelling out: **there is no CORS configuration anywhere,
and that is correct.** CORS governs what a browser may do with a cross-origin
response. Since no browser can address the API at all, there is no cross-origin
request to govern. Adding CORS headers would only make sense if the API were
reachable from a browser — which is the thing this design prevents.

### The bind address is a separate question from exposure

`GRIEFER_ALLOW_PUBLIC_BIND=true` is set on `api`, and reads alarmingly. It is
not about exposure. `internal/config/config.go` refuses to bind a non-loopback
address when the service has neither a credential nor an explicit
acknowledgement, because an unauthenticated listener on an unknown network is
worth failing over. Inside a container, the container's own interface is not the
internet; what makes a service reachable is whether the platform gave it a
route, which §4 confirms it did not. The API also sets `INTERNAL_API_TOKEN`, so
it satisfies the check by the stronger of the two available routes and the
permissive flag is belt-and-braces.

`GRIEFER_HTTP_ADDR` is set explicitly to `:8080` rather than left to the
platform. That matters: `listenAddr()` falls back to `0.0.0.0:$PORT` when only
`PORT` is injected, and `0.0.0.0` is an IPv4 wildcard, whereas Railway's private
network addresses services over IPv6. The explicit `:8080` binds both families.

---

## 7. Open finding — no deployment records a commit

**Status: open.** Not remediated in M1.1; recorded here because the exposure
verification surfaced it.

`ServiceInstance.source` is `{repo: null, image: null}` for `console`, `api`,
`opa` and `nats`. None of the four is connected to the GitHub repository. They
were deployed with `railway up`, which uploads the working directory as the
build context, so **Railway has no commit to associate with any deployment of
them.** (`Postgres` reports `image` and no repo, which is correct for a managed
template and is not part of this finding.)

The deployment metadata does record the resulting image digest, so two
deployments can be told apart. What is missing is the link from that digest back
to source: nothing maps a running container to a commit.

Why this is a security finding and not a workflow annoyance:

- **"What is running in production?" has no checkable answer.** The provenance
  of a deployment is a directory that existed on one machine at one moment. It
  cannot be diffed against `main`, and a compromise or a mistake cannot be
  scoped by asking which commits were live.
- **Uncommitted changes deploy silently.** Local edits, a stray debug flag, a
  half-finished branch — all ship without leaving a trace anywhere the
  repository can see.
- **`.gitignore` stops being the boundary that matters.** The upload is the
  build context, so exclusion depends entirely on `.railwayignore`. That file
  exists and duplicates the important exclusions deliberately, and it is now the
  only thing standing between a local secret and a build context.
- **It breaks the chain the M1.1 image-contract work was building.**
  `scripts/verify-image-contract.sh` and the "Deployment image contract" CI job
  establish that a target-less `docker build` of the repository's Dockerfiles
  produces the right images. That guarantee is about *the repository*. With no
  commit recorded against a deployment, there is nothing tying the image
  Railway actually ran to a commit those checks ever passed on.

Remediation is to connect each service to the repository (`railway service
source`) so deployments are triggered by, and labelled with, a commit. That
changes how the project is deployed and who can deploy it, so it is Kamil's
decision rather than a change to be made in passing. Until then, treat the
deployed environment as a demonstration whose contents are asserted rather than
proven.

---

## Related

- `deployments/railway/README.md` — per-service images, variables, and the
  post-deploy checklist (see the correction in §2.2)
- `docs/security/DEPENDENCY_REMEDIATION_M1_1.md` — the other M1.1 finding
- `scripts/verify-image-contract.sh` — that the deployed image is the one CI builds
