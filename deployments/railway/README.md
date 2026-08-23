# Railway deployment images

| Service | Image built from | Public |
|---|---|---|
| `console` | `console/Dockerfile` | **yes** — the only public service |
| `api` | `Dockerfile` (repository root) | no |
| `opa` | `deployments/railway/opa/Dockerfile` | no |
| `nats` | `deployments/railway/nats/Dockerfile` | no |
| `postgres` | Railway's managed PostgreSQL | no |

## Why `api` and `console` are not duplicated here

Their production images already live at `Dockerfile` and `console/Dockerfile`,
and both already do what a platform needs: read `PORT`, bind every interface,
run as a non-root user, and carry no build toolchain.

Copying them into this directory would create two Dockerfiles per service that
must be kept identical by hand. They will not stay identical — one gets a
security fix and the other does not, and the divergence is invisible until the
wrong one is deployed. The platform is pointed at the canonical files instead.

`opa` and `nats` genuinely need their own images: the upstream ones ship no
policy bundle and no authentication, and both of those must come from this
repository rather than from a runtime mount.

## Build context

Both Dockerfiles here expect the **repository root** as their build context,
because they copy policy and configuration from it:

```bash
docker build -f deployments/railway/opa/Dockerfile  -t griefer-opa  .
docker build -f deployments/railway/nats/Dockerfile -t griefer-nats .
```

Set the corresponding service's root directory to `/` and its Dockerfile path
to the file above.
