# NATS runtime user — an accepted Trivy exception

**Created:** 2026-08-24 · **Next review:** 2027-02-24

The review date is enforced, not aspirational: the entry in `.trivyignore.yaml`
carries `expired_at: 2027-02-24`. On that date Trivy stops honouring it, the
finding returns, and the Security workflow fails until someone re-reads this
page and either renews the date or changes the image.

A suppressed scanner finding is a claim that the scanner is wrong. This document
is the evidence for that claim, and the instructions for checking whether it is
still true.

## The rule

| Field | Value |
|---|---|
| Rule id | `DS-0002` (long form `AVD-DS-0002`; both work in the ignore file) |
| Title | "Specify at least 1 USER command in Dockerfile with non-root user as argument" |
| Severity | HIGH |
| Scanner | Trivy misconfiguration scan (`trivy config`) |
| Version checked | Trivy **v0.70.0** — the version the pinned `aquasecurity/trivy-action@v0.36.0` installs |
| Reference | <https://avd.aquasec.com/misconfig/ds-0002> |
| Fires on | `deployments/railway/nats/Dockerfile` — the only file in this repository that triggers it |

The rule parses the Dockerfile, looks for a `USER` instruction naming a non-root
user, and reports the image if it finds none. That is all it does. It never
reads the entrypoint, never starts the image, and has no way to observe which
user the process it is worried about actually runs as. It is a check on a
declaration standing in for a check on a process — a reasonable proxy in almost
every image, and wrong in this one.

`docker inspect -f '{{.Config.User}}' <container>` on the built image returns an
empty string, so the rule's reading of the Dockerfile is correct as far as it
goes. The server still does not run as root.

## Why the image starts as root

Because a mounted volume arrives owned by root whatever the image declares, and
the JetStream store lives on that volume.

A fresh volume, inspected before NATS ever touches it:

```
$ docker run --rm -v <volume>:/data alpine:3.22 ls -ldn /data
drwxr-xr-x    2 0        0             4096 /data
```

`nats.conf` sets `store_dir: "/data"`. An image that simply declares
`USER 10001` therefore starts a server that cannot create its own store. This is
not a theory; it was reproduced on 2026-08-24 by building a variant of this
Dockerfile with `USER 10001` and the server as the entrypoint, and running it
against a root-owned volume:

```
[1] [INF] Starting JetStream
[1] [FTL] Can't start JetStream: could not create storage directory -
          mkdir /data/jetstream: permission denied
```

The container exits. The usual response to that failure is to give up and run
the message bus as root — which is precisely the outcome `DS-0002` exists to
prevent. Satisfying the scanner and securing the service point in opposite
directions here, and the scanner is the one that has to give way.

### A local test that will mislead you

Repeating the experiment above with an *empty* Docker named volume will show the
`USER`-only image starting perfectly. That is a Docker convenience, not a
refutation: when a named volume is empty at first mount, Docker seeds it from the
image, ownership included, so `/data` arrives already owned by 10001 because the
Dockerfile chowned it at build time. Platform-provisioned volumes are not seeded
that way. To reproduce the real conditions, write something into the volume as
root first, then mount it.

### Alternatives that were considered and rejected

| Option | Why not |
|---|---|
| Add `USER 10001` and nothing else | The failure above. Green scanner, dead service. |
| Run the server as root | Exactly what the rule is protecting against, on the component that carries every security event GRIEFER has seen. |
| `chown` at build time only | Already done, and it does not survive a mount: the volume's ownership wins over the image's. |
| Drop to the user with `su`, `sudo`, or a supervisor | Leaves a wrapper as PID 1. See below. |
| Have the platform pre-own the volume | The clean answer where an orchestrator offers it (Kubernetes `fsGroup` is the obvious example). Nothing in this deployment does it today; if that changes, this exception should be deleted rather than renewed. |

## What actually runs

`deployments/railway/nats/entrypoint.sh`, in the root branch:

```sh
mkdir -p "$STORE_DIR"
chown -R "${RUN_UID}:${RUN_GID}" "$STORE_DIR"
exec su-exec "${RUN_UID}:${RUN_GID}" /usr/local/bin/nats-server --config /etc/nats/nats.conf "$@"
```

Two properties matter, and both are load-bearing.

**The privileged phase is short and does nothing network-facing.** It creates a
directory and changes its ownership. It has not opened a socket, parsed a
message, or read a credential. The server binary is only reached through the
`exec` line, by which point the process is uid 10001.

**`exec` replaces the process rather than forking it.** `su-exec` overlays
itself with `nats-server`, so the server *is* PID 1. Nothing sits between the
container runtime and the server: `SIGTERM` from the platform reaches the server
directly, its exit status is the container's exit status, and there is no
wrapper that might exit first, swallow a signal, or leave orphaned children
behind. Had this used `su`, `sudo`, or a supervisor, PID 1 would be that helper,
and a signal it forwarded badly would turn every restart into a ten-second kill
after a shutdown timeout.

Both were confirmed on a container built from this Dockerfile on 2026-08-24:

```
$ docker exec <container> ps -o pid,user,comm
PID   USER     COMMAND
    1 griefer  nats-server

$ docker top <container>
UID     PID       CMD
10001   1164270   /usr/local/bin/nats-server --config /etc/nats/nats.conf

$ docker exec <container> id griefer      # the account, not the running process
uid=10001(griefer) gid=10001(griefer) groups=10001(griefer)

$ docker exec <container> ls -ldn /data
drwxr-xr-x    3 10001    10001         4096 /data     # was 0:0 before start
```

`docker stop` produced `Initiating Shutdown...` through `Server Exiting..` and
exit code `0` in about a third of a second — the signal was handled, not waited
out.

## How to verify — and the check that lies

```
docker exec griefer-nats-1 ps -o pid,user,comm
```

(`griefer-nats-1` is the Compose container; substitute the name the platform
gives the container elsewhere.)

PID 1 must be `nats-server` running as `griefer`. Anything else — a different
PID 1, or `root` in that row — means the exception no longer holds and the
finding is real again. Run against the local Compose stack on 2026-08-24, on a
container that had been up for twenty-four hours:

```
PID   USER     COMMAND
    1 griefer  nats-server
```

**Do not check this with `docker exec <container> id`.** On the same container,
at the same moment, with the server running unprivileged as PID 1, that command
answers:

```
uid=0(root) gid=0(root) groups=0(root),...
```

It is not lying about anything except the question you meant to ask. `docker
exec` starts a *new* process, and a new process runs as the image's default user
— which is root here, because the image declares no `USER`, which is why
`DS-0002` fires in the first place. The command reports the identity of the shell
you just started, never the identity of the server that has been running since
the container booted. It is convincing, it is fast to type, and it will tell you
the drop never happened. The same trap catches `docker exec <container> whoami`
and anything else that inspects the current process.

`docker top <container>` is the other honest check: it reads the host's process
table, so `exec` semantics cannot colour the answer.

## What the suppression covers

`.trivyignore.yaml` scopes the exception to the single path it applies to:

```yaml
misconfigurations:
  - id: DS-0002
    paths:
      - "deployments/railway/nats/Dockerfile"
```

Three properties of that file, each verified against Trivy v0.70.0 rather than
assumed:

- **YAML is required.** The plain-text `.trivyignore` format reads every line as
  a bare rule id. `DS-0002:deployments/railway/nats/Dockerfile` matches nothing
  and suppresses nothing; a bare `DS-0002` suppresses the rule for *every*
  Dockerfile in the repository, which is what this change replaced.
- **The `.yaml` extension is load-bearing.** Trivy chooses its parser from the
  filename. The same YAML in a file named `.trivyignore` is read as an id list,
  matches nothing, and silently suppresses nothing.
- **Trivy will not find the file on its own.** `--ignorefile` still defaults to
  `.trivyignore`, so a local run needs the flag; CI passes it through the
  action's `trivyignores` input. Forgetting it surfaces the accepted finding
  rather than hiding a real one, which is the right way for that mistake to
  fail.

To reproduce the scan CI runs:

```
trivy config . --severity CRITICAL,HIGH --ignorefile .trivyignore.yaml
```

## What would make this a real finding again

Any one of these, and the suppression should be deleted rather than argued with:

1. **`entrypoint.sh` stops calling `su-exec`,** or calls it without `exec`. The
   first runs the server as root; the second leaves a wrapper as PID 1 and
   breaks signal delivery.
2. **The uid becomes 0** — `RUN_UID` changed, or the `adduser`/`addgroup` lines
   dropped from the Dockerfile so that `su-exec` has no account to drop to.
3. **`ENTRYPOINT` no longer points at the script,** or the deployment overrides
   the container's command. A platform-level start command that invokes
   `nats-server` directly bypasses the drop entirely, and the Dockerfile in this
   repository will still look correct while it happens.
4. **`su-exec` is no longer installed.** The script runs under `set -eu`, so
   this fails closed rather than silently continuing as root — but it is still a
   broken image and the exception no longer describes it.
5. **The store directory and the config disagree.** The script chowns
   `${GRIEFER_NATS_STORE_DIR:-/data}` while `nats.conf` hard-codes
   `store_dir: "/data"`. Setting that variable without changing the config
   chowns a directory NATS will not use, and the server fails as uid 10001 for
   the original reason. This is a fragility rather than a security hole, but it
   is the most likely way to end up back at "just run it as root".
6. **The running container stops matching this Dockerfile.** The Railway
   services are not connected to GitHub — they were deployed by uploading a
   directory, so the platform records no commit for a deployment. Nothing in
   this repository is proof of what is running. That is exactly why the check
   above is a runtime check.
7. **The expiry passes** without anyone re-establishing the above.

## Limits of this document

- Everything above was verified on 2026-08-24 against an image built locally
  from `deployments/railway/nats/Dockerfile` (`nats:2.12-alpine`, Docker 29.5.2)
  and against the running Compose container. **The Railway deployment was not
  inspected.** Given point 6, running `ps -o pid,user,comm` against the deployed
  NATS container is worth doing and has not been done here.
- The exception is about the runtime user and nothing else. It says nothing
  about NATS authentication, which `nats.conf` requires and which draws its
  credentials from the environment, nor about exposure, which is handled by the
  service having no public domain and no TCP proxy.
- The privileged phase does perform a recursive `chown` over whatever the volume
  already contains. Tested with a symlink planted in the volume pointing at
  `/etc`: busybox `chown -R` retargeted the symlink itself and did **not**
  follow it, leaving `/etc` and `/etc/passwd` root-owned. The privileged write
  is bounded by the mount, which is the residual risk being accepted — small,
  but real, and it is the price of the store being writable at all.
