# Security policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report privately through GitHub Security Advisories:

**<https://github.com/kamilxgriefer/griefer-security-platform/security/advisories/new>**

If that is unavailable to you, open a public issue containing only the words
"security contact request" and no detail, and a private channel will be arranged.

### What to include

- What the issue is and why it matters
- Steps to reproduce, or a proof of concept
- Affected version or commit
- Any suggested fix

### What to expect

| | |
|---|---|
| Acknowledgement | within 3 working days |
| Initial assessment | within 10 working days |
| Fix or a public statement of a known limitation | as fast as the severity warrants |

This is an unfunded research project maintained in spare time. Those targets are
what will genuinely be attempted, not a contractual commitment. If a deadline
slips you will be told, rather than left waiting.

Credit is given in the advisory unless you prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| `main` | ✅ |
| v0.1.x | ✅ |

There are no releases yet. `main` is the supported version.

## Scope

**In scope**

- The GRIEFER API, correlation engine, Policy Kernel and console
- The Rego policy, and any way to bypass or subvert a decision
- The event schema and the ingest trust boundary
- The audit trail's integrity properties
- Container configuration and the Compose stack
- CI/CD workflows and the supply chain
- Dependencies, where GRIEFER's use of them is the problem

**Out of scope**

- The absence of authentication in v0.1. This is documented, deliberate, and
  tracked as M8. The API refuses to bind a non-loopback interface without an
  explicit override, and warns on every start when overridden.
- Denial of service against the demonstration stack running with default local
  credentials on a laptop.
- Findings that require host or database administrator access — the threat model
  states these assumptions explicitly.
- Missing hardening in the synthetic fixtures.
- Automated scanner output with no demonstrated impact.

If you are unsure whether something is in scope, report it. A report that turns
out to be out of scope costs a short conversation; an unreported one may cost
more.

## Known limitations

These are stated in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and are not
vulnerabilities:

| Limitation | Milestone |
|---|---|
| One shared service credential; no per-caller authentication or revocation | M8 |
| No producer authentication — anyone with network reach can submit events | M4 |
| Audit chain is not externally anchored — a database role can rewrite it consistently | M4 |
| No release signing or build provenance | M8 |
| No detection of a sensor going silent | M4/M5 |
| Security Graph is in memory and lost on restart | M2 |

## What GRIEFER will not accept

This is defensive software. Contributions adding any of the following will be
declined regardless of quality:

- Exploit code, or proof-of-concept code that reproduces a specific CVE
- Credential harvesting or dumping
- Persistence mechanisms
- Detection or logging evasion
- Offensive automation, or anything designed to act against systems the operator
  does not control

The controlled defense-validation capability planned for M6 is explicitly bounded
by [docs/SAFETY_MODEL.md](docs/SAFETY_MODEL.md): safe, reversible, scoped to
registered assets, policy-evaluated, and fully audited.

## Security practices in this repository

| Practice | Where |
|---|---|
| Trust boundary validation with `additionalProperties: false` | `schemas/events/` |
| Control-plane injection guard | `internal/events/guard.go` |
| Fail-closed authorization | `internal/policy/` |
| Append-only audit, enforced by type and by database trigger | `internal/audit/`, `internal/storage/schema.sql` |
| No secrets in code or fixtures, enforced by test and by CI scanning | `internal/demo/demo_test.go`, `.github/workflows/security.yml` |
| Errors that never leak internals to a client | `internal/httpx/response.go` |
| Distroless non-root, read-only, all capabilities dropped | `Dockerfile`, `docker-compose.yml` |
| Minimal GitHub Actions permissions, never `write-all` | `.github/workflows/` |
| npm build scripts opt-out by default | `console/pnpm-workspace.yaml` |
| Dependency, secret, image and SAST scanning | `.github/workflows/security.yml`, `codeql.yml` |
| SBOM per build | `.github/workflows/security.yml` |

The safety contract has an executable specification:

```bash
go test -run TestSafetyContract ./tests/integration/ -v
opa test policies/rego -v
```

## Responsible use

Run GRIEFER only against systems you own or are explicitly authorised to defend.
When it gains real response capability, running it against systems you do not
control could disable other people's access — with the same legal consequences as
any other unauthorised action.
