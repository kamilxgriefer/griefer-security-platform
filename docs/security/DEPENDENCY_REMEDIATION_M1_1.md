# Dependency remediation — M1.1

Both open Dependabot alerts on `main` were the **same advisory**, reported twice
because it matched two manifests in the same project.

## The advisory

| Field | Value |
|---|---|
| Advisory | `GHSA-f88m-g3jw-g9cj` |
| CVEs | CVE-2026-33327, CVE-2026-33328, CVE-2026-35590, CVE-2026-35591 |
| Severity | High |
| Ecosystem | npm |
| Package | `sharp` |
| Nature | `sharp` inherits vulnerabilities from the libvips it bundles |
| Vulnerable range | `< 0.35.0` |
| First patched version | `0.35.0` |
| Dependabot alerts | `#2` (`package.json`), `#3` (`pnpm-lock.yaml`) — one advisory, two manifests |

## Where the vulnerable version actually was

| Question | Answer |
|---|---|
| Direct or transitive | **Direct** — declared in the repository-root `package.json` |
| Scope | **development** |
| Dependency path | root `package.json` → `sharp@0.34.5` |
| What uses it | `scripts/generate-brand-assets.mjs`, `scripts/build-brand-svg.mjs`, `scripts/verify-brand-assets.mjs` — the brand-asset pipeline |
| In a deployed runtime image | **No.** The root `package.json` is never installed into an image. `console/Dockerfile` builds from the `console/` context and installs `console/package.json`. |
| Reachable from the internet | **No.** The pipeline runs on a developer machine or in CI, never in a running service. |
| Input it processes | One committed PNG (`branding/source/…`) plus SVGs this repository generates. No user-supplied or network-fetched image ever reaches it. |

### The console does ship sharp — at a patched version

This is worth stating plainly, because "development scope" would otherwise read
as "not in the product at all", and that is not true.

Next.js 16.3.2 depends on `sharp` for image optimisation, so the console's
runtime image does contain it. Verified inside the built image:

```
/app/node_modules/.pnpm/sharp@0.35.3_@types+node@24.10.1
```

`0.35.3` is above the `0.35.0` fix, so the copy that ships was never vulnerable.
The alert was raised solely against the root toolchain.

## Remediation

`sharp` at the repository root moved `0.34.5` → **`0.35.0`**: the lowest version
carrying the fix, per the rule of preferring the minimal patched release. No
other dependency was touched and no lockfile was regenerated wholesale.

`0.35.0` is not itself subject to any advisory — the only other high-severity
`sharp` advisories, `GHSA-54xq-cgqr-rpm3` and `GHSA-gp95-ppv5-3jc5`, are fixed
in `0.32.6` and `0.30.5` respectively.

The console keeps resolving `0.35.3` transitively. That is not a conflict: the
two projects have separate lockfiles and separate `node_modules`, and both are
above the fix.

## The consequence that needed handling

`sharp 0.35.0` bundles **libvips 8.18.3**; `0.34.5` bundled **8.17.3**. The
encoder changed, so 34 of the 109 committed brand assets came out with different
bytes — while remaining visually identical and passing all 88 asset checks.

This matters because CI regenerates the assets and fails if the tree changes.
The regenerated assets are therefore committed alongside the bump; shipping the
version bump without them would have turned a dependency fix into a red build.

Reproducibility was re-established under the new libvips rather than assumed:

```
macOS (arm64, sharp 0.35.0, libvips 8.18.3)      109 files hashed
linux/amd64 (same versions, CI's architecture)   all 109 identical
```

## Status

| Item | State |
|---|---|
| Alert #2 (`package.json`) | Fixed by upgrade |
| Alert #3 (`pnpm-lock.yaml`) | Fixed by upgrade |
| Suppressions or ignores added | **None** |
| Dependencies removed as unused | None — `sharp` is genuinely used |
| Unfixable findings | None |

Dependabot re-scans `main` after the merge; the alerts close on that scan rather
than on this document.

## Dependabot pull requests left open

Dependabot had also opened routine dev-dependency bumps unrelated to this
advisory (`@types/node`, `@types/react`, `typescript` 6.x, `pnpm/action-setup`
6.x). They are out of scope for M1.1 and are deliberately not merged here: a
TypeScript major and an Actions major both deserve their own change with their
own test run, rather than riding along with a security fix.

The `sharp` bump PR that Dependabot raised is superseded by this branch, which
also carries the regenerated assets it would have left broken.
