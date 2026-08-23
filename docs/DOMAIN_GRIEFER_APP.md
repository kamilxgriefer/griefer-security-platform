# griefer.app

## What is published there

A single static page: the mark, the name, its expansion, the tagline, and a
plain statement that the platform is in early development and not publicly
reachable.

Nothing else. No login form, no dashboard, no statistics, no contact form, no
analytics, no third-party script of any kind. It has no JavaScript at all and
sets no cookies. It is served from `site/public/` exactly as committed.

The page carries `noindex, nofollow` while the project is in early development.

## What is NOT published there

| | Public |
|---|---|
| `griefer.app` — the static page | **yes** |
| GRIEFER API | no |
| PostgreSQL | no |
| NATS | no |
| OPA | no |
| The authenticated console | no |

The full stack runs locally under Docker Compose and nowhere else. The static
page depends on none of it and would keep working if every one of those
services were deleted.

`console.griefer.app` is reserved in this document for the authenticated
console. It has not been created, and no DNS record for it exists.

## DNS

**Operator: Cloudflare.** Nameservers `louis.ns.cloudflare.com` and
`heidi.ns.cloudflare.com`.

The zone was empty before this work — no A, AAAA, CNAME, MX, TXT or CAA record
of any kind. The state was captured to `~/.config/griefer/dns-before-deployment.txt`
(mode 600, outside the repository) before anything was changed.

Because there are no mail records, adding web records cannot affect mail
delivery. Nothing was deleted, and no MX, SPF, DKIM or DMARC record was touched.

### Records required

GitHub Pages serves the apex from four anycast addresses. Add these in the
Cloudflare dashboard as **DNS only** — the grey cloud, not the orange one.

| Type | Name | Value |
|---|---|---|
| A | `@` | `185.199.108.153` |
| A | `@` | `185.199.109.153` |
| A | `@` | `185.199.110.153` |
| A | `@` | `185.199.111.153` |
| AAAA | `@` | `2606:50c0:8000::153` |
| AAAA | `@` | `2606:50c0:8001::153` |
| AAAA | `@` | `2606:50c0:8002::153` |
| AAAA | `@` | `2606:50c0:8003::153` |
| CNAME | `www` | `kamilxgriefer.github.io` |

**Why DNS only.** With Cloudflare proxying enabled, Cloudflare terminates TLS
and GitHub sees only Cloudflare. GitHub then cannot complete the ACME challenge
it uses to issue the certificate for the apex, and the site serves either a
Cloudflare-branded certificate or an error. Proxying can be turned on later,
once the GitHub certificate exists and Full (strict) SSL is configured.

`.app` is on the HSTS preload list, so browsers refuse plain HTTP for it
outright. The certificate has to be right; there is no working-over-HTTP state
to fall back to.

## Hosting

**GitHub Pages**, free for public repositories including a custom domain. No
payment method is attached and no paid service was created.

Deployment is `.github/workflows/site.yml`:

1. Verify every brand asset — sizes, alpha channels, maskable safe zones,
   manifest references.
2. Regenerate the assets and fail if the tree changes, which catches the
   committed assets drifting from the vector masters.
3. Check that every asset the page references is actually shipped.
4. Check the page loads no third-party code.
5. Check the published output contains no infrastructure detail or secret name.
6. Deploy — **from `main` only**.

The deploy job authenticates with a short-lived OIDC token. No deployment
credential is stored in the repository or in Actions secrets. A pull request can
run the verification but cannot publish and cannot change DNS.

### Considered and not chosen

**Cloudflare Pages** would also work, and arguably fits better since DNS is
already there — it would wire the domain automatically and avoid the DNS-only
caveat above. It was not chosen because setting it up requires either the
Cloudflare dashboard or an API token, and this work had neither. It remains the
better option if the site outgrows a single static page.

**Railway** was ruled out: it has no free tier, and a static page is not worth
a paid plan.

## Migrating to the full console later

When the authenticated console is deployed, the intended shape is:

```
griefer.app          → this static page (unchanged)
console.griefer.app  → the authenticated console
```

The API, PostgreSQL, NATS and OPA stay private with no public hostname, exactly
as they are now. That is milestone M1; see [ROADMAP.md](ROADMAP.md).

Adding `console.griefer.app` is a new record. It does not touch the apex, so the
public page keeps working throughout.
