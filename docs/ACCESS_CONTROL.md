# Access control

Who can sign in to the GRIEFER console, and what each of them may reach.

## Roles

| | Administrator | Analyst |
|---|---|---|
| Dashboard | yes | yes |
| Incidents | yes | yes |
| Audit trail | yes | **no** |
| Accounts | yes | **no** |

Two things are administrator-only, and for the same reason: they describe the
console itself rather than an incident. Account management can grant somebody
access, and the audit trail records who did what — including who granted it. An
analyst reading incidents needs neither, and an attacker holding a stolen
analyst session should get neither.

Everything else is shared. The split is deliberately small: a role model with
many roles and few real differences invites people to hand out the higher one
because the lower one keeps getting in the way.

## Where the decision is made

In `console/middleware.ts`, in front of every route, using the rules in
`console/lib/roles.ts`.

It is enforced in one place rather than per page. A page that forgets its check
is invisible until somebody finds it; a route missing from the table stays
available to everyone, which is the failure that gets noticed. The navigation
hides links the current role cannot use, but that is presentation, not
protection — anyone can type an address.

**The upstream API paths are gated too.** Gating `/audit` while leaving
`/api/griefer/audit` open would be theatre: the console reaches the platform
through that route, so an analyst could read the same data as JSON by opening
the network tab. Both are in the same table.

## Sessions

A session is an HMAC-SHA256 token in an `HttpOnly`, `SameSite=Lax` cookie,
valid for twelve hours. It carries the subject and the role.

The role is **inside the signed payload**, not looked up per request, so a
request cannot be served with a role the login did not grant. The cost is that a
role change takes effect at the holder's next sign-in. For a twelve-hour session
that is the right trade — the alternative is a database round trip on every page
of the console.

A token whose role is missing or unrecognised is rejected outright rather than
defaulted. Defaulting would mean a tampered token, or one signed before roles
existed, quietly acquiring whatever the default happened to be.

## Accounts

Accounts are provisioned with the deployment, from configuration:

```
GRIEFER_ADMIN_USERNAME       GRIEFER_ANALYST_USERNAME
GRIEFER_ADMIN_PASSWORD_SALT  GRIEFER_ANALYST_PASSWORD_SALT
GRIEFER_ADMIN_PASSWORD_HASH  GRIEFER_ANALYST_PASSWORD_HASH
```

`make secrets` generates them. Passwords are written only to
`~/.config/griefer/demo-credentials.txt` with mode 600 — never to stdout, a CI
log, or the repository. What reaches configuration is a salt and an scrypt hash.

The administrator is required; the stack refuses to start without one. The
analyst is optional. An administrator provisioned only from inside the console
would be one forgotten password away from a platform nobody can enter, so
configuration is deliberately the way back in.

**There is no self-service registration.** No route creates an account without
an administrator, and there is no sign-up form anywhere in the console. A
security console that lets an anonymous visitor make themselves an account is
not a security console. The public page at `griefer.app` offers a sign-in link
and no registration for the same reason.

## What is not built yet

Creating accounts from the Accounts page. It needs somewhere durable to keep
them and an audit record of who created whom, and until both exist that page
deliberately shows a list and no form — a form that looked real but saved
nothing would be worse than its absence. Adding an account today means running
`make secrets` and applying the values to the deployment.

Also absent: password change from inside the console, multi-factor
authentication, and account lockout beyond the existing per-address rate limit
on the login route. None of them are simulated or stubbed; they are simply not
there.

## Password storage

scrypt, `N=32768, r=8, p=1`, 64-byte key, with `maxmem` set explicitly to 64 MiB.

The explicit `maxmem` is not optional. scrypt needs roughly `128 * N * r` bytes —
32 MiB at these parameters — and Node's default limit is exactly 32 MiB, so the
derivation fails with "memory limit exceeded" and every login is rejected. The
failure presents as a wrong password, which is the worst way for it to present.

Verification is timing-safe, and the same derivation runs whether or not the
username exists. Skipping the work for an unknown user would turn the login form
into an oracle answering "does this account exist" in a few milliseconds.
