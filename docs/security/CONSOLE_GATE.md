# The console access gate — what it is, and what it is not

The console is the only public entry point to a GRIEFER deployment. Everything
behind it — incidents, the account list, the audit trail — is reachable only
through a signed session cookie issued by `POST /api/auth/login`.

This document exists because two files pointed at `docs/DEMO_SECURITY.md` for
the limits of that gate, and that file was never written. A control whose
caveats live in a missing document is a control nobody can evaluate.

## What holds

**Sessions are signed, not stored.** HMAC-SHA256 over a JSON payload carrying
the subject, the role and an expiry, verified with Web Crypto so the same code
runs in Edge middleware and in Node route handlers. One implementation means the
gate cannot be strict in one place and lenient in the other. The role is inside
the signed payload rather than looked up per request, so a request cannot be
served with a role the login did not grant; the cost is that a role change takes
effect at the holder's next sign-in.

**Every failure looks the same.** A malformed token, a wrong signature and an
expired one all return `null`. A wrong password, an unknown username and an
unconfigured gate all return the same body and status. `authenticate` performs
the same scrypt work whether or not the account exists, so the response time
does not say which usernames are real.

**Authorisation is matched on a normalised path.** Percent-escapes are decoded
repeatedly, duplicate and trailing slashes collapse, and a path that cannot be
decoded is refused rather than guessed at. This is not decoration: middleware
receives the raw path and a route handler receives decoded segments, and before
that normalisation existed `/api/griefer/%61udit` passed a gate that
`/api/griefer/audit` failed. The gateway checks the role a second time on the
resolved target, and the GRIEFER API applies its own on top of both.

**The password never reaches the API.** The console authenticates the person and
then presents its own service credential upstream, with the operator's identity
in a header built from the session — never forwarded from the incoming request,
which would let a browser name itself.

## What does not hold

**Throttling is per-process and in memory.** It does not survive a restart and
does not coordinate across replicas. A deployment running more than one console
instance divides its budget by the instance count, and a restart clears it.

**The caller key is supplied by the caller.** `clientKey` reads the leftmost
`X-Forwarded-For` entry, because the console runs behind a proxy and the socket
address is the proxy. That entry is client-supplied and can be spoofed, so the
per-caller budget bounds honest abuse and stops nothing deliberate. What holds
instead is the per-**account** budget: whoever guesses the administrator's
password has to keep attempting the administrator, and that axis cannot be
rotated away.

**The per-account budget can be used to lock an administrator out.** Twenty-five
deliberate failures against a known username block it for five minutes. That is
accepted, and the numbers are chosen to reflect it: high enough that ordinary
mistyping never reaches it, short enough that a denial costs minutes. An
administrator locked out for five minutes is recoverable and visible; an
administrator password guessed is neither.

**There is no trusted-proxy allowlist.** Until there is, no decision that
matters should rest on the address a request claims.

**There is no second factor, no account recovery and no password rotation.**
Accounts come from configuration. This is a demonstration console, and its
session lifetime — twelve hours — is set for that rather than for a workspace.

**Login is not audited into the GRIEFER trail.** Failures reach the console's
log; they are not entries in `audit_log`, so the tamper-evidence the trail
carries does not extend to them.

## If this is ever more than a demonstration

In rough order of how much each buys:

1. A trusted-proxy allowlist, so the caller key means something.
2. Shared throttling state, so replicas and restarts do not reset it.
3. Per-caller credentials at the API, closing the limit
   [AUDIT_MODEL.md](AUDIT_MODEL.md) records about `RequireRole` admitting a
   request with no actor assertion. → M8
4. A second factor on the administrator account.
5. Login events into the audit trail, so the chain covers who tried to get in.
