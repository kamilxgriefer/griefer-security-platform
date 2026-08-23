# Progressive web app

## What works today

Both the console and the public site ship a complete web app manifest and the
full icon set, so a browser can install either one.

| | Console | griefer.app |
|---|---|---|
| Manifest | ✅ | ✅ |
| Icons, including maskable | ✅ | ✅ |
| Apple touch icon | ✅ | ✅ |
| Theme and background colour | ✅ | ✅ |
| Served over HTTPS | in deployment | ✅ |
| Service worker | ❌ | ❌ |
| Offline support | ❌ | ❌ |

**There is no service worker.** Chrome will therefore not show its install
prompt for the console; it requires one. Safari on iOS and iPadOS will still
add either to the home screen via *Share → Add to Home Screen*, and Edge and
Chrome on desktop will install from the address bar, because neither of those
paths requires a worker.

Calling this a working PWA would be overstating it. It is installable in the
senses listed above and not in the others.

## Why there is no service worker yet

A service worker is a cache that sits in front of every request the application
makes. On an application that shows security data behind an access gate, that
is a serious thing to add casually.

The rules it would have to hold:

**May be cached** — the mark and icons, the stylesheet, the static JavaScript
bundles, a public offline page.

**Must never be cached**

- `/api/*` — every response carries incident or audit data
- `/login`, `/logout`, `/api/auth/*` — caching an authentication response is how
  one visitor ends up holding another's session
- Any page behind the gate: the dashboard, incidents, the audit trail
- Any response carrying `Set-Cookie`
- Any response the server marked `Cache-Control: no-store`

Getting that wrong caches an incident page and serves it to whoever opens the
app next, including after sign-out. Adding a worker that is 90 % correct is
worse than having none, because the failure is invisible until it matters.

This is a deliberate next step rather than an oversight, and it is not on the
critical path for anything: the console is not publicly deployed, and the
public site is a single static page that has nothing to cache.

## Current cache policy

The console already sends `Cache-Control: no-store, private` on every response,
which is the behaviour a future worker would have to preserve rather than
discover.

The static site is immutable and public; it may be cached normally by the CDN
in front of it.

## What a future service worker must do

1. Cache only an explicit allowlist of static assets, by URL, never by pattern.
2. Never place a response with `Set-Cookie` into a cache.
3. Never place a response with `Cache-Control: no-store` into a cache.
4. Never intercept `/api/*` or the authentication routes at all — not "cache
   them carefully", not intercept them.
5. Clear every cache on sign-out.
6. Version the cache so a deploy cannot leave a stale bundle serving against a
   new API.
7. Ship with a test that a page behind the gate is still unreachable after
   sign-out with the worker active.

Point 7 is the one that makes the rest verifiable.
