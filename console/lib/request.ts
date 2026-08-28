import "server-only";

/**
 * clientKey identifies a caller for rate limiting.
 *
 * X-Forwarded-For is read here — unlike in the Go API — because the console
 * always runs behind the platform's proxy, where the socket address is the
 * proxy and the header is the only signal available. The leftmost entry is a
 * client-supplied value and can be spoofed, so a caller rotating the header
 * gets a fresh budget on every request and this bounds honest abuse only. The
 * axis that actually holds against password guessing is the per-account one in
 * lib/ratelimit.ts, because the username being attempted is not the attacker's
 * to rotate. Production authentication still needs a trusted-proxy allowlist;
 * see docs/security/CONSOLE_GATE.md.
 */
export function clientKey(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) return first.slice(0, 64);
  }
  return request.headers.get("x-real-ip")?.slice(0, 64) ?? "unknown";
}

/**
 * isSameOrigin reports whether a state-changing request came from this app.
 *
 * Checked on every POST. Combined with a SameSite=Lax session cookie this is
 * the CSRF defence: a cross-site form post arrives with a foreign Origin, and
 * a cross-site fetch cannot set Origin at all.
 */
export function isSameOrigin(request: Request): boolean {
  const site = request.headers.get("sec-fetch-site");
  if (site) {
    // Browsers that send Fetch Metadata give a definitive answer.
    return site === "same-origin" || site === "none";
  }

  const origin = request.headers.get("origin");
  if (!origin) {
    // No Origin and no Fetch Metadata: refuse rather than assume. Every browser
    // this console supports sends at least one of them on a POST.
    return false;
  }
  const host = request.headers.get("host");
  if (!host) return false;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}
