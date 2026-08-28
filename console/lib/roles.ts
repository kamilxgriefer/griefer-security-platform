/**
 * Roles, and what each one may reach.
 *
 * This module is deliberately free of imports. It is used by the Edge
 * middleware, by Node route handlers and by React components, and anything
 * pulled in here would have to work in all three. Keeping it to plain data and
 * pure functions means there is exactly one description of who may see what,
 * rather than one per runtime that can drift out of agreement.
 */

export const ROLES = ["admin", "analyst"] as const;

export type Role = (typeof ROLES)[number];

/** The role a newly provisioned account gets unless an administrator says otherwise. */
export const DEFAULT_ROLE: Role = "analyst";

export function isRole(value: unknown): value is Role {
  return typeof value === "string" && (ROLES as readonly string[]).includes(value);
}

/** How the role is written in the interface. */
export function roleLabel(role: Role): string {
  return role === "admin" ? "Administrator" : "Analyst";
}

/**
 * Paths reserved for administrators, matched as prefixes.
 *
 * Two things are administrator-only, and both for the same reason: they are the
 * parts of the console that describe the console itself rather than an
 * incident. Account management can grant somebody access, and the audit trail
 * records who did what — including who granted it. An analyst reading incidents
 * needs neither, and an attacker who takes an analyst session should get neither.
 */
const ADMIN_ONLY_PREFIXES = ["/admin", "/audit"] as const;

/**
 * Upstream API paths reserved for administrators.
 *
 * Gating the pages alone would be theatre: the console reaches the platform
 * through /api/griefer/*, so an analyst session could simply request the audit
 * endpoint directly and read the answer as JSON.
 */
const ADMIN_ONLY_API_PREFIXES = ["/api/griefer/audit", "/api/griefer/identity"] as const;

function matches(pathname: string, prefixes: readonly string[]): boolean {
  return prefixes.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`));
}

/**
 * normalise brings a request path to the form the prefixes are written in.
 *
 * This exists because the two halves of the console disagreed about what a path
 * IS. Next.js middleware receives `nextUrl.pathname` exactly as the client sent
 * it, percent-escapes intact, while a route handler receives its catch-all
 * segments already decoded. So `/api/griefer/%61udit` failed the prefix match
 * here — `%61` is not `a` — and then arrived at the gateway as `audit` and was
 * forwarded. Measured against a running console: `/api/griefer/audit` was
 * refused and `/api/griefer/%61udit` was not. `audit%2Fverify` did the same
 * with an encoded separator.
 *
 * Decoding repeats, because one pass leaves `%2561` as `%61` and the match
 * would go on being defeatable by adding a layer. It is bounded because an
 * unbounded loop on attacker input is its own problem.
 *
 * Returns null when the path cannot be decoded. The caller refuses those: a
 * path this function cannot read is not one it can promise anything about, and
 * a malformed path routes nowhere an analyst needs.
 */
function normalise(pathname: string): string | null {
  let path = pathname;
  for (let i = 0; i < 4; i += 1) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(path);
    } catch {
      return null;
    }
    if (decoded === path) break;
    path = decoded;
  }
  if (path.includes("%")) return null;
  // `//audit` and `/audit/` must not spell a path the prefix match misses.
  path = path.replace(/\/+/g, "/");
  if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
  // Lower-cased only for the deny check, which can only ever match MORE paths.
  return path.toLowerCase();
}

/**
 * mayAccess reports whether role is allowed to reach pathname.
 *
 * Note what this is and is not. It is the console's own authorisation, and the
 * GRIEFER API applies its own role gate to the same request — which is what
 * contained the bypass above, because the gateway forwards the session's real
 * role rather than the caller's word for it. A layer whose failure is invisible
 * because another layer holds is still a failed layer.
 */
export function mayAccess(role: Role, pathname: string): boolean {
  if (role === "admin") return true;
  const path = normalise(pathname);
  if (path === null) return false;
  return !matches(path, ADMIN_ONLY_PREFIXES) && !matches(path, ADMIN_ONLY_API_PREFIXES);
}

/** Whether the role may create, disable or re-role accounts. */
export function mayManageAccounts(role: Role): boolean {
  return role === "admin";
}
