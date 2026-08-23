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

/** mayAccess reports whether role is allowed to reach pathname. */
export function mayAccess(role: Role, pathname: string): boolean {
  if (role === "admin") return true;
  return !matches(pathname, ADMIN_ONLY_PREFIXES) && !matches(pathname, ADMIN_ONLY_API_PREFIXES);
}

/** Whether the role may create, disable or re-role accounts. */
export function mayManageAccounts(role: Role): boolean {
  return role === "admin";
}
