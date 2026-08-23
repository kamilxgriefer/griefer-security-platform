import "server-only";

/**
 * Server-side configuration for the console.
 *
 * Nothing here is prefixed NEXT_PUBLIC_, so none of it can reach the browser
 * bundle. The private API address in particular must never be inlined into
 * client JavaScript: it is the one piece of information that turns a locked
 * console into a map of the internal network.
 */

export interface ConsoleConfig {
  apiBaseUrl: string;
  internalApiToken: string;
  sessionSecret: string;
  adminUsername: string;
  adminPasswordSalt: string;
  adminPasswordHash: string;
  analystUsername: string;
  analystPasswordSalt: string;
  analystPasswordHash: string;
  /** secureCookies is false only on plain-HTTP localhost. */
  secureCookies: boolean;
  appEnv: string;
}

export function consoleConfig(): ConsoleConfig {
  return {
    apiBaseUrl: process.env.GRIEFER_API_BASE_URL ?? "http://127.0.0.1:8080",
    internalApiToken: process.env.INTERNAL_API_TOKEN ?? "",
    sessionSecret: process.env.DEMO_SESSION_SECRET ?? "",
    adminUsername: process.env.GRIEFER_ADMIN_USERNAME ?? "admin",
    adminPasswordSalt: process.env.GRIEFER_ADMIN_PASSWORD_SALT ?? "",
    adminPasswordHash: process.env.GRIEFER_ADMIN_PASSWORD_HASH ?? "",
    analystUsername: process.env.GRIEFER_ANALYST_USERNAME ?? "analyst",
    analystPasswordSalt: process.env.GRIEFER_ANALYST_PASSWORD_SALT ?? "",
    analystPasswordHash: process.env.GRIEFER_ANALYST_PASSWORD_HASH ?? "",
    // Cookies are Secure everywhere except plain-HTTP local development, where
    // a browser silently drops a Secure cookie and login appears to fail for no
    // visible reason.
    secureCookies: process.env.NODE_ENV === "production",
    appEnv: process.env.APP_ENV ?? "local",
  };
}

/**
 * authConfigured reports whether the access gate can actually work.
 *
 * When false the console refuses every request rather than serving incident
 * data. A misconfigured gate that fails open is worse than no gate, because it
 * looks protected.
 */
export function authConfigured(config: ConsoleConfig = consoleConfig()): boolean {
  if (config.sessionSecret.length < 32) return false;
  // At least one account must be usable, and it must be the administrator.
  // A deployment with only an analyst configured has nobody who can provision
  // the rest, which is a locked door with the key inside.
  const adminUsable =
    config.adminUsername.length > 0 &&
    config.adminPasswordSalt.length > 0 &&
    config.adminPasswordHash.length > 0;
  return adminUsable;
}
