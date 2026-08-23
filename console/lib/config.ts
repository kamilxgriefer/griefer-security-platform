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
  passwordHash: string;
  passwordSalt: string;
  demoUsername: string;
  /** secureCookies is false only on plain-HTTP localhost. */
  secureCookies: boolean;
  appEnv: string;
}

export function consoleConfig(): ConsoleConfig {
  return {
    apiBaseUrl: process.env.GRIEFER_API_BASE_URL ?? "http://127.0.0.1:8080",
    internalApiToken: process.env.INTERNAL_API_TOKEN ?? "",
    sessionSecret: process.env.DEMO_SESSION_SECRET ?? "",
    passwordHash: process.env.DEMO_PASSWORD_HASH ?? "",
    passwordSalt: process.env.DEMO_PASSWORD_SALT ?? "",
    demoUsername: process.env.DEMO_USERNAME ?? "demo-admin",
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
  return (
    config.sessionSecret.length >= 32 &&
    config.passwordHash.length > 0 &&
    config.passwordSalt.length > 0
  );
}
