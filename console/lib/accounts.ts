import "server-only";

import { consoleConfig, type ConsoleConfig } from "./config";
import { verifyPassword } from "./password";
import { isRole, type Role } from "./roles";

/**
 * The console's accounts.
 *
 * Two accounts are provisioned from configuration: an administrator and an
 * analyst. They are the accounts the deployment starts with, and the
 * administrator is deliberately among them — an account store that can only be
 * populated from inside the console is one lost password away from a platform
 * nobody can get into. Configuration is the way back in.
 *
 * There is no self-service registration anywhere in this console, and no route
 * that creates an account without an administrator session. A security console
 * that lets an anonymous visitor make themselves an account is not a security
 * console.
 *
 * Passwords are never stored here in any form a reader could use. What
 * configuration carries is a salt and an scrypt hash; the password itself
 * exists only in the operator's credential file, written once at generation.
 */

export interface Account {
  username: string;
  role: Role;
  saltHex: string;
  hashHex: string;
}

/** A successful authentication. Carries no secret material. */
export interface Identity {
  username: string;
  role: Role;
}

function account(
  username: string,
  role: Role,
  saltHex: string,
  hashHex: string,
): Account | null {
  // An account missing either half of its credential is not a half-configured
  // account, it is an unusable one. Returning it would let it be matched by
  // username and then fail verification, which reads as a wrong password and
  // sends whoever is debugging it looking in the wrong place.
  if (!username || !saltHex || !hashHex) return null;
  return { username, role, saltHex, hashHex };
}

/** configuredAccounts returns the accounts this deployment was provisioned with. */
export function configuredAccounts(config: ConsoleConfig = consoleConfig()): Account[] {
  const accounts = [
    account(config.adminUsername, "admin", config.adminPasswordSalt, config.adminPasswordHash),
    account(
      config.analystUsername,
      "analyst",
      config.analystPasswordSalt,
      config.analystPasswordHash,
    ),
  ].filter((entry): entry is Account => entry !== null);

  // Two accounts sharing a name would make which one you get depend on the
  // order of this array, and the answer would be whichever is listed first —
  // the administrator. Treat it as a configuration error and keep neither.
  const seen = new Set<string>();
  const duplicated = new Set<string>();
  for (const entry of accounts) {
    const key = entry.username.toLowerCase();
    if (seen.has(key)) duplicated.add(key);
    seen.add(key);
  }
  if (duplicated.size > 0) {
    console.error(
      `account configuration rejected: ${[...duplicated].join(", ")} is configured more than once`,
    );
    return [];
  }

  return accounts;
}

/**
 * authenticate resolves a username and password to an identity, or null.
 *
 * An scrypt derivation is performed whether or not the username matched, so the
 * response takes the same time either way. Skipping the work for an unknown
 * user turns the login form into an oracle that answers, in a few milliseconds,
 * "does this account exist" — which is exactly the question an attacker wants
 * answered before they start guessing passwords.
 */
export async function authenticate(
  username: string,
  password: string,
  config: ConsoleConfig = consoleConfig(),
): Promise<Identity | null> {
  const accounts = configuredAccounts(config);
  const submitted = username.trim().toLowerCase();

  const match = accounts.find((entry) => entry.username.toLowerCase() === submitted) ?? null;

  // With no match, verify against the first configured account's parameters so
  // the same amount of work happens. The comparison cannot succeed: the
  // password is checked against a hash belonging to a different account, and
  // the result is discarded regardless.
  const target = match ?? accounts[0];
  if (!target) {
    return null;
  }

  const ok = await verifyPassword(password, target.saltHex, target.hashHex);
  if (!match || !ok) return null;

  return { username: match.username, role: match.role };
}

/** accountsConfigured reports whether any account can sign in at all. */
export function accountsConfigured(config: ConsoleConfig = consoleConfig()): boolean {
  return configuredAccounts(config).length > 0;
}

/** adminConfigured reports whether an administrator can sign in. */
export function adminConfigured(config: ConsoleConfig = consoleConfig()): boolean {
  return configuredAccounts(config).some((entry) => entry.role === "admin");
}

export { isRole };
