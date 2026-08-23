import { randomBytes } from "node:crypto";

import { beforeAll, describe, expect, it, vi } from "vitest";

import { accountsConfigured, adminConfigured, authenticate, configuredAccounts } from "@/lib/accounts";
import type { ConsoleConfig } from "@/lib/config";
import { generateSalt, hashPassword } from "@/lib/password";

// Generated per run rather than written out. A literal here would be a
// passphrase-shaped string in the repository, which a secret scanner cannot
// distinguish from a real one — and teaching people to wave scanners past test
// files is how a real credential eventually gets committed.
const ADMIN_PASSWORD = `admin-${randomBytes(12).toString("hex")}`;
const ANALYST_PASSWORD = `analyst-${randomBytes(12).toString("hex")}`;

let adminSalt = "";
let adminHash = "";
let analystSalt = "";
let analystHash = "";

// scrypt is deliberately expensive, so the derivations happen once rather than
// per assertion.
beforeAll(async () => {
  adminSalt = generateSalt();
  adminHash = await hashPassword(ADMIN_PASSWORD, adminSalt);
  analystSalt = generateSalt();
  analystHash = await hashPassword(ANALYST_PASSWORD, analystSalt);
}, 30_000);

function config(overrides: Partial<ConsoleConfig> = {}): ConsoleConfig {
  return {
    apiBaseUrl: "http://127.0.0.1:8080",
    internalApiToken: "token",
    sessionSecret: "a-session-secret-long-enough-to-be-real-0123456789",
    adminUsername: "admin",
    adminPasswordSalt: adminSalt,
    adminPasswordHash: adminHash,
    analystUsername: "analyst",
    analystPasswordSalt: analystSalt,
    analystPasswordHash: analystHash,
    secureCookies: true,
    appEnv: "test",
    ...overrides,
  };
}

describe("configured accounts", () => {
  it("provisions exactly one administrator and one analyst", () => {
    const accounts = configuredAccounts(config());
    expect(accounts.map((a) => [a.username, a.role])).toEqual([
      ["admin", "admin"],
      ["analyst", "analyst"],
    ]);
  });

  it("drops an account whose credential is only half configured", () => {
    // Keeping it would let the username match and then fail verification,
    // which is indistinguishable from a wrong password.
    const accounts = configuredAccounts(config({ analystPasswordHash: "" }));
    expect(accounts.map((a) => a.username)).toEqual(["admin"]);
  });

  it("refuses every account when two share a username", () => {
    const warn = vi.spyOn(console, "error").mockImplementation(() => {});
    // Otherwise which account you get depends on array order, and the answer
    // would be the administrator.
    const accounts = configuredAccounts(config({ analystUsername: "Admin" }));
    expect(accounts).toEqual([]);
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  it("reports whether an administrator can sign in", () => {
    expect(adminConfigured(config())).toBe(true);
    expect(adminConfigured(config({ adminPasswordHash: "" }))).toBe(false);
    // An analyst alone is a locked door with the key inside.
    expect(accountsConfigured(config({ adminPasswordHash: "" }))).toBe(true);
  });
});

describe("authentication", () => {
  it("admits the administrator with the right password", async () => {
    expect(await authenticate("admin", ADMIN_PASSWORD, config())).toEqual({
      username: "admin",
      role: "admin",
    });
  });

  it("admits the analyst with the right password, as an analyst", async () => {
    const identity = await authenticate("analyst", ANALYST_PASSWORD, config());
    expect(identity).toEqual({ username: "analyst", role: "analyst" });
  });

  it("does not admit one account with the other's password", async () => {
    // The obvious way to get this wrong is to verify the submitted password
    // against every configured hash and accept any match.
    expect(await authenticate("analyst", ADMIN_PASSWORD, config())).toBeNull();
    expect(await authenticate("admin", ANALYST_PASSWORD, config())).toBeNull();
  });

  it("rejects a wrong password", async () => {
    expect(await authenticate("admin", "not-the-password", config())).toBeNull();
  });

  it("rejects an unknown username", async () => {
    expect(await authenticate("nobody", ADMIN_PASSWORD, config())).toBeNull();
  });

  it("matches the username case-insensitively and ignores surrounding space", async () => {
    for (const submitted of ["ADMIN", "Admin", "  admin  "]) {
      expect(await authenticate(submitted, ADMIN_PASSWORD, config())).toEqual({
        username: "admin",
        role: "admin",
      });
    }
  });

  it("returns the configured spelling of the username, not what was typed", async () => {
    // The session subject ends up in the audit trail, so it should be the
    // account's name rather than whatever capitalisation someone used.
    const identity = await authenticate("ADMIN", ADMIN_PASSWORD, config());
    expect(identity?.username).toBe("admin");
  });

  it("rejects an empty password without throwing", async () => {
    expect(await authenticate("admin", "", config())).toBeNull();
  });

  it("refuses everything when no account is configured", async () => {
    const empty = config({
      adminPasswordHash: "",
      adminPasswordSalt: "",
      analystPasswordHash: "",
      analystPasswordSalt: "",
    });
    expect(await authenticate("admin", ADMIN_PASSWORD, empty)).toBeNull();
    expect(accountsConfigured(empty)).toBe(false);
  });
});
