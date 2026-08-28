import { beforeEach, describe, expect, it } from "vitest";

import {
  accountKey,
  blockedFor,
  recordAccountFailure,
  recordFailure,
  recordSuccess,
  resetAll,
} from "@/lib/ratelimit";

describe("login throttling", () => {
  beforeEach(() => resetAll());

  it("blocks a caller that keeps failing from one address", () => {
    for (let i = 0; i < 8; i += 1) recordFailure("198.51.100.7");
    expect(blockedFor("198.51.100.7")).toBeGreaterThan(0);
  });

  // The caller key comes from X-Forwarded-For, which the caller supplies. An
  // attacker changing it on every request gets a fresh budget every time, so
  // the per-caller limit bounds honest abuse and stops nothing else.
  it("does not stop a caller who rotates the address it claims", () => {
    for (let i = 0; i < 500; i += 1) recordFailure(`10.0.0.${i % 250}`);
    expect(blockedFor("10.0.0.251")).toBe(0);
  });

  // The axis that holds: whoever is guessing the administrator's password has
  // to keep guessing against the administrator.
  it("blocks the account under attack however the caller spells its address", () => {
    const admin = accountKey("admin");
    for (let i = 0; i < 25; i += 1) {
      recordFailure(`10.0.0.${i}`);
      recordAccountFailure(admin);
    }
    expect(blockedFor(admin)).toBeGreaterThan(0);
    // And an untouched account is unaffected: the block is on the target, not
    // on logging in.
    expect(blockedFor(accountKey("analyst"))).toBe(0);
  });

  it("treats a username as one account however it is written", () => {
    expect(accountKey("Admin")).toBe(accountKey("  admin "));
    expect(accountKey("admin")).not.toBe(accountKey("analyst"));
    // Namespaced, so an account can never collide with a caller address.
    expect(accountKey("10.0.0.1")).not.toBe("10.0.0.1");
  });

  it("clears an account's budget once it signs in", () => {
    const admin = accountKey("admin");
    for (let i = 0; i < 25; i += 1) recordAccountFailure(admin);
    expect(blockedFor(admin)).toBeGreaterThan(0);
    recordSuccess(admin);
    expect(blockedFor(admin)).toBe(0);
  });
});
