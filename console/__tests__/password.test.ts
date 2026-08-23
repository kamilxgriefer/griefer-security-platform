import { describe, expect, it } from "vitest";

import { generateSalt, hashPassword, verifyPassword } from "@/lib/password";

describe("password hashing", () => {
  it("uses parameters Node will actually accept", async () => {
    // scrypt needs ~128 * N * r bytes, and Node's default maxmem is exactly
    // 32 MiB — the same figure these parameters require. Without an explicit
    // maxmem the derivation throws "memory limit exceeded", every login is
    // rejected, and it looks like a wrong password.
    const salt = generateSalt();
    await expect(hashPassword("any password", salt)).resolves.toHaveLength(128);
  });

  it("accepts the right password and rejects everything else", async () => {
    const salt = generateSalt();
    const hash = await hashPassword("correct horse battery staple", salt);

    expect(await verifyPassword("correct horse battery staple", salt, hash)).toBe(true);
    expect(await verifyPassword("correct horse battery stapl", salt, hash)).toBe(false);
    expect(await verifyPassword("Correct Horse Battery Staple", salt, hash)).toBe(false);
    expect(await verifyPassword("", salt, hash)).toBe(false);
  });

  it("produces a different hash for the same password under a different salt", async () => {
    const password = "the same password";
    const a = await hashPassword(password, generateSalt());
    const b = await hashPassword(password, generateSalt());

    expect(a).not.toBe(b);
    expect(a).toHaveLength(128); // 64 bytes, hex encoded
  });

  it("returns false rather than throwing on a broken configuration", async () => {
    // A console that crashes on a malformed DEMO_PASSWORD_HASH would announce,
    // through its error page, that the configuration is the problem.
    const salt = generateSalt();
    const hash = await hashPassword("password", salt);

    expect(await verifyPassword("password", "", hash)).toBe(false);
    expect(await verifyPassword("password", salt, "")).toBe(false);
    expect(await verifyPassword("password", salt, "not-hex-at-all")).toBe(false);
    expect(await verifyPassword("password", salt, "abcd")).toBe(false); // wrong length
  });

  it("normalises unicode so an equivalent password still works", async () => {
    const salt = generateSalt();
    // Same string, composed vs decomposed.
    const composed = "paßwort-café";
    const decomposed = "paßwort-café";

    const hash = await hashPassword(composed, salt);
    expect(await verifyPassword(decomposed, salt, hash)).toBe(true);
  });
});
