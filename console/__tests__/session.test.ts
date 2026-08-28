import { describe, expect, it } from "vitest";

import { SESSION_TTL_SECONDS, cookieOptions, sign, verify } from "@/lib/session";

const SECRET = "a-session-secret-long-enough-to-be-real-0123456789";

describe("session tokens", () => {
  it("round-trips a valid session", async () => {
    const token = await sign("demo-admin", "admin", SECRET);
    const payload = await verify(token, SECRET);

    expect(payload).not.toBeNull();
    expect(payload?.sub).toBe("demo-admin");
    expect(payload?.role).toBe("admin");
    expect(payload!.exp - payload!.iat).toBe(SESSION_TTL_SECONDS);
  });

  it("rejects a token signed with a different secret", async () => {
    const token = await sign("demo-admin", "admin", SECRET);
    expect(await verify(token, "a-completely-different-secret-value")).toBeNull();
  });

  it("rejects a tampered payload", async () => {
    const token = await sign("demo-admin", "admin", SECRET);
    const [body, signature] = token.split(".");
    // Re-encode the payload claiming a different subject, keeping the signature.
    const forged = Buffer.from(
      JSON.stringify({ sub: "root", role: "admin", iat: 0, exp: 9_999_999_999 }),
    ).toString("base64url");

    expect(await verify(`${forged}.${signature}`, SECRET)).toBeNull();
    expect(body).not.toBe(forged);
  });

  it("rejects an expired token", async () => {
    const issued = Date.now();
    const token = await sign("demo-admin", "admin", SECRET, issued);

    // One millisecond past expiry.
    const past = issued + SESSION_TTL_SECONDS * 1000 + 1;
    expect(await verify(token, SECRET, past)).toBeNull();
    // Still valid a second before.
    expect(await verify(token, SECRET, issued + 1000)).not.toBeNull();
  });

  it("rejects malformed input without throwing", async () => {
    for (const bad of [undefined, "", ".", "notatoken", "a.b.c", "!!!.???", "onlybody."]) {
      expect(await verify(bad, SECRET)).toBeNull();
    }
  });

  it("rejects everything when no secret is configured", async () => {
    // A gate that cannot verify must refuse, not admit.
    const token = await sign("demo-admin", "admin", SECRET);
    expect(await verify(token, "")).toBeNull();
  });

  it("sets cookie attributes that resist theft and cross-site use", () => {
    const options = cookieOptions(true);
    expect(options.httpOnly).toBe(true);
    expect(options.secure).toBe(true);
    expect(options.sameSite).toBe("lax");
    expect(options.path).toBe("/");
    expect(options.maxAge).toBe(SESSION_TTL_SECONDS);
    // Secure is dropped only for plain-HTTP localhost, where a browser would
    // silently discard the cookie and login would appear to fail.
    expect(cookieOptions(false).secure).toBe(false);
  });

  it("carries the role it was signed with, not a default", async () => {
    const analyst = await verify(await sign("nadia", "analyst", SECRET), SECRET);
    expect(analyst?.role).toBe("analyst");

    const admin = await verify(await sign("nadia", "admin", SECRET), SECRET);
    expect(admin?.role).toBe("admin");
  });

  it("rejects a validly signed token whose role is missing or unknown", async () => {
    // Signed with the real secret, so the signature checks out. This is the
    // shape a token from before roles existed would have, and the shape an
    // attacker would aim for if the role were merely defaulted rather than
    // required.
    const { createHmac } = await import("node:crypto");
    for (const payload of [
      { sub: "nadia", iat: 0, exp: 9_999_999_999 },
      { sub: "nadia", role: "root", iat: 0, exp: 9_999_999_999 },
      { sub: "nadia", role: "", iat: 0, exp: 9_999_999_999 },
      { sub: "nadia", role: 1, iat: 0, exp: 9_999_999_999 },
    ]) {
      const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
      const signature = createHmac("sha256", SECRET).update(body).digest("base64url");
      expect(await verify(`${body}.${signature}`, SECRET)).toBeNull();
    }
  });
});

describe("placeholder secrets", () => {
  // A configuration copied from the published .env.example must not produce a
  // working gate. The length check alone was not enough: the placeholder in
  // that file had been padded past 32 characters, so it passed.
  it("refuses a secret copied from the published example file", async () => {
    const { authConfigured, PLACEHOLDER_SECRET_MARKER } = await import("@/lib/config");
    const base = {
      apiBaseUrl: "http://127.0.0.1:8080",
      internalApiToken: "a-real-token",
      sessionSecret: "x".repeat(64),
      adminUsername: "admin",
      adminPasswordSalt: "salt",
      adminPasswordHash: "hash",
      analystUsername: "analyst",
      analystPasswordSalt: "",
      analystPasswordHash: "",
      secureCookies: false,
      appEnv: "test",
    };
    expect(authConfigured(base)).toBe(true);

    // Long enough to pass the length check, and still published.
    const published = `placeholder-${PLACEHOLDER_SECRET_MARKER}-at-least-32-chars`;
    expect(published.length).toBeGreaterThanOrEqual(32);
    expect(authConfigured({ ...base, sessionSecret: published })).toBe(false);
    expect(authConfigured({ ...base, internalApiToken: published })).toBe(false);
  });
});
