import { describe, expect, it } from "vitest";

import { SESSION_TTL_SECONDS, cookieOptions, sign, verify } from "@/lib/session";

const SECRET = "a-session-secret-long-enough-to-be-real-0123456789";

describe("session tokens", () => {
  it("round-trips a valid session", async () => {
    const token = await sign("demo-admin", SECRET);
    const payload = await verify(token, SECRET);

    expect(payload).not.toBeNull();
    expect(payload?.sub).toBe("demo-admin");
    expect(payload!.exp - payload!.iat).toBe(SESSION_TTL_SECONDS);
  });

  it("rejects a token signed with a different secret", async () => {
    const token = await sign("demo-admin", SECRET);
    expect(await verify(token, "a-completely-different-secret-value")).toBeNull();
  });

  it("rejects a tampered payload", async () => {
    const token = await sign("demo-admin", SECRET);
    const [body, signature] = token.split(".");
    // Re-encode the payload claiming a different subject, keeping the signature.
    const forged = Buffer.from(
      JSON.stringify({ sub: "root", iat: 0, exp: 9_999_999_999 }),
    ).toString("base64url");

    expect(await verify(`${forged}.${signature}`, SECRET)).toBeNull();
    expect(body).not.toBe(forged);
  });

  it("rejects an expired token", async () => {
    const issued = Date.now();
    const token = await sign("demo-admin", SECRET, issued);

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
    const token = await sign("demo-admin", SECRET);
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
});
