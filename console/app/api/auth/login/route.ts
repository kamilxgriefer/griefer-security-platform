import { cookies } from "next/headers";

import { authConfigured, consoleConfig } from "@/lib/config";
import { verifyPassword } from "@/lib/password";
import { blockedFor, recordFailure, recordSuccess } from "@/lib/ratelimit";
import { clientKey, isSameOrigin } from "@/lib/request";
import { SESSION_COOKIE, cookieOptions, sign } from "@/lib/session";

// scrypt is Node-only, so this route cannot run on the Edge runtime.
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * A single neutral message for every failure.
 *
 * The response never distinguishes an unknown username from a wrong password,
 * a malformed body from a missing field, or an unconfigured gate from a
 * rejected credential. Anything that tells an attacker which half they got
 * right halves the work.
 */
const REJECTED = "Invalid credentials.";

export async function POST(request: Request): Promise<Response> {
  if (!isSameOrigin(request)) {
    return Response.json({ error: REJECTED }, { status: 403 });
  }

  const config = consoleConfig();
  const key = clientKey(request);

  const blocked = blockedFor(key);
  if (blocked > 0) {
    return Response.json(
      { error: "Too many attempts. Try again later." },
      { status: 429, headers: { "Retry-After": String(blocked) } },
    );
  }

  if (!authConfigured(config)) {
    // Deliberately indistinguishable from a wrong password on the wire; the
    // detail goes to the server log, where an operator will look.
    console.error("login attempted while the access gate is not configured");
    recordFailure(key);
    return Response.json({ error: REJECTED }, { status: 401 });
  }

  let username = "";
  let password = "";
  try {
    const body = (await request.json()) as { username?: unknown; password?: unknown };
    if (typeof body.username === "string") username = body.username;
    if (typeof body.password === "string") password = body.password;
  } catch {
    recordFailure(key);
    return Response.json({ error: REJECTED }, { status: 401 });
  }

  // A bounded password length keeps an attacker from turning scrypt into a
  // denial-of-service primitive against this process.
  if (password.length === 0 || password.length > 512) {
    recordFailure(key);
    return Response.json({ error: REJECTED }, { status: 401 });
  }

  const usernameMatches = username.trim() === config.demoUsername;
  // The password is verified even when the username is wrong, so that a valid
  // username cannot be identified by how long the response takes.
  const passwordMatches = await verifyPassword(password, config.passwordSalt, config.passwordHash);

  if (!usernameMatches || !passwordMatches) {
    recordFailure(key);
    return Response.json({ error: REJECTED }, { status: 401 });
  }

  recordSuccess(key);
  const token = await sign(config.demoUsername, config.sessionSecret);
  (await cookies()).set(SESSION_COOKIE, token, cookieOptions(config.secureCookies));

  return Response.json({ ok: true });
}
