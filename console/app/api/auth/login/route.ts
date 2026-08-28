import { cookies } from "next/headers";

import { authenticate } from "@/lib/accounts";
import { authConfigured, consoleConfig } from "@/lib/config";
import {
  accountKey,
  blockedFor,
  recordAccountFailure,
  recordFailure,
  recordSuccess,
} from "@/lib/ratelimit";
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

  // The second budget, and the one that cannot be rotated away.
  //
  // `key` comes from X-Forwarded-For, which the caller supplies: an attacker
  // changing that header on every request gets a fresh caller budget every
  // time, so the limit above bounds honest abuse and nothing else. Whoever is
  // guessing the administrator's password has to keep guessing against the
  // administrator, so the username is the axis that holds.
  //
  // Checked after the body is read, because the username is in the body, and
  // deliberately BEFORE authenticate() — that is where the scrypt work is, and
  // an attacker who can reach it freely has a CPU cost as well as an unlimited
  // guess count.
  const account = accountKey(username);
  const accountBlocked = blockedFor(account);
  if (accountBlocked > 0) {
    return Response.json(
      { error: "Too many attempts. Try again later." },
      { status: 429, headers: { "Retry-After": String(accountBlocked) } },
    );
  }

  // authenticate performs the same scrypt work whether or not the username
  // exists, so the response time does not reveal which accounts are real.
  const identity = await authenticate(username, password, config);

  if (!identity) {
    recordFailure(key);
    // Counted whether or not the account exists, for the same reason the scrypt
    // work is done either way: a budget that only moved for real usernames
    // would say which ones those are.
    recordAccountFailure(account);
    return Response.json({ error: REJECTED }, { status: 401 });
  }

  recordSuccess(key);
  recordSuccess(account);
  const token = await sign(identity.username, identity.role, config.sessionSecret);
  (await cookies()).set(SESSION_COOKIE, token, cookieOptions(config.secureCookies));

  // The role goes back so the browser can render the right navigation
  // immediately. It is not what grants access — that is the signed cookie —
  // and a client that lies to itself about its role still cannot reach an
  // administrator route, because the middleware reads the cookie, not this.
  return Response.json({ ok: true, role: identity.role });
}
