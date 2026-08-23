/**
 * Signed demonstration sessions.
 *
 * Deliberately built on Web Crypto (HMAC-SHA256) rather than node:crypto, so
 * the same verification runs in Next.js middleware — which executes on the Edge
 * runtime — and in Node route handlers. One implementation means the gate
 * cannot be strict in one place and lenient in the other.
 *
 * Password verification is NOT here. That needs scrypt, which is Node-only, and
 * it lives in lib/password.ts where only the login route touches it.
 */

import { isRole, type Role } from "./roles";

export const SESSION_COOKIE = "griefer_session";

/** Sessions are short-lived: this is a demonstration, not a workspace. */
export const SESSION_TTL_SECONDS = 12 * 60 * 60;

export interface SessionPayload {
  /** Subject — the account name. */
  sub: string;
  /**
   * The role this session carries.
   *
   * It is inside the signed payload rather than looked up per request, so a
   * request cannot be served with a role the login did not grant. The cost is
   * that a role change takes effect at the holder's next sign-in; that is the
   * right trade for a session that lives twelve hours, and re-reading the role
   * on every request would mean a database call on every page of the console.
   */
  role: Role;
  /** Issued at, seconds since epoch. */
  iat: number;
  /** Expires at, seconds since epoch. */
  exp: number;
}

function encoder(): TextEncoder {
  return new TextEncoder();
}

function base64UrlEncode(bytes: Uint8Array<ArrayBufferLike>): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  // Backed by an explicit ArrayBuffer so the result satisfies BufferSource;
  // a plain Uint8Array is typed over ArrayBufferLike, which includes
  // SharedArrayBuffer and is therefore not accepted by Web Crypto.
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function key(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    encoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/** sign issues a session token for sub, valid for SESSION_TTL_SECONDS. */
export async function sign(
  sub: string,
  role: Role,
  secret: string,
  now = Date.now(),
): Promise<string> {
  const issuedAt = Math.floor(now / 1000);
  const payload: SessionPayload = {
    sub,
    role,
    iat: issuedAt,
    exp: issuedAt + SESSION_TTL_SECONDS,
  };
  const body = base64UrlEncode(encoder().encode(JSON.stringify(payload)));
  const signature = await crypto.subtle.sign("HMAC", await key(secret), encoder().encode(body));
  return `${body}.${base64UrlEncode(new Uint8Array(signature))}`;
}

/**
 * verify returns the payload of a valid, unexpired token, or null.
 *
 * crypto.subtle.verify performs the comparison, so it is constant-time with
 * respect to the signature. Every failure — malformed, wrong signature, expired
 * — returns the same null, because a caller that could tell them apart could
 * use the difference.
 */
export async function verify(
  token: string | undefined,
  secret: string,
  now = Date.now(),
): Promise<SessionPayload | null> {
  if (!token || !secret) return null;

  const separator = token.indexOf(".");
  if (separator <= 0 || separator === token.length - 1) return null;

  const body = token.slice(0, separator);
  const signature = token.slice(separator + 1);

  let valid: boolean;
  try {
    valid = await crypto.subtle.verify(
      "HMAC",
      await key(secret),
      base64UrlDecode(signature),
      encoder().encode(body),
    );
  } catch {
    return null;
  }
  if (!valid) return null;

  let payload: SessionPayload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(body))) as SessionPayload;
  } catch {
    return null;
  }
  if (typeof payload.exp !== "number" || typeof payload.sub !== "string") return null;
  // A token whose role is missing or unrecognised is rejected outright rather
  // than defaulted. Defaulting would mean a tampered or stale token silently
  // acquiring whatever role the default happens to be, and a token signed
  // before roles existed would come back as a valid session with no role at all.
  if (!isRole(payload.role)) return null;
  if (payload.exp * 1000 <= now) return null;

  return payload;
}

/** cookieOptions are the attributes every session cookie carries. */
export function cookieOptions(secure: boolean) {
  return {
    httpOnly: true,
    // Secure is omitted on plain-HTTP localhost, because a browser silently
    // drops a Secure cookie there and the login would appear to fail for no
    // visible reason. Every deployed environment is HTTPS.
    secure,
    sameSite: "lax" as const,
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  };
}
