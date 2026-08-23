import { cookies } from "next/headers";

import { consoleConfig } from "@/lib/config";
import { isSameOrigin } from "@/lib/request";
import { SESSION_COOKIE, cookieOptions } from "@/lib/session";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Logout clears the session cookie.
 *
 * A POST rather than a GET, and same-origin checked, so a third-party page
 * cannot log an analyst out mid-investigation with an image tag.
 */
export async function POST(request: Request): Promise<Response> {
  if (!isSameOrigin(request)) {
    return Response.json({ error: "Forbidden." }, { status: 403 });
  }
  const config = consoleConfig();
  (await cookies()).set(SESSION_COOKIE, "", {
    ...cookieOptions(config.secureCookies),
    maxAge: 0,
  });
  return Response.json({ ok: true });
}
