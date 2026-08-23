import "server-only";

import { cookies } from "next/headers";

import { consoleConfig } from "./config";
import type { Role } from "./roles";
import { SESSION_COOKIE, verify } from "./session";

/**
 * The signed-in identity, for server components that need to render differently
 * for an administrator and an analyst.
 *
 * This is for presentation, not protection. Access is decided in middleware.ts,
 * in front of every route, and a component that hides a link is not a control —
 * anyone can type the address. Hiding it is still worth doing, because a
 * console full of links that answer "forbidden" teaches people to ignore
 * permission errors.
 */
export interface CurrentSession {
  username: string;
  role: Role;
}

export async function currentSession(): Promise<CurrentSession | null> {
  const config = consoleConfig();
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  const payload = await verify(token, config.sessionSecret);
  if (!payload) return null;
  return { username: payload.sub, role: payload.role };
}
