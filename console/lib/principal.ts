import "server-only";

import { currentSession } from "./currentSession";

/**
 * Headers that carry the signed-in operator to the GRIEFER API.
 *
 * The API cannot authenticate a person. Only trusted components hold the
 * service credential, so that credential answers "is this the console", not
 * "who is using it" — and the audit trail needs the second answer.
 *
 * These headers supply it. They are trustworthy only because they travel with
 * the service credential over the private network: the API reads them after
 * verifying that credential and never before. A browser cannot set them,
 * because a browser cannot reach the API at all and this gateway builds its
 * outbound headers from the session rather than forwarding what it received.
 */
export const ACTOR_HEADER = "X-Griefer-Actor";
export const ACTOR_ROLE_HEADER = "X-Griefer-Actor-Role";

/**
 * actorHeaders returns the operator headers for the current session, if any.
 *
 * Reading the session needs a request to read cookies from, and not every call
 * into the API client has one — a build-time render or a test harness has no
 * request scope, and cookies() throws there rather than returning nothing. That
 * must not turn into a failed API call, so the absence of a session is treated
 * as what it is: a call made on nobody's behalf, which the API accepts and
 * records against the system actor.
 *
 * This deliberately cannot fail open in the dangerous direction. The worst case
 * is an unattributed request, never a request attributed to the wrong person.
 */
export async function actorHeaders(): Promise<Record<string, string>> {
  let session: Awaited<ReturnType<typeof currentSession>> = null;
  try {
    session = await currentSession();
  } catch {
    return {};
  }
  if (!session) return {};
  return {
    [ACTOR_HEADER]: `console:${session.username}`,
    [ACTOR_ROLE_HEADER]: session.role,
  };
}
