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

/** actorHeaders returns the operator headers for the current session, if any. */
export async function actorHeaders(): Promise<Record<string, string>> {
  const session = await currentSession();
  if (!session) return {};
  return {
    [ACTOR_HEADER]: `console:${session.username}`,
    [ACTOR_ROLE_HEADER]: session.role,
  };
}
