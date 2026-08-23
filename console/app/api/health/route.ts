/**
 * Liveness endpoint for the console container.
 *
 * It deliberately does NOT probe the GRIEFER API: this answers "is the console
 * process serving?", and a console that restarts every time the backend blips
 * is a console nobody can use to diagnose the blip.
 */
export const dynamic = "force-dynamic";

export function GET(): Response {
  return Response.json({ status: "ok", component: "griefer-console" });
}
