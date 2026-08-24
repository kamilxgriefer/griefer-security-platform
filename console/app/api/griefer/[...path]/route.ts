import { consoleConfig } from "@/lib/config";
import { currentSession } from "@/lib/currentSession";
import { actorHeaders } from "@/lib/principal";
import { isSameOrigin } from "@/lib/request";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Server-side gateway from the browser to the private GRIEFER API.
 *
 * The browser can never reach the API directly: it has no public address, and
 * its host name only resolves inside the platform's private network. Every
 * browser-initiated call therefore lands here, where it is authenticated by the
 * session cookie (enforced in middleware.ts) and re-issued with the service
 * credential.
 *
 * This is deliberately NOT a generic proxy. A gateway that forwards whatever
 * path it is handed is a server-side request forgery primitive pointed at the
 * internal network — the caller picks the target and the gateway supplies the
 * credential. Only the exact method-and-path pairs below are forwarded.
 */

/** Literal endpoints, matched exactly. */
const ALLOWED_EXACT: Record<string, readonly string[]> = {
  GET: [
    "system/status",
    "incidents",
    "events",
    "actions",
    "audit",
  ],
  POST: ["actions/evaluate"],
};

/**
 * Endpoints taking a single identifier. The identifier is matched against a
 * conservative pattern rather than being passed through, so it cannot carry a
 * path traversal, a query string or a second URL.
 */
const ALLOWED_WITH_ID: Record<string, readonly string[]> = {
  GET: ["incidents", "entities", "actions"],
};

/** GRIEFER identifiers, and entity ids such as `cloud_resource:arn:aws:s3:::bucket`. */
const ID_PATTERN = /^[A-Za-z0-9._:-]{1,256}$/;

/** Query parameters the gateway will forward, with their accepted shapes. */
const ALLOWED_QUERY: Record<string, RegExp> = {
  limit: /^\d{1,3}$/,
  offset: /^\d{1,6}$/,
  status: /^(open|investigating|contained|closed)$/,
  severity: /^(informational|low|medium|high|critical)$/,
  min_risk_score: /^\d{1,3}$/,
  incident_id: ID_PATTERN,
};

const MAX_BODY_BYTES = 16 * 1024;
const UPSTREAM_TIMEOUT_MS = 10_000;

function resolveTarget(method: string, segments: readonly string[]): string | null {
  if (segments.length === 0 || segments.length > 2) return null;
  if (segments.some((segment) => segment.length === 0)) return null;

  const [head, id] = segments;
  if (head === undefined) return null;

  if (segments.length === 1) {
    return (ALLOWED_EXACT[method] ?? []).includes(head) ? head : null;
  }

  // Two segments: either a literal like actions/evaluate, or a resource id.
  const literal = `${head}/${id}`;
  if ((ALLOWED_EXACT[method] ?? []).includes(literal)) return literal;

  if (id !== undefined && (ALLOWED_WITH_ID[method] ?? []).includes(head) && ID_PATTERN.test(id)) {
    return `${head}/${encodeURIComponent(id)}`;
  }
  return null;
}

function forwardableQuery(url: URL): string {
  const out = new URLSearchParams();
  for (const [name, pattern] of Object.entries(ALLOWED_QUERY)) {
    const value = url.searchParams.get(name);
    if (value !== null && pattern.test(value)) out.set(name, value);
  }
  const query = out.toString();
  return query ? `?${query}` : "";
}

/**
 * Stamp a response-action request with the operator who actually asked for it.
 *
 * requested_by ends up in ResponseAction and in the audit trail, and it is the
 * field that answers "who did this". It cannot come from the browser: a
 * signed-in caller can put any string in a request body, so a client-supplied
 * value attributes the action to whoever the client says — which makes the
 * audit trail worse than empty, because it looks authoritative.
 *
 * The value is taken from the signed session cookie and overwrites whatever
 * arrived, rather than filling in a missing field. Trusting a submitted value
 * when one is present would leave exactly the hole this closes.
 *
 * Returns null if the body is not a JSON object, so a malformed request is
 * refused here rather than forwarded to the API with the credential attached.
 */
async function attribute(raw: string): Promise<string | null> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;

  const session = await currentSession();
  // middleware.ts has already refused anonymous callers, so this is unreachable
  // in practice. It is handled rather than asserted because an unreachable
  // assertion becomes a crash the day the matcher changes — and the safe answer
  // here is to refuse, not to forward an unattributed action.
  if (!session) return null;

  // The identity now travels in headers the API reads after verifying the
  // service credential, so these body fields are stripped rather than
  // rewritten. The API ignores them, and removing them means a console and an
  // API deployed at different versions cannot end up disagreeing about which
  // of the two decided who the operator was.
  const { requested_by: _ignoredActor, automated: _ignoredAutomated, ...rest } =
    parsed as Record<string, unknown>;
  return JSON.stringify(rest);
}

async function handle(
  request: Request,
  context: { params: Promise<{ path: string[] }> },
): Promise<Response> {
  const { path } = await context.params;
  const method = request.method.toUpperCase();

  // Every state-changing call must originate from this app. Combined with the
  // SameSite=Lax session cookie, this is the CSRF defence.
  if (method !== "GET" && !isSameOrigin(request)) {
    return Response.json(
      { error: { code: "forbidden", message: "Cross-origin requests are not accepted." } },
      { status: 403 },
    );
  }

  const target = resolveTarget(method, path ?? []);
  if (target === null) {
    return Response.json(
      { error: { code: "not_found", message: "No such endpoint." } },
      { status: 404 },
    );
  }

  const config = consoleConfig();
  const upstream = new URL(request.url);
  const url = `${config.apiBaseUrl}/api/v1/${target}${method === "GET" ? forwardableQuery(upstream) : ""}`;

  let body: string | undefined;
  if (method === "POST") {
    const raw = await request.text();
    if (raw.length > MAX_BODY_BYTES) {
      return Response.json(
        { error: { code: "payload_too_large", message: "Request body is too large." } },
        { status: 413 },
      );
    }
    body = raw;

    if (target === "actions/evaluate") {
      const attributed = await attribute(raw);
      if (attributed === null) {
        return Response.json(
          { error: { code: "bad_request", message: "Malformed request body." } },
          { status: 400 },
        );
      }
      body = attributed;
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(url, {
      method,
      signal: controller.signal,
      cache: "no-store",
      headers: {
        Accept: "application/json",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(config.internalApiToken
          ? { Authorization: `Bearer ${config.internalApiToken}` }
          : {}),
        // Built from the session, never forwarded from the incoming request.
        // Forwarding would let a browser name itself simply by setting the
        // header on its call to this gateway.
        ...(await actorHeaders()),
      },
      ...(body === undefined ? {} : { body }),
    });
  } catch {
    // The upstream address and the reason both stay server-side: an error that
    // names an internal host has handed out part of the network map.
    return Response.json(
      { error: { code: "upstream_unavailable", message: "The GRIEFER API is unavailable." } },
      { status: 502 },
    );
  } finally {
    clearTimeout(timer);
  }

  const payload = await response.text();
  return new Response(payload, {
    status: response.status,
    headers: {
      "Content-Type": response.headers.get("content-type") ?? "application/json",
      // Incident data must not be cached by any shared cache.
      "Cache-Control": "no-store, private",
    },
  });
}

export const GET = handle;
export const POST = handle;
