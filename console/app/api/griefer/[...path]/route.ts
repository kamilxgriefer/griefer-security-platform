import { consoleConfig } from "@/lib/config";
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
