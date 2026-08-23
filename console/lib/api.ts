import "server-only";

import type {
  AuditEntry,
  Incident,
  Page,
  ResponseAction,
  SecurityEvent,
  SystemStatus,
} from "./types";

/**
 * Server-side client for the GRIEFER API.
 *
 * Every call runs in a React Server Component, never in the browser. That is a
 * security decision, not a style one: the API has no authentication in v0.1, so
 * the browser must never be able to reach it, and there is consequently no CORS
 * surface and no client-side API base URL to leak.
 */

const DEFAULT_BASE_URL = "http://127.0.0.1:8080";
const REQUEST_TIMEOUT_MS = 8_000;

function baseUrl(): string {
  return process.env.GRIEFER_API_BASE_URL ?? DEFAULT_BASE_URL;
}

/** ApiError carries enough context for the UI to explain a failure honestly. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | undefined;

  constructor(message: string, status: number, code: string, requestId?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }

  /** notFound distinguishes "no such incident" from "the platform is broken". */
  get notFound(): boolean {
    return this.status === 404;
  }
}

async function request<T>(path: string): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(`${baseUrl()}${path}`, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
      // Incident data is live operational state. A cached SOC console is a
      // console that shows an analyst yesterday's attack.
      cache: "no-store",
    });
  } catch (cause) {
    const reason =
      cause instanceof Error && cause.name === "AbortError"
        ? `The GRIEFER API did not respond within ${REQUEST_TIMEOUT_MS / 1000}s.`
        : "The GRIEFER API could not be reached.";
    throw new ApiError(reason, 503, "api_unreachable");
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    const requestId = response.headers.get("x-request-id") ?? undefined;
    let code = "http_error";
    let message = `The GRIEFER API returned ${response.status}.`;
    try {
      const body = (await response.json()) as { error?: { code?: string; message?: string } };
      if (body.error?.code) code = body.error.code;
      if (body.error?.message) message = body.error.message;
    } catch {
      // A non-JSON error body is itself a signal, but not one worth crashing on.
    }
    throw new ApiError(message, response.status, code, requestId);
  }

  return (await response.json()) as T;
}

export function getSystemStatus(): Promise<SystemStatus> {
  return request<SystemStatus>("/api/v1/system/status");
}

export function listIncidents(limit = 25): Promise<Page<Incident>> {
  return request<Page<Incident>>(`/api/v1/incidents?limit=${encodeURIComponent(limit)}`);
}

export function getIncident(id: string): Promise<Incident> {
  return request<Incident>(`/api/v1/incidents/${encodeURIComponent(id)}`);
}

export function listEvents(limit = 25): Promise<Page<SecurityEvent>> {
  return request<Page<SecurityEvent>>(`/api/v1/events?limit=${encodeURIComponent(limit)}`);
}

export function listActions(incidentId?: string, limit = 50): Promise<Page<ResponseAction>> {
  const query = new URLSearchParams({ limit: String(limit) });
  if (incidentId) query.set("incident_id", incidentId);
  return request<Page<ResponseAction>>(`/api/v1/actions?${query.toString()}`);
}

export function listAudit(limit = 100): Promise<Page<AuditEntry>> {
  return request<Page<AuditEntry>>(`/api/v1/audit?limit=${encodeURIComponent(limit)}`);
}

/**
 * settled runs a request and returns either its value or the error, so a page
 * can render the parts that loaded rather than failing whole because one panel
 * is unavailable. A dashboard that goes blank when one dependency is down is
 * worse than one that says which dependency is down.
 */
export async function settled<T>(promise: Promise<T>): Promise<{ ok: true; value: T } | { ok: false; error: ApiError }> {
  try {
    return { ok: true, value: await promise };
  } catch (cause) {
    if (cause instanceof ApiError) return { ok: false, error: cause };
    return {
      ok: false,
      error: new ApiError("An unexpected error occurred while loading data.", 500, "unexpected"),
    };
  }
}
