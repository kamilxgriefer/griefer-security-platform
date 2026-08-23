import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";

// server-only throws when imported outside a React Server Component. The module
// under test is genuinely server-only; stubbing the guard is what lets its error
// handling be tested at all.
vi.mock("server-only", () => ({}));

const { ApiError, getSystemStatus, listIncidents, settled } = await import("@/lib/api");

describe("GRIEFER API client", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    process.env.GRIEFER_API_BASE_URL = "http://griefer.test";
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    delete process.env.GRIEFER_API_BASE_URL;
  });

  it("never caches operational state", async () => {
    const fetchMock = vi.fn(
      async (_url: string, _init: RequestInit): Promise<Response> =>
        new Response(JSON.stringify({ status: "ready" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await getSystemStatus();

    const call = fetchMock.mock.calls[0];
    expect(call).toBeDefined();
    expect(call?.[1].cache).toBe("no-store");
  });

  it("surfaces the API's own error code and request id", async () => {
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          error: { code: "validation_failed", message: "Query parameter is invalid." },
        }),
        { status: 400, headers: { "content-type": "application/json", "x-request-id": "req-abc" } },
      )) as unknown as typeof fetch;

    const result = await settled(listIncidents());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(ApiError);
    expect(result.error.code).toBe("validation_failed");
    expect(result.error.message).toBe("Query parameter is invalid.");
    expect(result.error.requestId).toBe("req-abc");
    expect(result.error.notFound).toBe(false);
  });

  it("marks 404 so a page can render 'not found' rather than 'broken'", async () => {
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ error: { code: "not_found", message: "Incident not found." } }), {
        status: 404,
        headers: { "content-type": "application/json" },
      })) as unknown as typeof fetch;

    const result = await settled(listIncidents());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.notFound).toBe(true);
  });

  it("handles an error body that is not JSON", async () => {
    globalThis.fetch = (async () =>
      new Response("<html>502 Bad Gateway</html>", {
        status: 502,
        headers: { "content-type": "text/html" },
      })) as unknown as typeof fetch;

    const result = await settled(listIncidents());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(502);
    // The HTML must not be relayed to the analyst as if it were a message.
    expect(result.error.message).not.toContain("<html>");
  });

  it("reports an unreachable API as a connection failure, not an empty result", async () => {
    globalThis.fetch = (async () => {
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch;

    const result = await settled(getSystemStatus());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("api_unreachable");
    expect(result.error.status).toBe(503);
  });

  it("gives up rather than hanging when the API stops responding", async () => {
    globalThis.fetch = (async (_url: string, init: RequestInit) => {
      // Emulate an aborted request the way fetch does.
      const error = new Error("The operation was aborted.");
      error.name = "AbortError";
      void init;
      throw error;
    }) as unknown as typeof fetch;

    const result = await settled(getSystemStatus());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.message).toMatch(/did not respond within/i);
  });

  it("passes the pagination limit through", async () => {
    const fetchMock = vi.fn(
      async (_url: string, _init: RequestInit): Promise<Response> =>
        new Response(JSON.stringify({ items: [], total: 0, limit: 7, offset: 0 }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await listIncidents(7);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("http://griefer.test/api/v1/incidents?limit=7");
  });
});
