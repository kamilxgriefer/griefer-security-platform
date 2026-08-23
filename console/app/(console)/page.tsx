import { Dashboard, type DashboardData } from "@/components/Dashboard";
import { getSystemStatus, listEvents, listIncidents, settled } from "@/lib/api";

// Operational state, never cached.
export const dynamic = "force-dynamic";
export const revalidate = 0;

export default async function DashboardPage({
  searchParams,
}: {
  readonly searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  // middleware.ts sends an analyst here when they ask for an administrator
  // page. Without this the redirect is silent: the address changes, the page
  // looks normal, and nothing says why they did not arrive where they asked.
  const denied = (await searchParams).denied === "1";

  // Each panel is fetched independently so one unavailable dependency degrades
  // a single card rather than blanking the whole console.
  const [status, incidents, events] = await Promise.all([
    settled(getSystemStatus()),
    settled(listIncidents(25)),
    settled(listEvents(12)),
  ]);

  const data: DashboardData = {
    status: status.ok ? status.value : null,
    ...(status.ok ? {} : { statusError: describe(status.error) }),
    incidents: incidents.ok ? (incidents.value.items ?? []) : [],
    ...(incidents.ok ? {} : { incidentsError: describe(incidents.error) }),
    events: events.ok ? (events.value.items ?? []) : [],
    ...(events.ok ? {} : { eventsError: describe(events.error) }),
  };

  return (
    <>
      {denied && <AccessDenied />}
      <Dashboard data={data} />
    </>
  );
}

/**
 * Shown after the middleware turns an analyst away from an administrator page.
 *
 * It names the reason rather than apologising for an error, because this is not
 * one: the account worked, the session is valid, and the page simply is not
 * theirs. role="status" so a screen reader announces it — someone who navigated
 * by keyboard has no other way to notice the page they asked for is not the
 * page they got.
 */
function AccessDenied() {
  return (
    <div
      role="status"
      data-testid="access-denied"
      className="mb-4 rounded-lg border border-[var(--color-surface-border-strong)] bg-[var(--color-surface-raised)] px-4 py-3 text-[13px] text-[var(--color-text-secondary)]"
    >
      That page is available to administrators only. You have been returned to the dashboard.
    </div>
  );
}

function describe(error: { message: string; code: string; requestId?: string | undefined }) {
  return { message: error.message, code: error.code, requestId: error.requestId };
}
