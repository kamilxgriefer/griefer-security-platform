import { Dashboard, type DashboardData } from "@/components/Dashboard";
import { getSystemStatus, listEvents, listIncidents, settled } from "@/lib/api";

// Operational state, never cached.
export const dynamic = "force-dynamic";
export const revalidate = 0;

export default async function DashboardPage() {
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

  return <Dashboard data={data} />;
}

function describe(error: { message: string; code: string; requestId?: string | undefined }) {
  return { message: error.message, code: error.code, requestId: error.requestId };
}
