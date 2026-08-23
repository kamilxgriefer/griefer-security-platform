import { IncidentList } from "@/components/IncidentList";
import { listIncidents, settled } from "@/lib/api";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export default async function IncidentsPage() {
  const result = await settled(listIncidents(100));
  if (!result.ok) {
    return (
      <IncidentList
        incidents={[]}
        error={{
          message: result.error.message,
          code: result.error.code,
          requestId: result.error.requestId,
        }}
      />
    );
  }
  return <IncidentList incidents={result.value.items ?? []} />;
}
