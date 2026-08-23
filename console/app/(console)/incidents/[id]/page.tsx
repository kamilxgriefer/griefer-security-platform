import { notFound } from "next/navigation";

import { ErrorPanel } from "@/components/ErrorPanel";
import { IncidentDetail } from "@/components/IncidentDetail";
import { getIncident, listActions, settled } from "@/lib/api";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export default async function IncidentPage({
  params,
}: {
  readonly params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  const incident = await settled(getIncident(id));
  if (!incident.ok) {
    if (incident.error.notFound) notFound();
    return (
      <ErrorPanel
        title="Incident could not be loaded"
        message={incident.error.message}
        code={incident.error.code}
        requestId={incident.error.requestId}
      />
    );
  }

  // Policy decisions are supplementary: an incident is still worth reading if
  // the action history is unavailable.
  const actions = await settled(listActions(id));

  return (
    <IncidentDetail
      incident={incident.value}
      actions={actions.ok ? (actions.value.items ?? []) : []}
    />
  );
}
