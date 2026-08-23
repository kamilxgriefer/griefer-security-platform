import { AuditTrail } from "@/components/AuditTrail";
import { listAudit, settled } from "@/lib/api";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export default async function AuditPage() {
  const result = await settled(listAudit(200));
  if (!result.ok) {
    return (
      <AuditTrail
        entries={[]}
        error={{
          message: result.error.message,
          code: result.error.code,
          requestId: result.error.requestId,
        }}
      />
    );
  }
  return <AuditTrail entries={result.value.items ?? []} />;
}
