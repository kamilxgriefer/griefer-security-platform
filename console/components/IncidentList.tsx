import Link from "next/link";

import { Card, EmptyState } from "@/components/Card";
import { ErrorPanel } from "@/components/ErrorPanel";
import { SeverityBadge, StatusBadge } from "@/components/Badges";
import { formatRelative, formatTimestamp, shortId } from "@/lib/format";
import type { Incident } from "@/lib/types";

export function IncidentList({
  incidents,
  error,
}: {
  readonly incidents: readonly Incident[];
  readonly error?: { message: string; code: string; requestId?: string | undefined } | undefined;
}) {
  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-lg font-semibold">Incidents</h1>
        <p className="mt-1 text-[13px] text-[var(--color-text-secondary)]">
          Correlated findings grouped by acting identity, most recently active first.
        </p>
      </header>

      {error ? (
        <ErrorPanel
          title="Incidents unavailable"
          message={error.message}
          code={error.code}
          requestId={error.requestId}
        />
      ) : incidents.length === 0 ? (
        <Card>
          <EmptyState message="No incidents. Run `make demo` to replay the synthetic scenario through the ingest API." />
        </Card>
      ) : (
        <Card className="overflow-hidden" title={`${incidents.length} incidents`}>
          <div className="-mx-4 -my-4 overflow-x-auto">
            <table className="w-full min-w-[720px] border-collapse text-left">
              <thead>
                <tr className="border-b border-[var(--color-surface-border)] text-[11px] uppercase tracking-wider text-[var(--color-text-muted)]">
                  <th scope="col" className="px-4 py-2 font-semibold">Incident</th>
                  <th scope="col" className="px-4 py-2 font-semibold">Severity</th>
                  <th scope="col" className="px-4 py-2 font-semibold">Status</th>
                  <th scope="col" className="px-4 py-2 text-right font-semibold">Risk</th>
                  <th scope="col" className="px-4 py-2 text-right font-semibold">Blast</th>
                  <th scope="col" className="px-4 py-2 font-semibold">Last activity</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((incident) => (
                  <tr
                    key={incident.id}
                    className="border-b border-[var(--color-surface-border)] last:border-0 hover:bg-[var(--color-surface-overlay)]"
                  >
                    <td className="px-4 py-3">
                      <Link
                        href={`/incidents/${incident.id}`}
                        className="text-[13px] text-[var(--color-text-primary)] no-underline hover:text-[var(--color-brand)]"
                      >
                        {incident.title}
                      </Link>
                      <div className="mt-0.5 font-mono text-[11px] text-[var(--color-text-muted)]">
                        {shortId(incident.id)}
                        {incident.findings ? ` · ${incident.findings.length} findings` : ""}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={incident.severity} />
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={incident.status} />
                    </td>
                    <td className="px-4 py-3 text-right font-mono tabular-nums">
                      {incident.risk_score}
                    </td>
                    <td className="px-4 py-3 text-right font-mono tabular-nums text-[var(--color-text-secondary)]">
                      {incident.blast_radius?.score ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-[12px] text-[var(--color-text-secondary)]">
                      <span title={formatTimestamp(incident.last_seen)}>
                        {formatRelative(incident.last_seen)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
