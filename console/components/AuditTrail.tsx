import { Card, EmptyState } from "@/components/Card";
import { ErrorPanel } from "@/components/ErrorPanel";
import { formatTimestamp, humanize, shortId } from "@/lib/format";
import type { AuditEntry } from "@/lib/types";

const OUTCOME_STYLE: Record<string, string> = {
  success: "text-[var(--color-ok)]",
  denied: "text-[var(--color-bad)]",
  failure: "text-[var(--color-bad)]",
  pending: "text-[var(--color-warn)]",
};

export function AuditTrail({
  entries,
  error,
}: {
  readonly entries: readonly AuditEntry[];
  readonly error?: { message: string; code: string; requestId?: string | undefined } | undefined;
}) {
  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-lg font-semibold">Audit trail</h1>
        <p className="mt-1 text-[13px] text-[var(--color-text-secondary)]">
          Append-only record of every decision GRIEFER made and why. Oldest first. Entries are
          hash-chained, so an alteration is detectable — but the chain is stored beside the entries
          and is not externally anchored, so it is not evidence against whoever controls the
          database. See docs/SAFETY_MODEL.md.
        </p>
      </header>

      {error ? (
        <ErrorPanel
          title="Audit trail unavailable"
          message={error.message}
          code={error.code}
          requestId={error.requestId}
        />
      ) : entries.length === 0 ? (
        <Card>
          <EmptyState message="No audit entries yet." />
        </Card>
      ) : (
        <Card title={`${entries.length} entries`} className="overflow-hidden">
          <div className="-mx-4 -my-4 overflow-x-auto">
            <table className="w-full min-w-[820px] border-collapse text-left">
              <thead>
                <tr className="border-b border-[var(--color-surface-border)] text-[11px] uppercase tracking-wider text-[var(--color-text-muted)]">
                  <th scope="col" className="px-4 py-2 font-semibold">#</th>
                  <th scope="col" className="px-4 py-2 font-semibold">Time</th>
                  <th scope="col" className="px-4 py-2 font-semibold">Action</th>
                  <th scope="col" className="px-4 py-2 font-semibold">Subject</th>
                  <th scope="col" className="px-4 py-2 font-semibold">Outcome</th>
                  <th scope="col" className="px-4 py-2 font-semibold">Reason</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <tr
                    key={entry.id}
                    className="border-b border-[var(--color-surface-border)] align-top last:border-0"
                  >
                    <td className="px-4 py-2 font-mono text-[11px] tabular-nums text-[var(--color-text-muted)]">
                      {entry.sequence}
                    </td>
                    <td className="whitespace-nowrap px-4 py-2 font-mono text-[11px] text-[var(--color-text-secondary)]">
                      {formatTimestamp(entry.timestamp)}
                    </td>
                    <td className="px-4 py-2 font-mono text-[12px]">{entry.action}</td>
                    <td className="px-4 py-2 font-mono text-[11px] text-[var(--color-text-muted)]">
                      {entry.subject_type}
                      {entry.subject_id ? ` ${shortId(entry.subject_id)}` : ""}
                    </td>
                    <td
                      className={`px-4 py-2 text-[12px] font-semibold ${
                        OUTCOME_STYLE[entry.outcome] ?? "text-[var(--color-text-secondary)]"
                      }`}
                    >
                      {humanize(entry.outcome)}
                    </td>
                    <td className="max-w-[420px] px-4 py-2 text-[12px] text-[var(--color-text-secondary)]">
                      {entry.reason}
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
