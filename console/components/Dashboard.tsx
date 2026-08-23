import Link from "next/link";

import { Card, EmptyState, Stat } from "@/components/Card";
import { ErrorPanel } from "@/components/ErrorPanel";
import { SeverityBadge, StatusBadge } from "@/components/Badges";
import { SEVERITY_ORDER, formatRelative, formatTime, humanize, shortId } from "@/lib/format";
import type {
  ComponentStatus,
  Incident,
  SecurityEvent,
  Severity,
  SystemStatus,
} from "@/lib/types";

export interface DashboardData {
  readonly status: SystemStatus | null;
  readonly statusError?: { message: string; code: string; requestId?: string | undefined };
  readonly incidents: readonly Incident[];
  readonly incidentsError?: { message: string; code: string; requestId?: string | undefined };
  readonly events: readonly SecurityEvent[];
  readonly eventsError?: { message: string; code: string; requestId?: string | undefined };
}

/**
 * Dashboard is a pure presentational component. Data fetching lives in the
 * server page that renders it, which is what makes the whole dashboard
 * testable without a running platform.
 */
export function Dashboard({ data }: { readonly data: DashboardData }) {
  const openIncidents = data.incidents.filter((i) => i.status !== "closed");
  const bySeverity = countBySeverity(openIncidents);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-lg font-semibold">Operations overview</h1>
        <p className="mt-1 text-[13px] text-[var(--color-text-secondary)]">
          Live state of the GRIEFER event pipeline, correlation engine and Policy Kernel.
        </p>
      </header>

      {data.statusError && (
        <ErrorPanel
          title="Platform status unavailable"
          message={data.statusError.message}
          code={data.statusError.code}
          requestId={data.statusError.requestId}
        />
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {/*
          When the incident query failed, the count is unknown — not zero. A
          reassuring "0" on a console that cannot see the platform is the single
          most dangerous thing this page could display.
        */}
        <Stat
          label="Active incidents"
          value={data.incidentsError ? "—" : openIncidents.length}
          hint={
            data.incidentsError
              ? "unknown — API unreachable"
              : openIncidents.length === 0
                ? "nothing open"
                : "not yet closed"
          }
          tone={data.incidentsError ? "bad" : openIncidents.length > 0 ? "warn" : "good"}
        />
        <Stat
          label="Events ingested"
          value={data.status?.events_ingested ?? "—"}
          hint="since start"
        />
        <Stat
          label="Graph entities"
          value={data.status?.graph_entities ?? "—"}
          hint={`${data.status?.graph_edges ?? 0} relationships`}
        />
        <Stat
          label="Detection rules"
          value={data.status?.detection_rules ?? "—"}
          hint="loaded and active"
          tone={data.status && data.status.detection_rules === 0 ? "bad" : "default"}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Incidents by severity" className="lg:col-span-1">
          {openIncidents.length === 0 ? (
            <EmptyState message="No active incidents." />
          ) : (
            <ul className="space-y-2">
              {SEVERITY_ORDER.map((severity) => {
                const count = bySeverity[severity] ?? 0;
                const share = openIncidents.length > 0 ? (count / openIncidents.length) * 100 : 0;
                return (
                  <li key={severity} className="flex items-center gap-3">
                    <span className="w-24 shrink-0">
                      <SeverityBadge severity={severity} />
                    </span>
                    <span
                      className="h-1.5 flex-1 overflow-hidden rounded bg-[var(--color-surface-overlay)]"
                      aria-hidden="true"
                    >
                      <span
                        className="block h-full rounded bg-[var(--color-brand)]"
                        style={{ width: `${share}%` }}
                      />
                    </span>
                    <span className="w-6 text-right tabular-nums text-[13px]">{count}</span>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>

        <Card
          title="Platform components"
          subtitle={data.status ? `Response mode: ${data.status.response_mode}` : undefined}
          className="lg:col-span-2"
        >
          {data.status ? (
            <ul className="grid gap-2 sm:grid-cols-3">
              {data.status.components.map((component) => (
                <ComponentTile key={component.name} component={component} />
              ))}
            </ul>
          ) : (
            <EmptyState message="Component status could not be read." />
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card
          title="Open incidents"
          actions={
            <Link href="/incidents" className="text-[12px] text-[var(--color-brand)] no-underline">
              View all
            </Link>
          }
        >
          {data.incidentsError ? (
            <ErrorPanel
              title="Incidents unavailable"
              message={data.incidentsError.message}
              code={data.incidentsError.code}
              requestId={data.incidentsError.requestId}
            />
          ) : openIncidents.length === 0 ? (
            <EmptyState message="Nothing open. Run `make demo` to replay the synthetic scenario." />
          ) : (
            <ul className="divide-y divide-[var(--color-surface-border)]">
              {openIncidents.slice(0, 6).map((incident) => (
                <li key={incident.id} className="py-2.5 first:pt-0 last:pb-0">
                  <Link
                    href={`/incidents/${incident.id}`}
                    className="flex flex-wrap items-center justify-between gap-2 no-underline"
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[13px] text-[var(--color-text-primary)]">
                        {incident.title}
                      </span>
                      <span className="mt-0.5 block font-mono text-[11px] text-[var(--color-text-muted)]">
                        {shortId(incident.id)} · {formatRelative(incident.last_seen)}
                      </span>
                    </span>
                    <span className="flex items-center gap-2">
                      <SeverityBadge severity={incident.severity} />
                      <StatusBadge status={incident.status} />
                      <span className="w-8 text-right font-mono text-[13px] tabular-nums text-[var(--color-text-primary)]">
                        {incident.risk_score}
                      </span>
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Latest telemetry" subtitle="Newest first, as received by the ingest API">
          {data.eventsError ? (
            <ErrorPanel
              title="Event feed unavailable"
              message={data.eventsError.message}
              code={data.eventsError.code}
              requestId={data.eventsError.requestId}
            />
          ) : data.events.length === 0 ? (
            <EmptyState message="No events ingested yet." />
          ) : (
            <ul className="divide-y divide-[var(--color-surface-border)]">
              {data.events.slice(0, 8).map((event) => (
                <li key={event.id} className="flex items-baseline gap-3 py-2 first:pt-0 last:pb-0">
                  <span className="shrink-0 font-mono text-[11px] text-[var(--color-text-muted)]">
                    {formatTime(event.timestamp)}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[13px]">
                      {humanize(event.event_type)}
                      {event.actor?.name ? (
                        <span className="text-[var(--color-text-muted)]"> · {event.actor.name}</span>
                      ) : null}
                    </span>
                    <span className="text-[11px] text-[var(--color-text-muted)]">
                      {event.source_name} · {humanize(event.category)}
                    </span>
                  </span>
                  <SeverityBadge severity={event.severity} />
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}

function ComponentTile({ component }: { readonly component: ComponentStatus }) {
  const tone = component.healthy
    ? "border-[var(--color-ok)] text-[var(--color-ok)]"
    : component.required
      ? "border-[var(--color-bad)] text-[var(--color-bad)]"
      : "border-[var(--color-warn)] text-[var(--color-warn)]";
  return (
    <li className="rounded border border-[var(--color-surface-border)] bg-[var(--color-surface-overlay)] p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[12px] font-semibold text-[var(--color-text-primary)]">
          {humanize(component.name)}
        </span>
        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase ${tone}`}>
          {component.healthy ? "healthy" : component.required ? "down" : "degraded"}
        </span>
      </div>
      <div className="mt-1 font-mono text-[11px] text-[var(--color-text-muted)]">{component.kind}</div>
      {component.detail && (
        <p className="mt-1 text-[11px] text-[var(--color-text-secondary)]">{component.detail}</p>
      )}
    </li>
  );
}

function countBySeverity(incidents: readonly Incident[]): Partial<Record<Severity, number>> {
  const counts: Partial<Record<Severity, number>> = {};
  for (const incident of incidents) {
    counts[incident.severity] = (counts[incident.severity] ?? 0) + 1;
  }
  return counts;
}
