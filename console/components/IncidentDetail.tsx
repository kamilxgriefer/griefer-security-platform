import Link from "next/link";

import { Card, EmptyState, Stat } from "@/components/Card";
import { EntityGraph } from "@/components/EntityGraph";
import {
  ActionStatusBadge,
  CriticalityBadge,
  PolicyEffectBadge,
  SeverityBadge,
  StatusBadge,
  TechniqueBadge,
} from "@/components/Badges";
import {
  formatConfidence,
  formatRelative,
  formatTimestamp,
  humanize,
  shortId,
} from "@/lib/format";
import type { Incident, RecommendedAction, ResponseAction } from "@/lib/types";

export function IncidentDetail({
  incident,
  actions,
}: {
  readonly incident: Incident;
  readonly actions: readonly ResponseAction[];
}) {
  const findings = incident.findings ?? [];
  const entities = incident.entities ?? [];
  const evidence = incident.evidence ?? [];
  const techniques = incident.attack_techniques ?? [];
  const recommended = incident.recommended_actions ?? [];
  const reachable = incident.blast_radius?.reachable ?? [];

  const decisionsByAction = new Map<string, ResponseAction>();
  for (const action of actions) {
    const existing = decisionsByAction.get(action.action_type);
    if (!existing || action.created_at > existing.created_at) {
      decisionsByAction.set(action.action_type, action);
    }
  }

  return (
    <div className="space-y-6">
      <nav aria-label="Breadcrumb" className="text-[12px] text-[var(--color-text-muted)]">
        <Link href="/incidents" className="text-[var(--color-brand)] no-underline">
          Incidents
        </Link>
        <span aria-hidden="true"> / </span>
        <span className="font-mono">{shortId(incident.id)}</span>
      </nav>

      <header className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold">{incident.title}</h1>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
            {incident.primary_identity && (
              <span className="font-mono text-[11px] text-[var(--color-text-muted)]">
                {incident.primary_identity}
              </span>
            )}
          </div>
        </div>
        <dl className="text-right text-[11px] text-[var(--color-text-muted)]">
          <div>
            <dt className="inline">First seen </dt>
            <dd className="inline text-[var(--color-text-secondary)]">
              {formatTimestamp(incident.first_seen)}
            </dd>
          </div>
          <div>
            <dt className="inline">Last activity </dt>
            <dd className="inline text-[var(--color-text-secondary)]">
              {formatRelative(incident.last_seen)}
            </dd>
          </div>
        </dl>
      </header>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat
          label="Risk score"
          value={incident.risk_score}
          hint="0–100, saturating"
          tone={incident.risk_score >= 70 ? "bad" : incident.risk_score >= 45 ? "warn" : "default"}
        />
        <Stat
          label="Confidence"
          value={formatConfidence(incident.confidence)}
          hint="capped at 95%"
        />
        <Stat
          label="Blast radius"
          value={incident.blast_radius?.score ?? 0}
          hint={`${incident.blast_radius?.critical_assets ?? 0} critical assets`}
          tone={(incident.blast_radius?.critical_assets ?? 0) > 0 ? "warn" : "default"}
        />
        <Stat
          label="Evidence"
          value={findings.length}
          hint={`${new Set(findings.map((f) => f.category)).size} independent categories`}
        />
      </div>

      {techniques.length > 0 && (
        <Card title="ATT&CK techniques" subtitle="Annotations for triage; not a coverage claim">
          <div className="flex flex-wrap gap-2">
            {techniques.map((technique) => (
              <TechniqueBadge
                key={technique.id}
                id={technique.id}
                name={technique.name}
                tactic={technique.tactic}
              />
            ))}
          </div>
        </Card>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Timeline" subtitle="Source events behind this incident, oldest first">
          {evidence.length === 0 ? (
            <EmptyState message="No evidence recorded." />
          ) : (
            <ol className="relative space-y-4 border-l border-[var(--color-surface-border-strong)] pl-5">
              {evidence.map((item) => (
                <li key={item.event_id} className="relative">
                  <span
                    aria-hidden="true"
                    className="absolute -left-[23px] top-1.5 h-2 w-2 rounded-full bg-[var(--color-brand)]"
                  />
                  <div className="text-[13px] text-[var(--color-text-primary)]">{item.summary}</div>
                  <div className="mt-0.5 flex flex-wrap gap-x-3 font-mono text-[11px] text-[var(--color-text-muted)]">
                    <span>{formatTimestamp(item.occurred_at)}</span>
                    <span>{item.source_name}</span>
                    <span>{item.category}</span>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </Card>

        <Card title="Findings" subtitle="One per detection rule that fired">
          {findings.length === 0 ? (
            <EmptyState message="No findings." />
          ) : (
            <ul className="space-y-3">
              {findings.map((finding) => (
                <li
                  key={finding.id}
                  className="rounded border border-[var(--color-surface-border)] bg-[var(--color-surface-overlay)] p-3"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <span className="text-[13px] font-medium">{finding.title}</span>
                    <span className="flex items-center gap-2">
                      <SeverityBadge severity={finding.severity} />
                      <span className="font-mono text-[11px] text-[var(--color-text-muted)]">
                        {finding.rule_id}
                      </span>
                    </span>
                  </div>
                  {finding.description && (
                    <p className="mt-1.5 text-[12px] leading-relaxed text-[var(--color-text-secondary)]">
                      {finding.description}
                    </p>
                  )}
                  <div className="mt-2 flex flex-wrap gap-x-4 text-[11px] text-[var(--color-text-muted)]">
                    <span>Category: {humanize(finding.category)}</span>
                    <span>Confidence: {formatConfidence(finding.confidence)}</span>
                    <span>{finding.event_ids?.length ?? 0} events</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card
        title="Blast radius"
        subtitle={incident.blast_radius?.summary}
      >
        <EntityGraph entities={entities} reachable={reachable} />
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Involved entities">
          {entities.length === 0 ? (
            <EmptyState message="No entities linked." />
          ) : (
            <ul className="divide-y divide-[var(--color-surface-border)]">
              {entities.map((entity) => (
                <li key={entity.id} className="flex items-center justify-between gap-3 py-2">
                  <span className="min-w-0">
                    <span className="block truncate text-[13px]">{entity.name || entity.id}</span>
                    <span className="font-mono text-[11px] text-[var(--color-text-muted)]">
                      {entity.type}
                    </span>
                  </span>
                  <CriticalityBadge criticality={entity.criticality} />
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Reachable within the graph" subtitle="What the compromised entities unlock">
          {reachable.filter((r) => r.hops > 0).length === 0 ? (
            <EmptyState message="Nothing beyond the entities already involved." />
          ) : (
            <ul className="divide-y divide-[var(--color-surface-border)]">
              {reachable
                .filter((r) => r.hops > 0)
                .map((item) => (
                  <li key={item.id} className="flex items-center justify-between gap-3 py-2">
                    <span className="min-w-0">
                      <span className="block truncate text-[13px]">{item.name || item.id}</span>
                      <span className="font-mono text-[11px] text-[var(--color-text-muted)]">
                        {item.type}
                        {item.via ? ` · via ${item.via}` : ""}
                      </span>
                    </span>
                    <span className="flex items-center gap-2">
                      <CriticalityBadge criticality={item.criticality} />
                      <span className="font-mono text-[11px] text-[var(--color-text-muted)]">
                        {item.hops} hop{item.hops === 1 ? "" : "s"}
                      </span>
                    </span>
                  </li>
                ))}
            </ul>
          )}
        </Card>
      </div>

      <Card
        title="Recommended actions"
        subtitle="Proposed by the correlation engine; authorised only by the Policy Kernel"
      >
        {recommended.length === 0 ? (
          <EmptyState message="No actions recommended." />
        ) : (
          <ul className="space-y-3">
            {recommended.map((action) => (
              <RecommendedActionRow
                key={action.action_type}
                action={action}
                decision={decisionsByAction.get(action.action_type)}
              />
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function RecommendedActionRow({
  action,
  decision,
}: {
  readonly action: RecommendedAction;
  readonly decision: ResponseAction | undefined;
}) {
  return (
    <li className="rounded border border-[var(--color-surface-border)] bg-[var(--color-surface-overlay)] p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-[13px] font-medium">{action.title || humanize(action.action_type)}</div>
          <div className="font-mono text-[11px] text-[var(--color-text-muted)]">
            {action.action_type}
            {action.target_entity_id ? ` → ${action.target_entity_id}` : ""}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {action.targets_critical_asset && (
            <span className="rounded border border-[var(--color-sev-critical)] px-1.5 py-0.5 text-[10px] font-bold uppercase text-[var(--color-sev-critical)]">
              critical asset
            </span>
          )}
          <span
            className={`rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase ${
              action.reversible
                ? "border-[var(--color-ok)] text-[var(--color-ok)]"
                : "border-[var(--color-warn)] text-[var(--color-warn)]"
            }`}
          >
            {action.reversible ? "reversible" : "not reversible"}
          </span>
          {decision && <ActionStatusBadge status={decision.status} />}
        </div>
      </div>

      {action.rationale && (
        <p className="mt-2 text-[12px] leading-relaxed text-[var(--color-text-secondary)]">
          {action.rationale}
        </p>
      )}

      <dl className="mt-2 grid gap-x-6 gap-y-1 text-[11px] sm:grid-cols-2">
        <div className="flex gap-2">
          <dt className="text-[var(--color-text-muted)]">Rollback</dt>
          <dd className="font-mono text-[var(--color-text-secondary)]">
            {action.rollback_action || "none defined — requires human approval"}
          </dd>
        </div>
        <div className="flex gap-2">
          <dt className="text-[var(--color-text-muted)]">Destructive</dt>
          <dd className="text-[var(--color-text-secondary)]">{action.destructive ? "yes" : "no"}</dd>
        </div>
      </dl>

      {decision?.policy_decision && (
        <div
          data-testid={`policy-decision-${action.action_type}`}
          className="mt-3 rounded border border-[var(--color-surface-border)] bg-[var(--color-surface-raised)] p-2.5"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)]">
              Policy Kernel
            </span>
            <PolicyEffectBadge effect={decision.policy_decision.effect} />
            <span className="font-mono text-[10px] text-[var(--color-text-muted)]">
              {decision.policy_decision.policy_package}@{decision.policy_decision.policy_version} ·{" "}
              {decision.policy_decision.engine}
            </span>
            {decision.policy_decision.fail_closed && (
              <span className="rounded border border-[var(--color-bad)] px-1.5 py-0.5 text-[10px] font-bold uppercase text-[var(--color-bad)]">
                fail-closed
              </span>
            )}
          </div>
          <ul className="mt-1.5 space-y-1">
            {decision.policy_decision.reasons.map((reason) => (
              <li key={reason} className="text-[12px] leading-relaxed text-[var(--color-text-secondary)]">
                {reason}
              </li>
            ))}
          </ul>
          {decision.simulated_effect && (
            <div className="mt-2 border-t border-[var(--color-surface-border)] pt-2">
              <p className="text-[12px] text-[var(--color-text-primary)]">
                <span className="font-semibold">Simulated: </span>
                {decision.simulated_effect.description}
              </p>
              <p className="mt-0.5 text-[11px] text-[var(--color-text-muted)]">
                {decision.simulated_effect.rollback_plan}
              </p>
            </div>
          )}
        </div>
      )}
    </li>
  );
}
