import type { ActionStatus, Criticality, IncidentStatus, PolicyEffect, Severity } from "@/lib/types";
import { humanize } from "@/lib/format";

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "border-[var(--color-sev-critical)] text-[var(--color-sev-critical)] bg-[color-mix(in_srgb,var(--color-sev-critical)_14%,transparent)]",
  high: "border-[var(--color-sev-high)] text-[var(--color-sev-high)] bg-[color-mix(in_srgb,var(--color-sev-high)_14%,transparent)]",
  medium: "border-[var(--color-sev-medium)] text-[var(--color-sev-medium)] bg-[color-mix(in_srgb,var(--color-sev-medium)_14%,transparent)]",
  low: "border-[var(--color-sev-low)] text-[var(--color-sev-low)] bg-[color-mix(in_srgb,var(--color-sev-low)_14%,transparent)]",
  informational: "border-[var(--color-sev-info)] text-[var(--color-sev-info)] bg-[color-mix(in_srgb,var(--color-sev-info)_14%,transparent)]",
};

const baseBadge =
  "inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide whitespace-nowrap";

export function SeverityBadge({ severity }: { readonly severity: Severity }) {
  return (
    <span className={`${baseBadge} ${SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.informational}`}>
      {severity}
    </span>
  );
}

const CRITICALITY_STYLES: Record<Criticality, string> = {
  critical: "border-[var(--color-sev-critical)] text-[var(--color-sev-critical)]",
  high: "border-[var(--color-sev-high)] text-[var(--color-sev-high)]",
  medium: "border-[var(--color-surface-border-strong)] text-[var(--color-text-secondary)]",
  low: "border-[var(--color-surface-border)] text-[var(--color-text-muted)]",
};

export function CriticalityBadge({ criticality }: { readonly criticality: Criticality }) {
  return (
    <span className={`${baseBadge} ${CRITICALITY_STYLES[criticality] ?? CRITICALITY_STYLES.medium}`}>
      {criticality}
    </span>
  );
}

const STATUS_STYLES: Record<IncidentStatus, string> = {
  open: "border-[var(--color-sev-high)] text-[var(--color-sev-high)]",
  investigating: "border-[var(--color-brand)] text-[var(--color-brand)]",
  contained: "border-[var(--color-ok)] text-[var(--color-ok)]",
  closed: "border-[var(--color-surface-border-strong)] text-[var(--color-text-muted)]",
};

export function StatusBadge({ status }: { readonly status: IncidentStatus }) {
  return <span className={`${baseBadge} ${STATUS_STYLES[status] ?? STATUS_STYLES.open}`}>{status}</span>;
}

const EFFECT_STYLES: Record<PolicyEffect, string> = {
  allow: "border-[var(--color-ok)] text-[var(--color-ok)]",
  deny: "border-[var(--color-bad)] text-[var(--color-bad)]",
  require_approval: "border-[var(--color-warn)] text-[var(--color-warn)]",
};

export function PolicyEffectBadge({ effect }: { readonly effect: PolicyEffect }) {
  return (
    <span className={`${baseBadge} ${EFFECT_STYLES[effect] ?? EFFECT_STYLES.deny}`}>
      {humanize(effect)}
    </span>
  );
}

const ACTION_STATUS_STYLES: Record<ActionStatus, string> = {
  simulated: "border-[var(--color-ok)] text-[var(--color-ok)]",
  requires_approval: "border-[var(--color-warn)] text-[var(--color-warn)]",
  denied: "border-[var(--color-bad)] text-[var(--color-bad)]",
  rejected: "border-[var(--color-bad)] text-[var(--color-bad)]",
};

export function ActionStatusBadge({ status }: { readonly status: ActionStatus }) {
  return (
    <span className={`${baseBadge} ${ACTION_STATUS_STYLES[status] ?? ACTION_STATUS_STYLES.denied}`}>
      {humanize(status)}
    </span>
  );
}

/** TechniqueBadge renders a MITRE ATT&CK annotation. GRIEFER records techniques
 * to make an incident legible; it does not claim automated coverage scoring. */
export function TechniqueBadge({
  id,
  name,
  tactic,
}: {
  readonly id: string;
  readonly name: string;
  readonly tactic?: string | undefined;
}) {
  return (
    <span
      title={tactic ? `${name} — ${tactic}` : name}
      className="inline-flex items-center gap-1.5 rounded border border-[var(--color-surface-border-strong)] bg-[var(--color-surface-overlay)] px-2 py-0.5 text-[11px]"
    >
      <span className="font-mono font-semibold text-[var(--color-brand)]">{id}</span>
      <span className="text-[var(--color-text-secondary)]">{name}</span>
    </span>
  );
}
