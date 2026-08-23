import type { ReactNode } from "react";

export function Card({
  title,
  subtitle,
  actions,
  children,
  className = "",
}: {
  readonly title?: string;
  readonly subtitle?: string;
  readonly actions?: ReactNode;
  readonly children: ReactNode;
  readonly className?: string;
}) {
  return (
    <section
      className={`rounded-lg border border-[var(--color-surface-border)] bg-[var(--color-surface-raised)] ${className}`}
    >
      {(title || actions) && (
        <header className="flex flex-wrap items-baseline justify-between gap-2 border-b border-[var(--color-surface-border)] px-4 py-3">
          <div>
            {title && (
              <h2 className="text-[13px] font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
                {title}
              </h2>
            )}
            {subtitle && <p className="mt-0.5 text-[12px] text-[var(--color-text-muted)]">{subtitle}</p>}
          </div>
          {actions}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

/** slug turns a human label into a stable test hook. */
function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

export function Stat({
  label,
  value,
  hint,
  tone = "default",
}: {
  readonly label: string;
  readonly value: string | number;
  readonly hint?: string;
  readonly tone?: "default" | "good" | "warn" | "bad";
}) {
  const toneClass =
    tone === "good"
      ? "text-[var(--color-ok)]"
      : tone === "warn"
        ? "text-[var(--color-warn)]"
        : tone === "bad"
          ? "text-[var(--color-bad)]"
          : "text-[var(--color-text-primary)]";
  return (
    <div
      data-testid={`stat-${slug(label)}`}
      className="rounded-lg border border-[var(--color-surface-border)] bg-[var(--color-surface-raised)] px-4 py-3"
    >
      <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)]">
        {label}
      </div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${toneClass}`}>{value}</div>
      {hint && <div className="mt-0.5 text-[11px] text-[var(--color-text-muted)]">{hint}</div>}
    </div>
  );
}

export function EmptyState({ message }: { readonly message: string }) {
  return (
    <p className="py-6 text-center text-[13px] text-[var(--color-text-muted)]">{message}</p>
  );
}
