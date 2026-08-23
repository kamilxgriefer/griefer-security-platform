/**
 * ErrorPanel explains a failed API call without pretending the data is merely
 * empty. An analyst must be able to tell "there are no incidents" from "the
 * console cannot see the platform" — those call for opposite reactions.
 */
export function ErrorPanel({
  title,
  message,
  code,
  requestId,
}: {
  readonly title: string;
  readonly message: string;
  readonly code?: string;
  readonly requestId?: string | undefined;
}) {
  return (
    <div
      role="alert"
      data-testid="error-panel"
      className="rounded-lg border border-[var(--color-bad)] bg-[color-mix(in_srgb,var(--color-bad)_10%,var(--color-surface-raised))] p-4"
    >
      <h3 className="text-[13px] font-semibold text-[var(--color-bad)]">{title}</h3>
      <p className="mt-1 text-[13px] text-[var(--color-text-secondary)]">{message}</p>
      {(code || requestId) && (
        <dl className="mt-2 flex flex-wrap gap-x-6 gap-y-1 font-mono text-[11px] text-[var(--color-text-muted)]">
          {code && (
            <div className="flex gap-1.5">
              <dt>code</dt>
              <dd className="text-[var(--color-text-secondary)]">{code}</dd>
            </div>
          )}
          {requestId && (
            <div className="flex gap-1.5">
              <dt>request_id</dt>
              <dd className="text-[var(--color-text-secondary)]">{requestId}</dd>
            </div>
          )}
        </dl>
      )}
    </div>
  );
}
