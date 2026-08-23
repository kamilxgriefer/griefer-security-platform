"use client";

import { useEffect } from "react";

/**
 * Route-level error boundary.
 *
 * The digest is shown rather than the error message: a rendering failure can
 * carry internal detail, and the console has no business relaying that to
 * whoever is looking at the screen. The digest is enough to find the matching
 * server log line.
 */
export default function ConsoleError({
  error,
  reset,
}: {
  readonly error: Error & { digest?: string };
  readonly reset: () => void;
}) {
  useEffect(() => {
    console.error("console render failed", error.digest ?? "no digest");
  }, [error]);

  return (
    <div
      role="alert"
      className="rounded-lg border border-[var(--color-bad)] bg-[color-mix(in_srgb,var(--color-bad)_10%,var(--color-surface-raised))] p-6"
    >
      <h1 className="text-[15px] font-semibold text-[var(--color-bad)]">
        The console could not render this page
      </h1>
      <p className="mt-2 text-[13px] text-[var(--color-text-secondary)]">
        This is a console fault, not an indication of the platform&apos;s state. Check the GRIEFER
        API directly before drawing conclusions about your environment.
      </p>
      {error.digest && (
        <p className="mt-2 font-mono text-[11px] text-[var(--color-text-muted)]">
          digest {error.digest}
        </p>
      )}
      <button
        type="button"
        onClick={reset}
        className="mt-4 rounded border border-[var(--color-surface-border-strong)] px-3 py-1.5 text-[13px] text-[var(--color-text-primary)]"
      >
        Try again
      </button>
    </div>
  );
}
