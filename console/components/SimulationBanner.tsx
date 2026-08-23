/**
 * SimulationBanner is rendered on every page of the console.
 *
 * v0.1 evaluates response actions and describes what they would do; it never
 * carries them out. An analyst who forgets that would draw exactly the wrong
 * conclusion from a screen full of green "simulated" verdicts, so the statement
 * is part of the frame rather than something to be discovered in a tooltip.
 */
export function SimulationBanner() {
  return (
    <div
      role="status"
      aria-live="polite"
      data-testid="simulation-banner"
      className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-[var(--color-brand-dim)] bg-[color-mix(in_srgb,var(--color-brand)_10%,var(--color-surface-base))] px-4 py-2 text-[12px] sm:px-6"
    >
      <span className="rounded bg-[var(--color-brand-dim)] px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-widest text-[var(--color-text-primary)]">
        Simulation only
      </span>
      <span className="text-[var(--color-text-secondary)]">
        Response actions are evaluated and simulated. GRIEFER v0.1 does not contact identity
        providers, endpoints or cloud platforms.
      </span>
    </div>
  );
}
