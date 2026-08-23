"use client";

import { useState } from "react";

import { PolicyEffectBadge } from "@/components/Badges";
import type { ResponseAction } from "@/lib/types";

/**
 * Ask the Policy Kernel to judge this action again, now.
 *
 * The request goes to the console's own server-side gateway, never to the
 * GRIEFER API: the API has no public address and its host name only resolves
 * inside the private network. The gateway authenticates the session, forwards
 * one allowlisted endpoint, and attaches the service credential — none of which
 * the browser ever sees.
 *
 * The result is a decision and, when policy permits it, a description of what
 * the action WOULD have done. Nothing is executed.
 */
export function EvaluateAction({
  incidentId,
  actionType,
}: {
  readonly incidentId: string;
  readonly actionType: string;
}) {
  const [result, setResult] = useState<ResponseAction | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function evaluate() {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/griefer/actions/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          incident_id: incidentId,
          action_type: actionType,
          mode: "simulate",
          requested_by: "console:demo",
          automated: false,
        }),
      });

      if (response.status === 401) {
        /*
         * A full navigation is deliberate at an authentication boundary. A
         * client-side transition can serve a cached RSC payload rendered under
         * the previous session — showing the console to someone who just signed
         * out, or the login page to someone who just signed in.
         */
        // eslint-disable-next-line @next/next/no-location-assign-relative-destination
        window.location.assign("/login");
        return;
      }
      const body = (await response.json()) as ResponseAction & {
        error?: { message?: string };
      };
      if (!response.ok) {
        setError(body.error?.message ?? "The Policy Kernel could not be reached.");
        return;
      }
      setResult(body);
    } catch {
      setError("The Policy Kernel could not be reached.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-3">
      <button
        type="button"
        onClick={evaluate}
        disabled={busy}
        data-testid={`evaluate-${actionType}`}
        className="rounded border border-[var(--color-surface-border-strong)] px-2.5 py-1 text-[11px] font-semibold text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)] disabled:opacity-60"
      >
        {busy ? "Evaluating…" : "Re-evaluate with the Policy Kernel"}
      </button>

      {error && (
        <p role="alert" className="mt-2 text-[12px] text-[var(--color-bad)]">
          {error}
        </p>
      )}

      {result?.policy_decision && (
        <div
          data-testid={`evaluation-${actionType}`}
          className="mt-2 rounded border border-[var(--color-surface-border)] bg-[var(--color-surface-raised)] p-2.5"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)]">
              Live decision
            </span>
            <PolicyEffectBadge effect={result.policy_decision.effect} />
            <span className="font-mono text-[10px] text-[var(--color-text-muted)]">
              {result.policy_decision.policy_package}@{result.policy_decision.policy_version} ·{" "}
              {result.policy_decision.engine}
            </span>
            {result.policy_decision.fail_closed && (
              <span className="rounded border border-[var(--color-bad)] px-1.5 py-0.5 text-[10px] font-bold uppercase text-[var(--color-bad)]">
                fail-closed
              </span>
            )}
          </div>
          <ul className="mt-1.5 space-y-1">
            {result.policy_decision.reasons.map((reason) => (
              <li key={reason} className="text-[12px] leading-relaxed text-[var(--color-text-secondary)]">
                {reason}
              </li>
            ))}
          </ul>
          {result.simulated_effect && (
            <p className="mt-2 border-t border-[var(--color-surface-border)] pt-2 text-[12px] text-[var(--color-text-primary)]">
              <span className="font-semibold">Simulated: </span>
              {result.simulated_effect.description}
            </p>
          )}
          <p className="mt-1.5 text-[11px] text-[var(--color-text-muted)]">
            Evaluated only. GRIEFER v0.1 contacts no external system.
          </p>
        </div>
      )}
    </div>
  );
}
