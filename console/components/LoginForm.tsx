"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

/**
 * The access gate.
 *
 * The form shows one neutral message for every failure. It never reports which
 * field was wrong, whether the account exists, or whether the gate is even
 * configured — all of which would narrow an attacker's search.
 */
export function LoginForm({ destination }: { readonly destination: string }) {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      if (response.ok) {
        /*
         * A full navigation is deliberate at an authentication boundary. A
         * client-side transition can serve a cached RSC payload rendered under
         * the previous session — showing the console to someone who just signed
         * out, or the login page to someone who just signed in.
         */
        window.location.assign(destination);
        return;
      }

      const body = (await response.json().catch(() => ({}))) as { error?: string };
      setError(body.error ?? "Invalid credentials.");
      setPassword("");
    } catch {
      setError("The console could not reach the sign-in service.");
    } finally {
      setBusy(false);
      router.refresh();
    }
  }

  return (
    <form
      onSubmit={onSubmit}
      className="rounded-lg border border-[var(--color-surface-border)] bg-[var(--color-surface-raised)] p-5"
    >
      <label className="block" htmlFor="username">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)]">
          Username
        </span>
        <input
          id="username"
          name="username"
          type="text"
          autoComplete="username"
          required
          value={username}
          onChange={(event) => setUsername(event.target.value)}
          className="mt-1.5 w-full rounded border border-[var(--color-surface-border-strong)] bg-[var(--color-surface-overlay)] px-3 py-2 font-mono text-[13px] text-[var(--color-text-primary)] outline-none focus:border-[var(--color-brand)]"
        />
      </label>

      <label className="mt-4 block" htmlFor="password">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)]">
          Password
        </span>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          maxLength={512}
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          className="mt-1.5 w-full rounded border border-[var(--color-surface-border-strong)] bg-[var(--color-surface-overlay)] px-3 py-2 font-mono text-[13px] text-[var(--color-text-primary)] outline-none focus:border-[var(--color-brand)]"
        />
      </label>

      {error && (
        <p
          role="alert"
          data-testid="login-error"
          className="mt-4 rounded border border-[var(--color-bad)] bg-[color-mix(in_srgb,var(--color-bad)_10%,transparent)] px-3 py-2 text-[12px] text-[var(--color-bad)]"
        >
          {error}
        </p>
      )}

      <button
        type="submit"
        disabled={busy}
        className="mt-5 w-full rounded bg-[var(--color-brand-dim)] px-3 py-2.5 text-[13px] font-semibold text-[var(--color-text-primary)] transition-opacity disabled:opacity-60"
      >
        {busy ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}
