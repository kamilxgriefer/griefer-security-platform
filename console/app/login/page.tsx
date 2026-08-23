import type { Metadata } from "next";

import { LoginForm } from "@/components/LoginForm";

export const metadata: Metadata = {
  // The root layout appends " — GRIEFER"; repeating it here produced
  // "Sign in — GRIEFER — GRIEFER" in the tab.
  title: "Sign in",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

export default async function LoginPage({
  searchParams,
}: {
  readonly searchParams: Promise<{ next?: string }>;
}) {
  const { next } = await searchParams;
  // Only a same-site absolute path is accepted, so the parameter cannot be
  // turned into an open redirect.
  const destination = next && /^\/(?!\/)[A-Za-z0-9/_\-.:]*$/.test(next) ? next : "/";

  return (
    <div className="flex min-h-[100dvh] flex-col items-center justify-center px-4 py-10">
      <div className="w-full max-w-[420px]">
        <header className="mb-6 text-center">
          <div className="font-mono text-[22px] font-bold tracking-[0.3em] text-[var(--color-brand)]">
            GRIEFER
          </div>
          <h1 className="mt-2 text-[15px] font-semibold text-[var(--color-text-primary)]">
            Restricted Demonstration Environment
          </h1>
          <p className="mt-1 text-[12px] uppercase tracking-wider text-[var(--color-text-muted)]">
            Simulation-only access
          </p>
        </header>

        <LoginForm destination={destination} />

        <div
          role="note"
          className="mt-5 rounded-lg border border-[var(--color-brand-dim)] bg-[color-mix(in_srgb,var(--color-brand)_8%,var(--color-surface-raised))] p-3.5"
        >
          <p className="text-[12px] leading-relaxed text-[var(--color-text-secondary)]">
            This environment contains synthetic security data only. No real response actions are
            executed.
          </p>
        </div>

        <p className="mt-5 text-center text-[11px] leading-relaxed text-[var(--color-text-muted)]">
          GRIEFER v0.1 — a research and engineering prototype exploring verifiable,
          policy-governed cyber defense. Not a production security service.
        </p>
      </div>
    </div>
  );
}
