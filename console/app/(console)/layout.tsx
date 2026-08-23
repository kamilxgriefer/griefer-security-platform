import type { ReactNode } from "react";

import { Nav } from "@/components/Nav";
import { SimulationBanner } from "@/components/SimulationBanner";
import { currentSession } from "@/lib/currentSession";

/**
 * Layout for every page behind the access gate.
 *
 * middleware.ts guarantees a valid session before any of this renders, so the
 * chrome — and the incident data inside it — never reaches an anonymous
 * visitor.
 */
export default async function ConsoleLayout({ children }: { readonly children: ReactNode }) {
  // middleware.ts has already established that this is a valid session, so the
  // null branch is unreachable in practice. It is handled rather than asserted
  // because an unreachable assertion becomes a crashed page the day the
  // matcher changes.
  const session = await currentSession();

  return (
    <>
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded focus:bg-[var(--color-surface-overlay)] focus:px-3 focus:py-2"
      >
        Skip to content
      </a>
      <SimulationBanner />
      <Nav username={session?.username ?? null} role={session?.role ?? null} />
      <main id="main" className="mx-auto w-full max-w-[1400px] px-4 py-6 sm:px-6">
        {children}
      </main>
      <footer className="mx-auto w-full max-w-[1400px] px-4 pb-8 text-[11px] text-[var(--color-text-muted)] sm:px-6">
        GRIEFER v0.1 — a research and engineering prototype. All data shown is synthetic.
      </footer>
    </>
  );
}
