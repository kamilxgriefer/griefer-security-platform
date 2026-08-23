import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";

import { Nav } from "@/components/Nav";
import { SimulationBanner } from "@/components/SimulationBanner";

import "./globals.css";

export const metadata: Metadata = {
  title: "GRIEFER Console",
  description:
    "Analyst console for GRIEFER — a research prototype exploring verifiable, policy-governed cyber defense. Response actions are simulated.",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#08090c",
};

export default function RootLayout({ children }: { readonly children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded focus:bg-[var(--color-surface-overlay)] focus:px-3 focus:py-2"
        >
          Skip to content
        </a>
        <SimulationBanner />
        <Nav />
        <main id="main" className="mx-auto w-full max-w-[1400px] px-4 py-6 sm:px-6">
          {children}
        </main>
        <footer className="mx-auto w-full max-w-[1400px] px-4 pb-8 text-[11px] text-[var(--color-text-muted)] sm:px-6">
          GRIEFER v0.1 — a research and engineering prototype. All data shown is synthetic.
        </footer>
      </body>
    </html>
  );
}
