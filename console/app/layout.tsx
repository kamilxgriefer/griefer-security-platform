import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";

import "./globals.css";

export const metadata: Metadata = {
  // Resolves the relative asset paths below. Without it Next.js emits relative
  // Open Graph URLs, which every crawler that matters refuses to follow.
  metadataBase: new URL("https://griefer.app"),
  title: {
    default: "GRIEFER Console",
    template: "%s — GRIEFER",
  },
  applicationName: "GRIEFER",
  description:
    "Analyst console for GRIEFER — a research prototype exploring verifiable, policy-governed cyber defense. Response actions are simulated.",
  // The console shows security data behind an access gate. It should never be
  // indexed, and this is the last line of that argument rather than the first:
  // the gate is.
  robots: { index: false, follow: false, nocache: true },
  manifest: "/site.webmanifest",
  icons: {
    icon: [
      // SVG first: browsers that understand it scale it themselves and ignore
      // the rest.
      { url: "/favicon.svg", type: "image/svg+xml" },
      { url: "/favicon-32x32.png", sizes: "32x32", type: "image/png" },
      { url: "/favicon-16x16.png", sizes: "16x16", type: "image/png" },
      { url: "/favicon.ico", sizes: "any" },
    ],
    apple: [{ url: "/apple-touch-icon.png", sizes: "180x180", type: "image/png" }],
    other: [{ rel: "mask-icon", url: "/safari-pinned-tab.svg", color: "#1AD7CE" }],
  },
  appleWebApp: {
    capable: true,
    title: "GRIEFER",
    // The console's own chrome is dark; a translucent bar would let the page
    // scroll under the status bar.
    statusBarStyle: "black-translucent",
  },
  openGraph: {
    type: "website",
    siteName: "GRIEFER",
    title: "GRIEFER Console",
    description:
      "Graph-based Resilient Intelligence Engine for Enforcement & Response. Simulation-only research platform.",
    images: [{ url: "/og-image.png", width: 1200, height: 630, alt: "GRIEFER" }],
  },
  twitter: {
    card: "summary_large_image",
    title: "GRIEFER Console",
    description:
      "Graph-based Resilient Intelligence Engine for Enforcement & Response. Simulation-only research platform.",
    images: ["/og-image.png"],
  },
  formatDetection: { telephone: false, email: false, address: false },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  // Matches --color-surface-base, so the browser chrome continues the app
  // rather than framing it.
  themeColor: "#08090C",
};

/**
 * The root layout is the document shell and nothing else.
 *
 * Navigation, the simulation banner and the page frame live in the (console)
 * route group, so the sign-in page — the only route an unauthenticated visitor
 * can reach — renders without them and cannot leak the shape of the
 * application behind the gate.
 */
export default function RootLayout({ children }: { readonly children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
