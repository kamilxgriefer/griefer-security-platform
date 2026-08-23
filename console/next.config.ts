import type { NextConfig } from "next";

const isProduction = process.env.NODE_ENV === "production";

/**
 * React's development build uses eval() for debugging features such as
 * reconstructing call stacks. Production React never does. The relaxation is
 * therefore scoped to development rather than weakening the shipped policy,
 * and a production build always emits the strict directive.
 */
const scriptSrc = isProduction
  ? "script-src 'self' 'unsafe-inline'"
  : "script-src 'self' 'unsafe-inline' 'unsafe-eval'";

/**
 * The browser never talks to the GRIEFER API directly — every fetch happens in
 * a React Server Component — so a production console needs no outbound origin
 * at all. Development additionally needs the hot-reload WebSocket.
 */
const connectSrc = isProduction ? "connect-src 'self'" : "connect-src 'self' ws: wss:";

const config: NextConfig = {
  // The Compose image runs `node server.js`; standalone output ships only the
  // server and the files it actually imports, keeping the build toolchain out
  // of the runtime image.
  output: "standalone",
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
          {
            key: "Content-Security-Policy",
            // The console renders server-side and ships no third-party script,
            // font or image. 'unsafe-inline' on style-src is required by
            // Next.js's inlined critical CSS.
            value: [
              "default-src 'self'",
              scriptSrc,
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data:",
              "font-src 'self'",
              connectSrc,
              "frame-ancestors 'none'",
              "base-uri 'self'",
              "form-action 'self'",
            ].join("; "),
          },
        ],
      },
    ];
  },
};

export default config;
