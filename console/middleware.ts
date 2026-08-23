import { NextResponse, type NextRequest } from "next/server";

import { SESSION_COOKIE, verify } from "@/lib/session";

/**
 * Route protection for the whole console.
 *
 * Everything is behind the gate by default. The exemptions below are an
 * allowlist, not a denylist, so a new page is protected the moment it is added
 * rather than the moment someone remembers to protect it.
 *
 * This runs on the Edge runtime, which is why session verification uses Web
 * Crypto (see lib/session.ts) and password checking happens elsewhere.
 */

const PUBLIC_PATHS = new Set(["/login", "/api/auth/login", "/api/health"]);

function isPublic(pathname: string): boolean {
  return PUBLIC_PATHS.has(pathname);
}

export async function middleware(request: NextRequest): Promise<NextResponse> {
  const { pathname } = request.nextUrl;

  const secret = process.env.DEMO_SESSION_SECRET ?? "";
  const session = await verify(request.cookies.get(SESSION_COOKIE)?.value, secret);

  if (session) {
    // A signed-in visitor has no reason to see the login form.
    if (pathname === "/login") {
      return NextResponse.redirect(new URL("/", request.url));
    }
    return NextResponse.next();
  }

  if (isPublic(pathname)) {
    return NextResponse.next();
  }

  // An unauthenticated API call gets a status code, not a redirect to HTML —
  // a fetch() that receives a 200 page of login markup is far harder to debug
  // than one that receives 401.
  if (pathname.startsWith("/api/")) {
    return NextResponse.json(
      { error: { code: "unauthorized", message: "Authentication is required." } },
      { status: 401 },
    );
  }

  const login = new URL("/login", request.url);
  // Only a same-site path is preserved, so the login page cannot be turned into
  // an open redirect.
  if (pathname !== "/" && !pathname.startsWith("//")) {
    login.searchParams.set("next", pathname);
  }
  return NextResponse.redirect(login);
}

export const config = {
  /**
   * Everything except Next's own asset routes and the favicon. Static assets
   * carry no incident data, and gating them would break the login page itself.
   */
  matcher: ["/((?!_next/static|_next/image|favicon.ico|robots.txt).*)"],
};
