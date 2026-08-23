"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";

import { mayAccess, roleLabel, type Role } from "@/lib/roles";

const LINKS = [
  { href: "/", label: "Dashboard" },
  { href: "/incidents", label: "Incidents" },
  { href: "/audit", label: "Audit trail" },
  { href: "/admin/users", label: "Accounts" },
] as const;

function isActive(pathname: string, href: string): boolean {
  if (href === "/") return pathname === "/";
  return pathname === href || pathname.startsWith(`${href}/`);
}

/**
 * Nav is the console's primary navigation.
 *
 * On a wide screen the links sit inline. Below the `sm` breakpoint they collapse
 * behind a disclosure button, because a SOC console is read on a phone during a
 * callout at least as often as at a desk.
 */
export function Nav({
  username,
  role,
}: {
  readonly username: string | null;
  readonly role: Role | null;
}) {
  const pathname = usePathname() ?? "/";
  const [open, setOpen] = useState(false);

  // The same rules the middleware enforces, reused rather than restated. A
  // second hand-written list of administrator paths would be one edit away
  // from showing a link that answers "forbidden".
  const links = role ? LINKS.filter((link) => mayAccess(role, link.href)) : [];

  return (
    <nav
      aria-label="Primary"
      className="border-b border-[var(--color-surface-border)] bg-[var(--color-surface-raised)]"
    >
      <div className="flex items-center justify-between gap-4 px-4 py-3 sm:px-6">
        <Link href="/" className="flex items-baseline gap-2 no-underline">
          <span className="font-mono text-[15px] font-bold tracking-widest text-[var(--color-brand)]">
            GRIEFER
          </span>
          <span className="hidden text-[11px] text-[var(--color-text-muted)] md:inline">
            See the attack. Contain the blast. Prove the defense.
          </span>
        </Link>

        <ul className="hidden items-center gap-1 sm:flex">
          {links.map((link) => (
            <li key={link.href}>
              <Link
                href={link.href}
                aria-current={isActive(pathname, link.href) ? "page" : undefined}
                className={`rounded px-3 py-1.5 text-[13px] no-underline transition-colors ${
                  isActive(pathname, link.href)
                    ? "bg-[var(--color-surface-overlay)] text-[var(--color-text-primary)]"
                    : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                }`}
              >
                {link.label}
              </Link>
            </li>
          ))}
          <li className="ml-2 flex items-center gap-3 border-l border-[var(--color-surface-border)] pl-3">
            {username && role && <Identity username={username} role={role} />}
            <SignOutButton />
          </li>
        </ul>

        <button
          type="button"
          onClick={() => setOpen((value) => !value)}
          aria-expanded={open}
          aria-controls="primary-navigation-mobile"
          aria-label={open ? "Close navigation" : "Open navigation"}
          className="rounded border border-[var(--color-surface-border-strong)] px-3 py-1.5 text-[13px] text-[var(--color-text-secondary)] sm:hidden"
        >
          {open ? "Close" : "Menu"}
        </button>
      </div>

      {open && (
        <ul
          id="primary-navigation-mobile"
          className="border-t border-[var(--color-surface-border)] px-4 pb-3 sm:hidden"
        >
          {links.map((link) => (
            <li key={link.href}>
              <Link
                href={link.href}
                onClick={() => setOpen(false)}
                aria-current={isActive(pathname, link.href) ? "page" : undefined}
                className={`block border-b border-[var(--color-surface-border)] py-2.5 text-[14px] no-underline ${
                  isActive(pathname, link.href)
                    ? "text-[var(--color-brand)]"
                    : "text-[var(--color-text-secondary)]"
                }`}
              >
                {link.label}
              </Link>
            </li>
          ))}
          <li className="flex items-center justify-between gap-3 pt-3">
            {username && role && <Identity username={username} role={role} />}
            <SignOutButton />
          </li>
        </ul>
      )}
    </nav>
  );
}

/**
 * Who is signed in, and as what.
 *
 * The role is shown rather than left to be inferred from which links happen to
 * be present. Someone who cannot see the audit trail should be able to tell at
 * a glance that this is their role, not an outage.
 */
function Identity({ username, role }: { readonly username: string; readonly role: Role }) {
  return (
    <span className="flex items-baseline gap-1.5 text-[12px] leading-none">
      <span className="text-[var(--color-text-secondary)]">{username}</span>
      <span
        className={`rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider ${
          role === "admin"
            ? "bg-[var(--color-brand-dim)] text-[var(--color-brand-bright)]"
            : "bg-[var(--color-surface-overlay)] text-[var(--color-text-muted)]"
        }`}
      >
        {roleLabel(role)}
      </span>
    </span>
  );
}

/**
 * Sign out.
 *
 * A POST, not a link: logout changes state, and a GET endpoint that ends a
 * session can be triggered by any page that can get the browser to load a URL.
 */
function SignOutButton() {
  const [busy, setBusy] = useState(false);

  async function signOut() {
    setBusy(true);
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } finally {
      /*
       * A full navigation is deliberate at an authentication boundary. A
       * client-side transition can serve a cached RSC payload rendered under
       * the previous session — showing the console to someone who just signed
       * out, or the login page to someone who just signed in.
       */
      // eslint-disable-next-line @next/next/no-location-assign-relative-destination
      window.location.assign("/login");
    }
  }

  return (
    <button
      type="button"
      onClick={signOut}
      disabled={busy}
      className="rounded border border-[var(--color-surface-border-strong)] px-3 py-1.5 text-[13px] text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)] disabled:opacity-60"
    >
      {busy ? "Signing out…" : "Sign out"}
    </button>
  );
}
