"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";

const LINKS = [
  { href: "/", label: "Dashboard" },
  { href: "/incidents", label: "Incidents" },
  { href: "/audit", label: "Audit trail" },
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
export function Nav() {
  const pathname = usePathname() ?? "/";
  const [open, setOpen] = useState(false);

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
          {LINKS.map((link) => (
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
          {LINKS.map((link) => (
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
        </ul>
      )}
    </nav>
  );
}
