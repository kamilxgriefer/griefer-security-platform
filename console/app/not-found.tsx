import Link from "next/link";

export default function NotFound() {
  return (
    <div className="rounded-lg border border-[var(--color-surface-border)] bg-[var(--color-surface-raised)] p-8 text-center">
      <h1 className="text-lg font-semibold">Not found</h1>
      <p className="mt-2 text-[13px] text-[var(--color-text-secondary)]">
        No such page or incident.
      </p>
      <Link href="/" className="mt-4 inline-block text-[13px] text-[var(--color-brand)]">
        Back to the dashboard
      </Link>
    </div>
  );
}
