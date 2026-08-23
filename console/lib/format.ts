import type { Criticality, Severity } from "./types";

/** Severity ordering, used for sorting and for the dashboard breakdown. */
export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  informational: 0,
};

export function severityRank(severity: Severity): number {
  return SEVERITY_RANK[severity] ?? 0;
}

const CRITICALITY_RANK: Record<Criticality, number> = {
  critical: 3,
  high: 2,
  medium: 1,
  low: 0,
};

export function criticalityRank(criticality: Criticality): number {
  return CRITICALITY_RANK[criticality] ?? 1;
}

/** formatTimestamp renders an ISO timestamp in UTC. GRIEFER stores UTC, and a
 * console that silently converts to a viewer's local zone makes two analysts
 * describing the same incident disagree about when it happened. */
export function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "unknown";
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} UTC`
  );
}

/** formatTime renders just the clock portion, for dense timelines. */
export function formatTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "--:--:--";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`;
}

export function formatRelative(iso: string, now: Date = new Date()): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "unknown";
  const seconds = Math.round((now.getTime() - date.getTime()) / 1000);
  if (seconds < 0) return "in the future";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export function formatConfidence(confidence: number): string {
  return `${Math.round(confidence * 100)}%`;
}

/** humanize turns a snake_case identifier into readable text. */
export function humanize(value: string): string {
  if (!value) return "";
  const spaced = value.replace(/[_.]/g, " ").trim();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

/** shortId trims a long GRIEFER identifier for dense tables while keeping the
 * type prefix, which is the part an analyst actually reads. */
export function shortId(id: string): string {
  const separator = id.indexOf("-");
  if (separator < 0 || id.length <= 16) return id;
  return `${id.slice(0, separator)}-${id.slice(separator + 1, separator + 9)}`;
}
