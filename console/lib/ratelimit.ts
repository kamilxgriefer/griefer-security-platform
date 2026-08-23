import "server-only";

/**
 * In-memory attempt limiter for the login route.
 *
 * Deliberately simple and deliberately limited: it is per-process, so it does
 * not survive a restart and does not coordinate across replicas. That is
 * adequate for a single-instance demonstration and is NOT adequate for
 * production authentication — see docs/DEMO_SECURITY.md.
 */

interface Attempt {
  count: number;
  firstAt: number;
  blockedUntil: number;
}

const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 8;
const BLOCK_MS = 15 * 60 * 1000;

/** MAX_TRACKED bounds memory: without it, a caller rotating source addresses
 * turns the limiter into a leak. */
const MAX_TRACKED = 5_000;

const attempts = new Map<string, Attempt>();

function sweep(now: number): void {
  for (const [key, attempt] of attempts) {
    if (now > attempt.blockedUntil && now - attempt.firstAt > WINDOW_MS) {
      attempts.delete(key);
    }
  }
}

/** blockedFor returns the remaining block in seconds, or 0 when allowed. */
export function blockedFor(key: string, now = Date.now()): number {
  const attempt = attempts.get(key);
  if (!attempt || now >= attempt.blockedUntil) return 0;
  return Math.ceil((attempt.blockedUntil - now) / 1000);
}

/** recordFailure counts a failed attempt and blocks once the limit is reached. */
export function recordFailure(key: string, now = Date.now()): void {
  sweep(now);
  if (attempts.size >= MAX_TRACKED && !attempts.has(key)) return;

  const existing = attempts.get(key);
  if (!existing || now - existing.firstAt > WINDOW_MS) {
    attempts.set(key, { count: 1, firstAt: now, blockedUntil: 0 });
    return;
  }
  existing.count += 1;
  if (existing.count >= MAX_ATTEMPTS) {
    existing.blockedUntil = now + BLOCK_MS;
    existing.count = 0;
    existing.firstAt = now;
  }
}

/** recordSuccess clears the counter for a key. */
export function recordSuccess(key: string): void {
  attempts.delete(key);
}

/** resetAll clears all state. Test support only. */
export function resetAll(): void {
  attempts.clear();
}
