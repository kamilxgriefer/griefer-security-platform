import "server-only";

/**
 * In-memory attempt limiter for the login route.
 *
 * Deliberately simple and deliberately limited: it is per-process, so it does
 * not survive a restart and does not coordinate across replicas. That is
 * adequate for a single-instance demonstration and is NOT adequate for
 * production authentication — see docs/security/CONSOLE_GATE.md.
 *
 * It counts on two axes, and the second one is what makes the first worth
 * anything. The caller key comes from X-Forwarded-For, which the caller
 * supplies, so an attacker rotating that header gets a fresh budget on every
 * request and the per-caller limit stops nothing. The account key is the
 * username being attempted, and someone guessing the administrator's password
 * has to keep attempting the administrator.
 */

interface Attempt {
  count: number;
  firstAt: number;
  blockedUntil: number;
}

interface Policy {
  windowMs: number;
  maxAttempts: number;
  blockMs: number;
}

/** Per caller: strict, because a caller key is cheap to rotate and cheap to block. */
const CALLER: Policy = {
  windowMs: 15 * 60 * 1000,
  maxAttempts: 8,
  blockMs: 15 * 60 * 1000,
};

/**
 * Per account: looser, and deliberately so.
 *
 * This axis cannot be rotated away, which is the point — and it also means
 * anyone can lock the administrator out by failing against that username on
 * purpose. That trade is accepted with the numbers chosen to reflect it: a
 * higher budget so ordinary fat-fingering never reaches it, and a short block
 * so a denial costs minutes rather than a shift.
 *
 * The asymmetry is the reasoning. An administrator locked out for five minutes
 * is recoverable and visible; an administrator password guessed is neither.
 */
const ACCOUNT: Policy = {
  windowMs: 15 * 60 * 1000,
  maxAttempts: 25,
  blockMs: 5 * 60 * 1000,
};

/** MAX_TRACKED bounds memory: without it, a caller rotating source addresses
 * turns the limiter into a leak. */
const MAX_TRACKED = 5_000;

const attempts = new Map<string, Attempt>();

function sweep(now: number): void {
  for (const [key, attempt] of attempts) {
    if (now > attempt.blockedUntil && now - attempt.firstAt > CALLER.windowMs) {
      attempts.delete(key);
    }
  }
}

/** accountKey namespaces an account so it cannot collide with a caller key. */
export function accountKey(username: string): string {
  return "account:" + username.trim().toLowerCase().slice(0, 64);
}

function blocked(key: string, now: number): number {
  const attempt = attempts.get(key);
  if (!attempt || now >= attempt.blockedUntil) return 0;
  return Math.ceil((attempt.blockedUntil - now) / 1000);
}

function fail(key: string, policy: Policy, now: number): void {
  sweep(now);
  if (attempts.size >= MAX_TRACKED && !attempts.has(key)) return;

  const existing = attempts.get(key);
  if (!existing || now - existing.firstAt > policy.windowMs) {
    attempts.set(key, { count: 1, firstAt: now, blockedUntil: 0 });
    return;
  }
  existing.count += 1;
  if (existing.count >= policy.maxAttempts) {
    existing.blockedUntil = now + policy.blockMs;
    existing.count = 0;
    existing.firstAt = now;
  }
}

/** blockedFor returns the remaining block in seconds, or 0 when allowed. */
export function blockedFor(key: string, now = Date.now()): number {
  return blocked(key, now);
}

/** recordFailure counts a failed attempt against the caller budget. */
export function recordFailure(key: string, now = Date.now()): void {
  fail(key, CALLER, now);
}

/**
 * recordAccountFailure counts a failed attempt against the account budget.
 *
 * Called with the username that was attempted, whether or not that account
 * exists — otherwise the response time would say which usernames are real.
 */
export function recordAccountFailure(key: string, now = Date.now()): void {
  fail(key, ACCOUNT, now);
}

/** recordSuccess clears the counter for a key. */
export function recordSuccess(key: string): void {
  attempts.delete(key);
}

/** resetAll clears all state. Test support only. */
export function resetAll(): void {
  attempts.clear();
}
