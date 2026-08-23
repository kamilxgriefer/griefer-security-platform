import "server-only";

import {
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
  type ScryptOptions,
} from "node:crypto";

/**
 * promisify loses scrypt's four-argument overload, so the wrapper is written
 * out. Passing the cost parameters explicitly is the point — the defaults are
 * far too cheap for a password.
 */
function scrypt(
  password: string,
  salt: Buffer,
  keylen: number,
  options: ScryptOptions,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(password, salt, keylen, options, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

/**
 * scrypt parameters.
 *
 * N=2^15 with r=8 costs roughly 100 ms per attempt on a small container — slow
 * enough that guessing is expensive, fast enough that a real login does not
 * feel broken. They are recorded here rather than inferred from the stored
 * hash, so changing them is a deliberate edit with a visible diff.
 *
 * maxmem is set explicitly and is NOT optional. scrypt needs roughly
 * 128 * N * r bytes — 32 MiB at these settings — and Node's default maxmem is
 * exactly 32 MiB, so the derivation fails with "memory limit exceeded" and
 * every login is rejected. The failure looks like a wrong password, which is
 * the worst possible way for it to present.
 */
const SCRYPT_PARAMS = {
  N: 32768,
  r: 8,
  p: 1,
  keylen: 64,
  maxmem: 64 * 1024 * 1024,
} as const;

/** hashPassword derives a hash for password with salt. Both hex-encoded. */
export async function hashPassword(password: string, saltHex: string): Promise<string> {
  const derived = await scrypt(
    password.normalize("NFKC"),
    Buffer.from(saltHex, "hex"),
    SCRYPT_PARAMS.keylen,
    {
      N: SCRYPT_PARAMS.N,
      r: SCRYPT_PARAMS.r,
      p: SCRYPT_PARAMS.p,
      maxmem: SCRYPT_PARAMS.maxmem,
    },
  );
  return derived.toString("hex");
}

/**
 * verifyPassword compares a submitted password against the stored hash.
 *
 * The comparison is timing-safe, and a missing or malformed configuration
 * returns false rather than throwing — a console that crashes on a bad
 * DEMO_PASSWORD_HASH would leak, through the error page, that the
 * configuration is the problem.
 */
export async function verifyPassword(
  password: string,
  saltHex: string,
  expectedHashHex: string,
): Promise<boolean> {
  if (!password || !saltHex || !expectedHashHex) return false;

  let expected: Buffer;
  try {
    expected = Buffer.from(expectedHashHex, "hex");
  } catch {
    return false;
  }
  if (expected.length !== SCRYPT_PARAMS.keylen) return false;

  let actual: Buffer;
  try {
    actual = Buffer.from(await hashPassword(password, saltHex), "hex");
  } catch {
    return false;
  }
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

/** generateSalt returns a fresh hex-encoded salt. */
export function generateSalt(): string {
  return randomBytes(16).toString("hex");
}
