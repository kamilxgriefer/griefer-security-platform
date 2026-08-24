#!/usr/bin/env node
/**
 * Generate the secrets the GRIEFER demonstration environment needs.
 *
 * Writes the human-facing credential to ~/.config/griefer/demo-credentials.txt
 * with mode 600, and prints the environment-variable values to stdout so they
 * can be pasted into the platform's secret store.
 *
 * The password itself is written ONLY to that file. It is never printed to
 * stdout, so it cannot end up in a terminal scrollback that gets shared, in a
 * CI log, or in a screenshot of this command running.
 *
 * Usage: node scripts/generate-demo-credentials.mjs [--print-env]
 */

import { randomBytes, scrypt as scryptCallback } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

const SCRYPT = { N: 32768, r: 8, p: 1, keylen: 64, maxmem: 64 * 1024 * 1024 };

/**
 * The two accounts a deployment starts with.
 *
 * The administrator is provisioned here rather than only from inside the
 * console, because an account store that can only be populated by an existing
 * administrator is one forgotten password away from a platform nobody can
 * enter. Further analysts are created by the administrator from the console.
 */
const ACCOUNTS = [
  { key: "ADMIN", username: "admin", role: "Administrator", can: "everything, including the audit trail and account management" },
  { key: "ANALYST", username: "analyst", role: "Analyst", can: "the dashboard and incidents; not the audit trail, not account management" },
];
const CREDENTIALS_PATH = join(homedir(), ".config", "griefer", "demo-credentials.txt");

function scrypt(password, salt, keylen, options) {
  return new Promise((resolve, reject) => {
    scryptCallback(password, salt, keylen, options, (err, derived) =>
      err ? reject(err) : resolve(derived),
    );
  });
}

/**
 * A passphrase from a word list rather than a random character string.
 *
 * Someone has to read this out of a file and type it into a login form. A
 * password that invites a copy-paste into a chat window is a worse password
 * than a slightly longer one that can be typed.
 */
const WORDS = [
  "amber", "anchor", "basalt", "beacon", "cinder", "cobalt", "dagger", "delta",
  "ember", "falcon", "granite", "harbor", "indigo", "javelin", "kestrel", "lantern",
  "marble", "nickel", "onyx", "pewter", "quartz", "raven", "saffron", "talon",
  "umber", "vector", "walnut", "xenon", "yarrow", "zephyr", "bastion", "citadel",
];

function passphrase(words = 5) {
  // Masking rather than taking a remainder. Both are uniform *while* the list
  // is a power of two, but a remainder stays silently biased if somebody later
  // adds a word — 256 % 33 leaves the first 25 entries slightly likelier. The
  // mask cannot: it stops being correct loudly, at the assertion below, rather
  // than quietly weakening every password generated afterwards.
  const mask = WORDS.length - 1;
  if ((WORDS.length & mask) !== 0) {
    throw new Error(`WORDS must have a power-of-two length; it has ${WORDS.length}`);
  }

  const chosen = [];
  for (let i = 0; i < words; i += 1) {
    chosen.push(WORDS[randomBytes(1)[0] & mask]);
  }
  // A digit group so the result satisfies policies that demand one.
  return `${chosen.join("-")}-${randomBytes(2).readUInt16BE(0)}`;
}

async function main() {
  const provisioned = [];
  for (const account of ACCOUNTS) {
    const password = passphrase();
    const salt = randomBytes(16).toString("hex");
    const hash = (
      await scrypt(password, Buffer.from(salt, "hex"), SCRYPT.keylen, SCRYPT)
    ).toString("hex");
    provisioned.push({ ...account, password, salt, hash });
  }

  const sessionSecret = randomBytes(48).toString("base64url");
  const internalToken = randomBytes(48).toString("base64url");
  const natsPassword = randomBytes(32).toString("base64url");

  mkdirSync(dirname(CREDENTIALS_PATH), { recursive: true, mode: 0o700 });

  // Preserve a URL already recorded by a previous run, so re-generating the
  // password does not lose the deployment address.
  // Read and handle absence, rather than asking whether the file exists and
  // then reading it: between those two steps the answer can change, and the
  // read throws on a file that existed a moment earlier.
  let existingUrl = "to be filled in after deployment";
  try {
    const previous = readFileSync(CREDENTIALS_PATH, "utf8");
    const match = previous.match(/^GRIEFER demo URL:\s*(.+)$/m);
    if (match?.[1] && !match[1].startsWith("to be filled")) existingUrl = match[1].trim();
  } catch (error) {
    // A missing file is the ordinary first run. Anything else is not, and
    // silently discarding it would lose a recorded URL without saying so.
    if (error.code !== "ENOENT") throw error;
  }

  writeFileSync(
    CREDENTIALS_PATH,
    [
      `GRIEFER demo URL: ${existingUrl}`,
      "",
      ...provisioned.flatMap((account) => [
        `${account.role}`,
        `  Username: ${account.username}`,
        `  Password: ${account.password}`,
        `  Can see:  ${account.can}`,
        "",
      ]),
      "This file holds the console logins only.",
      "It deliberately contains no platform token, no database connection string,",
      "no session secret and no service credential.",
      "",
      `Generated: ${new Date().toISOString()}`,
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  chmodSync(CREDENTIALS_PATH, 0o600);

  // stdout carries the values that go into the platform's secret store. The
  // password is not among them — only its salt and hash, which are useless
  // without the work factor of a scrypt derivation.
  process.stdout.write(
    [
      "# Console service",
      ...provisioned.flatMap((account) => [
        `GRIEFER_${account.key}_USERNAME=${account.username}`,
        `GRIEFER_${account.key}_PASSWORD_SALT=${account.salt}`,
        `GRIEFER_${account.key}_PASSWORD_HASH=${account.hash}`,
      ]),
      `DEMO_SESSION_SECRET=${sessionSecret}`,
      "",
      "# Console and API — must be identical in both",
      `INTERNAL_API_TOKEN=${internalToken}`,
      "",
      "# API and NATS — must be identical in both",
      "NATS_USER=griefer",
      `NATS_PASSWORD=${natsPassword}`,
      "",
      `# The login passwords were written to ${CREDENTIALS_PATH} (mode 600).`,
      "# They are not printed here on purpose.",
      "",
    ].join("\n"),
  );

  process.stderr.write(`\n${provisioned.length} console passwords written to ${CREDENTIALS_PATH}\n`);
}

main().catch((error) => {
  process.stderr.write(`failed to generate credentials: ${error.message}\n`);
  process.exit(1);
});
