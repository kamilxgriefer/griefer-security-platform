#!/usr/bin/env node
/**
 * Verify the generated brand assets.
 *
 * Checks the things that are easy to get wrong and invisible until someone
 * installs the app: an icon that is the right size but empty, an Apple icon
 * that kept its alpha channel, a maskable icon whose shield gets sliced off by
 * a launcher's squircle, a manifest pointing at a file that was renamed.
 *
 *   node scripts/verify-brand-assets.mjs
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GENERATED = join(ROOT, "branding", "generated");
const WEB = join(GENERATED, "web");

let failures = 0;
let checks = 0;

function ok(message) {
  checks++;
  console.log(`  ok    ${message}`);
}

function fail(message) {
  checks++;
  failures++;
  console.log(`  FAIL  ${message}`);
}

function check(condition, message) {
  if (condition) ok(message);
  else fail(message);
}

/* ------------------------------------------------------------------ files */

/** Every asset the applications reference, with its expected pixel size. */
const REQUIRED = [
  ["web/favicon.ico", null],
  ["web/favicon.svg", null],
  ["web/safari-pinned-tab.svg", null],
  ["web/griefer-mark.svg", null],
  ["web/favicon-16x16.png", 16],
  ["web/favicon-32x32.png", 32],
  ["web/favicon-48x48.png", 48],
  ["web/favicon-64x64.png", 64],
  ["web/favicon-96x96.png", 96],
  ["web/apple-touch-icon.png", 180],
  ["web/icon-192x192.png", 192],
  ["web/icon-512x512.png", 512],
  ["web/icon-maskable-192x192.png", 192],
  ["web/icon-maskable-512x512.png", 512],
  ["web/og-image.png", null],
  ["ios/AppIcon.appiconset/Contents.json", null],
  ["ios/AppIcon.appiconset/icon-1024.png", 1024],
  ["android/mipmap-xxxhdpi/ic_launcher.png", 192],
  ["android/mipmap-anydpi-v26/ic_launcher.xml", null],
  ["windows/griefer.ico", null],
  ["windows/griefer-1024x1024.png", 1024],
  ["macos/griefer.icns", null],
  ["macos/griefer.iconset/icon_512x512@2x.png", 1024],
  ["png/griefer-1024.png", 1024],
  ["preview/contact-sheet.png", null],
];

async function files() {
  console.log("\nrequired assets");
  for (const [relative, expected] of REQUIRED) {
    const path = join(GENERATED, relative);
    if (!existsSync(path)) {
      fail(`${relative} is missing`);
      continue;
    }
    const bytes = statSync(path).size;
    if (bytes === 0) {
      fail(`${relative} is empty`);
      continue;
    }
    if (expected === null) {
      ok(`${relative} (${bytes} B)`);
      continue;
    }
    const meta = await sharp(path).metadata();
    check(
      meta.width === expected && meta.height === expected,
      `${relative} is ${meta.width}x${meta.height}, expected ${expected}x${expected}`,
    );
  }
}

/* ------------------------------------------------------------------ alpha */

async function alpha() {
  console.log("\nalpha channel");

  // Apple and iOS reject alpha; the store rejects the build outright.
  for (const relative of ["web/apple-touch-icon.png", "ios/AppIcon.appiconset/icon-1024.png"]) {
    const { channels, hasAlpha } = await sharp(join(GENERATED, relative)).metadata();
    check(!hasAlpha, `${relative} is opaque (channels=${channels})`);
  }

  // The adaptive foreground must be transparent, or the launcher composites a
  // solid square over its own background and the animation looks broken.
  const fg = await sharp(join(GENERATED, "android/mipmap-xxxhdpi/ic_launcher_foreground.png")).metadata();
  check(fg.hasAlpha, "android adaptive foreground keeps its alpha channel");
}

/* --------------------------------------------------------------- coverage */

/**
 * Reject an icon that is technically valid but visually empty — the failure
 * mode when a render silently produces a blank canvas.
 */
async function coverage() {
  console.log("\nink coverage");
  for (const relative of [
    "web/favicon-16x16.png",
    "web/favicon-32x32.png",
    "web/icon-512x512.png",
    "web/apple-touch-icon.png",
  ]) {
    const { data, info } = await sharp(join(GENERATED, relative))
      .ensureAlpha()
      .raw()
      .toBuffer({ resolveWithObject: true });
    let ink = 0;
    const total = info.width * info.height;
    for (let i = 0; i < data.length; i += 4) {
      const [r, g, b, a] = [data[i], data[i + 1], data[i + 2], data[i + 3]];
      if (a > 32 && g > 90 && b > 90 && g > r + 40) ink++;
    }
    const percent = (100 * ink) / total;
    check(percent > 3, `${relative} carries ${percent.toFixed(1)}% brand ink`);
  }
}

/* --------------------------------------------------------------- maskable */

/**
 * Android guarantees only that the central circle of 80% diameter survives
 * every launcher mask. Anything outside it may be cut, so the shield and the
 * letter must fit inside — checked against the four mask families Android
 * actually ships.
 */
async function maskable() {
  console.log("\nmaskable safe zone");
  const size = 512;
  const path = join(GENERATED, "web/icon-maskable-512x512.png");
  const { data, info } = await sharp(path).ensureAlpha().raw().toBuffer({ resolveWithObject: true });

  const isInk = (x, y) => {
    const i = (y * info.width + x) * 4;
    const [r, g, b, a] = [data[i], data[i + 1], data[i + 2], data[i + 3]];
    return a > 32 && g > 90 && b > 90 && g > r + 40;
  };

  const centre = size / 2;
  const masks = {
    // The guaranteed-safe circle.
    circle: (x, y) => Math.hypot(x - centre, y - centre) <= size * 0.4,
    // Rounded square and squircle are more generous than the circle; the
    // teardrop clips one corner hard.
    "rounded square": (x, y) => {
      const inset = size * 0.10;
      const r = size * 0.16;
      const dx = Math.max(inset - x, 0, x - (size - inset));
      const dy = Math.max(inset - y, 0, y - (size - inset));
      return Math.hypot(dx, dy) <= r;
    },
    squircle: (x, y) => {
      const n = 4;
      const a = size * 0.42;
      return (Math.abs(x - centre) / a) ** n + (Math.abs(y - centre) / a) ** n <= 1;
    },
    teardrop: (x, y) => {
      // Round on three corners, square on the bottom-right.
      const inset = size * 0.10;
      if (x > centre && y > centre) return x <= size - inset && y <= size - inset;
      return Math.hypot(x - centre, y - centre) <= size * 0.42;
    },
  };

  for (const [name, inside] of Object.entries(masks)) {
    let clipped = 0;
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (isInk(x, y) && !inside(x, y)) clipped++;
      }
    }
    check(clipped === 0, `${name} mask clips ${clipped} ink pixels`);
  }
}

/* --------------------------------------------------------------------- svg */

async function svg() {
  console.log("\nvector masters");
  for (const name of [
    "griefer-shield-g.svg",
    "griefer-shield-g-small.svg",
    "griefer-shield-g-monochrome.svg",
  ]) {
    const path = join(ROOT, "branding", "vector", name);
    if (!existsSync(path)) {
      fail(`${name} is missing`);
      continue;
    }
    const text = readFileSync(path, "utf8");

    check(text.includes("<path"), `${name} contains path elements`);
    // A raster wrapped in an <svg> is not a vector version.
    check(!/data:image\/(png|jpe?g)/i.test(text), `${name} embeds no raster image`);
    check(!/<image\b/i.test(text), `${name} contains no <image> element`);
    // An SVG that needs a font renders differently on every machine.
    check(!/<text\b/i.test(text), `${name} contains no <text> element`);
    check(!/font-family/i.test(text), `${name} depends on no font`);

    // It must actually rasterise.
    try {
      const png = await sharp(Buffer.from(text), { density: 384 }).resize(64, 64).png().toBuffer();
      check(png.length > 200, `${name} rasterises`);
    } catch (error) {
      fail(`${name} does not rasterise: ${error.message}`);
    }
  }

  const mono = readFileSync(join(ROOT, "branding", "vector", "griefer-shield-g-monochrome.svg"), "utf8");
  check(mono.includes("currentColor"), "monochrome master inherits currentColor");
  check(!/<rect[^>]*fill="#/.test(mono), "monochrome master has no baked background");
}

/* ---------------------------------------------------------------- manifest */

async function manifest() {
  console.log("\nweb app manifest");
  const candidates = [
    join(ROOT, "console", "public", "site.webmanifest"),
    join(ROOT, "site", "public", "site.webmanifest"),
  ];

  for (const path of candidates) {
    if (!existsSync(path)) {
      fail(`${path.replace(`${ROOT}/`, "")} is missing`);
      continue;
    }
    const label = path.replace(`${ROOT}/`, "");
    let parsed;
    try {
      parsed = JSON.parse(readFileSync(path, "utf8"));
    } catch (error) {
      fail(`${label} is not valid JSON: ${error.message}`);
      continue;
    }

    for (const key of ["name", "short_name", "start_url", "scope", "display", "theme_color", "background_color", "icons"]) {
      check(parsed[key] !== undefined, `${label} declares ${key}`);
    }

    const purposes = new Set(parsed.icons.flatMap((i) => (i.purpose ?? "any").split(/\s+/)));
    check(purposes.has("any"), `${label} provides an "any" purpose icon`);
    check(purposes.has("maskable"), `${label} provides a "maskable" purpose icon`);

    // Every referenced icon must exist beside the manifest.
    const publicDir = dirname(path);
    for (const icon of parsed.icons) {
      const asset = join(publicDir, icon.src.replace(/^\//, ""));
      check(existsSync(asset), `${label} → ${icon.src} exists`);
    }

    // Declaring screenshots that were never produced turns an install prompt
    // into a broken dialog.
    if (parsed.screenshots) {
      for (const shot of parsed.screenshots) {
        check(existsSync(join(publicDir, shot.src.replace(/^\//, ""))), `${label} → ${shot.src} exists`);
      }
    }
  }
}

/* ---------------------------------------------------------------------- */

async function main() {
  console.log("GRIEFER brand asset verification");
  await files();
  await alpha();
  await coverage();
  await maskable();
  await svg();
  await manifest();

  console.log(`\n${checks - failures}/${checks} checks passed`);
  if (failures > 0) {
    console.log(`${failures} FAILED`);
    process.exit(1);
  }
}

await main();
