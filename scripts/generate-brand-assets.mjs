#!/usr/bin/env node
/**
 * Generate every GRIEFER brand asset from the vector masters.
 *
 * Rasters come from the SVGs, not from the source PNG. Rendering vectors at
 * each target size gives crisp edges everywhere, where downscaling one large
 * bitmap smears the shield's outline at small sizes.
 *
 * Deterministic: the same SVGs produce byte-identical output, so rerunning
 * this does not churn the repository.
 *
 *   node scripts/generate-brand-assets.mjs
 */

import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

import { encodeIco } from "./lib/ico.mjs";
import { ICNS_TYPES, encodeIcns } from "./lib/icns.mjs";
import { textSvg } from "./lib/microfont.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const VECTOR = join(ROOT, "branding", "vector");
const GENERATED = join(ROOT, "branding", "generated");
const CONSOLE_PUBLIC = join(ROOT, "console", "public");
const SITE_PUBLIC = join(ROOT, "site", "public");

/** Measured from the approved artwork. See branding/README.md. */
const BRAND = {
  cyan: "#1AD7CE",
  field: "#010104",
  surface: "#08090C",
};

const FULL = readFileSync(join(VECTOR, "griefer-shield-g.svg"));
const SMALL = readFileSync(join(VECTOR, "griefer-shield-g-small.svg"));
const MONO = readFileSync(join(VECTOR, "griefer-shield-g-monochrome.svg"));

/**
 * Below this, the full mark's outline falls under one device pixel and the
 * letter's counter fills in. The simplified variant is used instead.
 */
const SIMPLIFY_BELOW = 64;

const hexToRgb = (hex) => ({
  r: parseInt(hex.slice(1, 3), 16),
  g: parseInt(hex.slice(3, 5), 16),
  b: parseInt(hex.slice(5, 7), 16),
});

/**
 * render rasterises a master SVG at an exact pixel size.
 *
 * density is derived from the target so libvips rasterises at native
 * resolution rather than rendering once and resampling.
 */
async function render(svg, size, { background = null, inset = 0 } = {}) {
  const markSize = Math.round(size * (1 - inset * 2));
  const density = Math.max(72, Math.ceil((markSize / 512) * 72 * 4));
  let mark = sharp(svg, { density }).resize(markSize, markSize, {
    fit: "contain",
    background: { r: 0, g: 0, b: 0, alpha: 0 },
  });

  if (inset === 0 && !background) return mark.png({ compressionLevel: 9 }).toBuffer();

  const canvas = background
    ? { ...hexToRgb(background), alpha: 1 }
    : { r: 0, g: 0, b: 0, alpha: 0 };

  return sharp({ create: { width: size, height: size, channels: 4, background: canvas } })
    .composite([{ input: await mark.png().toBuffer(), gravity: "centre" }])
    .png({ compressionLevel: 9 })
    .toBuffer();
}

/** master picks the right vector for a target size. */
const master = (size) => (size < SIMPLIFY_BELOW ? SMALL : FULL);

function write(path, buffer) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, buffer);
  return { path: path.replace(`${ROOT}/`, ""), bytes: buffer.length };
}

const written = [];
const record = (r) => written.push(r);

/* -------------------------------------------------------------------------
 * Web and PWA
 * ---------------------------------------------------------------------- */

async function web() {
  const dir = join(GENERATED, "web");

  for (const size of [16, 32, 48, 64, 96, 128, 256]) {
    record(write(join(dir, `favicon-${size}x${size}.png`), await render(master(size), size)));
  }

  // Multi-resolution .ico. Windows and older browsers pick the closest entry,
  // so the small sizes carry the simplified mark and the large ones the full.
  const icoSizes = [16, 24, 32, 48, 64, 128, 256];
  const ico = encodeIco(
    await Promise.all(
      icoSizes.map(async (size) => ({ size, png: await render(master(size), size) })),
    ),
  );
  record(write(join(dir, "favicon.ico"), ico));

  // The SVG favicon: modern browsers prefer it and scale it themselves. The
  // simplified master is used because browser tab rendering is small.
  record(write(join(dir, "favicon.svg"), SMALL));
  record(write(join(dir, "griefer-mark.svg"), FULL));
  record(write(join(dir, "safari-pinned-tab.svg"), MONO));

  // Apple touch icon: no rounding of our own — iOS applies the mask — inset so
  // the shield's tip is not clipped by that mask, and with the alpha channel
  // removed. Safari paints black wherever an apple-touch-icon is transparent,
  // and an icon that is "opaque" only because every pixel happens to be opaque
  // still carries the channel.
  record(
    write(
      join(dir, "apple-touch-icon.png"),
      await sharp(await render(FULL, 180, { background: BRAND.field, inset: 0.08 }))
        .removeAlpha()
        .png({ compressionLevel: 9 })
        .toBuffer(),
    ),
  );

  // PWA icons. "any" purpose keeps the full frame; "maskable" reserves the
  // safe zone Android's masks require.
  for (const size of [192, 512]) {
    record(
      write(join(dir, `icon-${size}x${size}.png`), await render(FULL, size, { background: BRAND.field })),
    );
    // Android guarantees only the central circle of 80% diameter survives
    // every mask, so the mark is inset to sit inside it with margin.
    record(
      write(
        join(dir, `icon-maskable-${size}x${size}.png`),
        await render(FULL, size, { background: BRAND.field, inset: 0.20 }),
      ),
    );
  }

  // Open Graph card. 1200x630 is the size every major platform crops from.
  const ogMark = await render(FULL, 320, { background: null });
  const og = await sharp({
    create: { width: 1200, height: 630, channels: 4, background: { ...hexToRgb(BRAND.field), alpha: 1 } },
  })
    .composite([{ input: ogMark, gravity: "centre" }])
    .png({ compressionLevel: 9 })
    .toBuffer();
  record(write(join(dir, "og-image.png"), og));
}

/* -------------------------------------------------------------------------
 * iOS — AppIcon.appiconset
 * ---------------------------------------------------------------------- */

/** Every slot Xcode expects, as {idiom, size(pt), scale}. */
const IOS_SLOTS = [
  ["iphone", 20, 2], ["iphone", 20, 3],
  ["iphone", 29, 2], ["iphone", 29, 3],
  ["iphone", 40, 2], ["iphone", 40, 3],
  ["iphone", 60, 2], ["iphone", 60, 3],
  ["ipad", 20, 1], ["ipad", 20, 2],
  ["ipad", 29, 1], ["ipad", 29, 2],
  ["ipad", 40, 1], ["ipad", 40, 2],
  ["ipad", 76, 1], ["ipad", 76, 2],
  ["ipad", 83.5, 2],
  ["ios-marketing", 1024, 1],
];

async function ios() {
  const dir = join(GENERATED, "ios", "AppIcon.appiconset");
  const images = [];
  const emitted = new Map();

  for (const [idiom, points, scale] of IOS_SLOTS) {
    const pixels = Math.round(points * scale);
    const filename = `icon-${pixels}.png`;
    if (!emitted.has(filename)) {
      // iOS icons must be fully opaque — the App Store rejects alpha — and
      // must not carry rounded corners of their own, because the system
      // applies its own mask over whatever is supplied.
      const png = await render(master(pixels), pixels, {
        background: BRAND.field,
        inset: 0.08,
      });
      record(write(join(dir, filename), await sharp(png).removeAlpha().png({ compressionLevel: 9 }).toBuffer()));
      emitted.set(filename, true);
    }
    images.push({
      size: `${points}x${points}`,
      idiom,
      filename,
      scale: `${scale}x`,
    });
  }

  record(
    write(
      join(dir, "Contents.json"),
      Buffer.from(
        `${JSON.stringify({ images, info: { version: 1, author: "griefer-brand-pipeline" } }, null, 2)}\n`,
      ),
    ),
  );
}

/* -------------------------------------------------------------------------
 * Android
 * ---------------------------------------------------------------------- */

const ANDROID_DENSITIES = [
  ["mdpi", 48], ["hdpi", 72], ["xhdpi", 96], ["xxhdpi", 144], ["xxxhdpi", 192],
];

async function android() {
  const dir = join(GENERATED, "android");

  for (const [density, size] of ANDROID_DENSITIES) {
    record(
      write(
        join(dir, `mipmap-${density}`, "ic_launcher.png"),
        await render(master(size), size, { background: BRAND.field }),
      ),
    );
    // Adaptive icons: the launcher composites a foreground over a background
    // and animates them independently, so the foreground is transparent and
    // inset into the safe zone.
    record(
      write(
        join(dir, `mipmap-${density}`, "ic_launcher_foreground.png"),
        await render(master(size), Math.round(size * 1.5), { inset: 0.28 }),
      ),
    );
    record(
      write(
        join(dir, `mipmap-${density}`, "ic_launcher_monochrome.png"),
        await sharp(await render(MONO, Math.round(size * 1.5), { inset: 0.28 }))
          .png({ compressionLevel: 9 })
          .toBuffer(),
      ),
    );
  }

  record(
    write(
      join(dir, "values", "ic_launcher_background.xml"),
      Buffer.from(
        `<?xml version="1.0" encoding="utf-8"?>\n` +
          `<!-- Adaptive icon background. Measured from the approved artwork. -->\n` +
          `<resources>\n    <color name="ic_launcher_background">${BRAND.field}</color>\n</resources>\n`,
      ),
    ),
  );
  record(
    write(
      join(dir, "mipmap-anydpi-v26", "ic_launcher.xml"),
      Buffer.from(
        `<?xml version="1.0" encoding="utf-8"?>\n` +
          `<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n` +
          `    <background android:drawable="@color/ic_launcher_background"/>\n` +
          `    <foreground android:drawable="@mipmap/ic_launcher_foreground"/>\n` +
          `    <monochrome android:drawable="@mipmap/ic_launcher_monochrome"/>\n` +
          `</adaptive-icon>\n`,
      ),
    ),
  );
}

/* -------------------------------------------------------------------------
 * Windows
 * ---------------------------------------------------------------------- */

async function windows() {
  const dir = join(GENERATED, "windows");

  const icoSizes = [16, 24, 32, 48, 64, 128, 256];
  record(
    write(
      join(dir, "griefer.ico"),
      encodeIco(
        await Promise.all(
          icoSizes.map(async (size) => ({
            size,
            png: await render(master(size), size, { background: BRAND.field }),
          })),
        ),
      ),
    ),
  );

  // Tile and store assets.
  for (const size of [44, 50, 150, 310, 256, 512, 1024]) {
    record(
      write(
        join(dir, `griefer-${size}x${size}.png`),
        await render(master(size), size, { background: BRAND.field }),
      ),
    );
  }
}

/* -------------------------------------------------------------------------
 * macOS
 * ---------------------------------------------------------------------- */

/** iconutil's expected filenames, so the iconset is usable directly. */
const MAC_ICONSET = [
  ["icon_16x16.png", 16], ["icon_16x16@2x.png", 32],
  ["icon_32x32.png", 32], ["icon_32x32@2x.png", 64],
  ["icon_128x128.png", 128], ["icon_128x128@2x.png", 256],
  ["icon_256x256.png", 256], ["icon_256x256@2x.png", 512],
  ["icon_512x512.png", 512], ["icon_512x512@2x.png", 1024],
];

async function macos() {
  const dir = join(GENERATED, "macos");
  const iconset = join(dir, "griefer.iconset");

  const cache = new Map();
  const at = async (size) => {
    if (!cache.has(size)) {
      // macOS composites its own shape for some contexts but shows the icon
      // as supplied in others, so a modest inset keeps the shield off the edge.
      cache.set(size, await render(master(size), size, { background: BRAND.field, inset: 0.06 }));
    }
    return cache.get(size);
  };

  for (const [filename, size] of MAC_ICONSET) {
    record(write(join(iconset, filename), await at(size)));
  }

  record(
    write(
      join(dir, "griefer.icns"),
      encodeIcns(await Promise.all(ICNS_TYPES.map(async ({ type, size }) => ({ type, png: await at(size) })))),
    ),
  );
}

/* -------------------------------------------------------------------------
 * Framework-neutral PNGs
 * ---------------------------------------------------------------------- */

async function neutral() {
  const dir = join(GENERATED, "png");
  for (const size of [128, 256, 512, 1024]) {
    record(write(join(dir, `griefer-${size}.png`), await render(FULL, size, { background: BRAND.field })));
    record(write(join(dir, `griefer-${size}-transparent.png`), await render(FULL, size)));
  }
}

/* -------------------------------------------------------------------------
 * Distribution into the applications
 * ---------------------------------------------------------------------- */

const DISTRIBUTED = [
  "favicon.ico", "favicon.svg", "safari-pinned-tab.svg",
  "apple-touch-icon.png",
  "icon-192x192.png", "icon-512x512.png",
  "icon-maskable-192x192.png", "icon-maskable-512x512.png",
  "favicon-16x16.png", "favicon-32x32.png", "favicon-48x48.png",
  "og-image.png", "griefer-mark.svg",
];

function distribute() {
  const from = join(GENERATED, "web");
  for (const target of [CONSOLE_PUBLIC, SITE_PUBLIC]) {
    for (const name of DISTRIBUTED) {
      try {
        record(write(join(target, name), readFileSync(join(from, name))));
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
    }
  }
}

/* -------------------------------------------------------------------------
 * Contact sheet — quality control only, never shipped as an icon
 * ---------------------------------------------------------------------- */

async function contactSheet() {
  const cells = [
    ["favicon 16", await render(SMALL, 16)],
    ["favicon 32", await render(SMALL, 32)],
    ["favicon 48", await render(SMALL, 48)],
    ["apple 180", await render(FULL, 180, { background: BRAND.field, inset: 0.08 })],
    ["pwa 192", await render(FULL, 192, { background: BRAND.field })],
    ["pwa 512", await render(FULL, 512, { background: BRAND.field })],
    ["maskable 512", await render(FULL, 512, { background: BRAND.field, inset: 0.2 })],
    ["desktop 256", await render(FULL, 256, { background: BRAND.field, inset: 0.06 })],
  ];

  const CELL = 200;
  const PAD = 16;
  const COLS = 4;
  const rows = Math.ceil(cells.length / COLS);
  const width = COLS * CELL + (COLS + 1) * PAD;
  const height = rows * (CELL + 28) + (rows + 1) * PAD;

  const composites = [];
  for (const [index, [, png]] of cells.entries()) {
    const col = index % COLS;
    const row = Math.floor(index / COLS);
    const resized = await sharp(png)
      .resize(CELL - 32, CELL - 32, { fit: "contain", background: { r: 0, g: 0, b: 0, alpha: 0 }, kernel: "nearest" })
      .png()
      .toBuffer();
    composites.push({
      input: resized,
      left: PAD + col * (CELL + PAD) + 16,
      top: PAD + row * (CELL + 28 + PAD) + 16,
    });
  }

  // Labels are drawn from the micro-font rather than an SVG <text> element.
  // "monospace" resolves to a different face on every host, which changes the
  // pixels and therefore the file — see scripts/lib/microfont.mjs.
  const LABEL_SCALE = 2;
  const labels = cells
    .map(([label], index) => {
      const col = index % COLS;
      const row = Math.floor(index / COLS);
      const x = PAD + col * (CELL + PAD) + CELL / 2;
      const y = PAD + row * (CELL + 28 + PAD) + CELL + 10;
      return textSvg(label, { x, y, scale: LABEL_SCALE, fill: "#9AA6B8", anchor: "middle" });
    })
    .join("");

  composites.push({
    input: Buffer.from(
      `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}">${labels}</svg>`,
    ),
    left: 0,
    top: 0,
  });

  const sheet = await sharp({
    create: { width, height, channels: 4, background: { ...hexToRgb(BRAND.surface), alpha: 1 } },
  })
    .composite(composites)
    .png({ compressionLevel: 9 })
    .toBuffer();

  record(write(join(GENERATED, "preview", "contact-sheet.png"), sheet));
}

/* ---------------------------------------------------------------------- */

async function main() {
  // Everything under generated/ is derived. Clearing it first means a removed
  // output cannot linger and be mistaken for a current asset — except the
  // reference crop, which documents where the vectors came from.
  for (const sub of ["web", "ios", "android", "windows", "macos", "png", "preview"]) {
    rmSync(join(GENERATED, sub), { recursive: true, force: true });
  }

  await web();
  await ios();
  await android();
  await windows();
  await macos();
  await neutral();
  distribute();
  await contactSheet();

  const bytes = written.reduce((sum, w) => sum + w.bytes, 0);
  console.log(`generated ${written.length} files, ${(bytes / 1024).toFixed(0)} KiB total`);
}

await main();
