#!/usr/bin/env node
/**
 * Author the GRIEFER mark as real SVG paths, traced from the approved artwork.
 *
 * The approved mark exists only as raster. This traces its ink boundary into
 * genuine vector contours rather than approximating it with hand-fitted arcs,
 * which drifts from the thing that was actually approved, and rather than
 * embedding a bitmap, which would make "vector version" a lie.
 *
 * Deterministic: same source bytes and same constants produce identical SVGs,
 * so regenerating does not churn the repository.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

import { normalizePngFile } from "./lib/png-normalize.mjs";
import { dilate, simplify, smoothToPath, traceContours } from "./lib/trace.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SOURCE = join(ROOT, "branding", "source", "GRIEFER_shield_G_logo_source.png");
const OUT = join(ROOT, "branding", "vector");

/**
 * Brand colours, measured from the source rather than chosen.
 * See branding/README.md for how each was derived.
 */
export const BRAND = {
  cyan: "#1AD7CE",
  cyanBright: "#1CD9D1",
  field: "#010104",
};

/**
 * The hero mark's ink bounding box within the source sheet.
 *
 * The source is a presentation sheet: the approved mark sits at the top, above
 * a horizontal rule, with size samples and labels below. These bounds were
 * measured, not guessed — see branding/README.md.
 */
const HERO = { left: 447, top: 73, width: 360, height: 428 };

const VIEW = 512;

/** How much of the 512 frame the mark occupies, leaving optical margin. */
const FRAME_RATIO = 0.80;

async function loadMask() {
  const { png } = normalizePngFile(SOURCE);
  const { data, info } = await sharp(png)
    .extract(HERO)
    .raw()
    .toBuffer({ resolveWithObject: true });

  const { width, height, channels } = info;
  const mask = new Uint8Array(width * height);
  for (let i = 0, p = 0; p < mask.length; i += channels, p++) {
    const r = data[i];
    const g = data[i + 1];
    const b = data[i + 2];
    // The mark is cyan on near-black. Requiring green and blue to lead red by a
    // clear margin keeps the glow's dim halo out of the trace, which would
    // otherwise round every edge outward.
    mask[p] = g > 110 && b > 110 && g > r + 50 ? 1 : 0;
  }
  return { mask, width, height };
}

function toPaths({ mask, width, height }, { epsilon, dilateBy }) {
  const grown = dilate(mask, width, height, dilateBy);
  const contours = traceContours(grown, width, height);

  // Scale the mark into the frame, preserving aspect and centring it.
  const scale = (VIEW * FRAME_RATIO) / Math.max(width, height);
  const offsetX = (VIEW - width * scale) / 2;
  const offsetY = (VIEW - height * scale) / 2;
  const transform = (x, y) => [offsetX + x * scale, offsetY + y * scale];

  return contours
    .map((ring) => smoothToPath(simplify(ring, epsilon), transform))
    .filter(Boolean)
    .join(" ");
}

function svg({ paths, background, colour, title, desc }) {
  const field = background ? `\n  <rect width="512" height="512" fill="${background}"/>` : "";
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512" role="img" aria-label="GRIEFER">
  <title>${title}</title>
  <desc>${desc}</desc>${field}
  <path fill="${colour}" fill-rule="evenodd" d="${paths}"/>
</svg>
`;
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  const source = await loadMask();

  // Full mark. A tight epsilon keeps the shield's sweep and the letterform's
  // curves faithful at large sizes.
  const full = toPaths(source, { epsilon: 0.8, dilateBy: 0 });
  writeFileSync(
    join(OUT, "griefer-shield-g.svg"),
    svg({
      paths: full,
      background: BRAND.field,
      colour: BRAND.cyan,
      title: "GRIEFER",
      desc: "A shield outline enclosing the letter G, in the GRIEFER brand cyan on a near-black field.",
    }),
  );

  // Small mark. At 16px the full outline falls below one device pixel and
  // disappears; dilating before the trace thickens every stroke so the shield
  // and the letter both survive. A looser epsilon drops detail that cannot be
  // resolved at that size anyway.
  const small = toPaths(source, { epsilon: 2.0, dilateBy: 4 });
  writeFileSync(
    join(OUT, "griefer-shield-g-small.svg"),
    svg({
      paths: small,
      background: BRAND.field,
      colour: BRAND.cyan,
      title: "GRIEFER",
      desc: "Simplified GRIEFER mark for small sizes: heavier strokes, reduced detail.",
    }),
  );

  // Monochrome. Inherits currentColor and carries no field, for mask icons,
  // pinned tabs, system glyphs and single-colour printing.
  writeFileSync(
    join(OUT, "griefer-shield-g-monochrome.svg"),
    svg({
      paths: small,
      background: null,
      colour: "currentColor",
      title: "GRIEFER",
      desc: "Single-colour GRIEFER mark. Inherits currentColor and has no background.",
    }),
  );

  console.log("wrote 3 SVGs to branding/vector/");
}

await main();
