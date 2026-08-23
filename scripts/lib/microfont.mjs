/**
 * A 3x5 bitmap font, drawn as rectangles.
 *
 * The contact sheet needs to label its cells, and the obvious way to do that —
 * an SVG <text> element with font-family="monospace" — is not reproducible.
 * "monospace" is resolved by the host: macOS answers Menlo, Debian answers
 * DejaVu Sans Mono, and a machine with neither answers with whatever
 * fontconfig decides. The glyphs differ, so the rendered pixels differ, so the
 * PNG bytes differ, and a pipeline that promises identical output stops
 * delivering it the moment it runs somewhere else. That is not hypothetical:
 * the sheet differed by 11 bytes between macOS and Linux for exactly this
 * reason, which is enough to fail a regeneration check.
 *
 * Rectangles have no such ambiguity. Every glyph here is five rows of three
 * cells, returned as plain rectangles for the caller to fill, and the result is
 * the same on any machine with any fonts installed or none at all.
 *
 * The set is a-z, 0-9, space, "." and "-": what icon labels use. An unknown
 * character throws rather than rendering as a blank, so a future label that
 * needs a glyph says so at build time instead of quietly losing a letter.
 */

const GLYPHS = {
  "0": "###|#.#|#.#|#.#|###",
  // Centred, with a flag and a base. A bare right-hand stroke reads as though
  // it were spaced away from the digit before it: "512" looked like "5 12".
  "1": ".#.|##.|.#.|.#.|###",
  "2": "###|..#|###|#..|###",
  "3": "###|..#|###|..#|###",
  "4": "#.#|#.#|###|..#|..#",
  "5": "###|#..|###|..#|###",
  "6": "###|#..|###|#.#|###",
  "7": "###|..#|..#|..#|..#",
  "8": "###|#.#|###|#.#|###",
  "9": "###|#.#|###|..#|###",
  a: "###|#.#|###|#.#|#.#",
  b: "#..|#..|###|#.#|###",
  c: "###|#..|#..|#..|###",
  d: "..#|..#|###|#.#|###",
  e: "###|#.#|###|#..|###",
  f: "###|#..|###|#..|#..",
  g: "###|#..|#.#|#.#|###",
  h: "#.#|#.#|###|#.#|#.#",
  i: "###|.#.|.#.|.#.|###",
  j: "..#|..#|..#|#.#|###",
  k: "#.#|#.#|##.|#.#|#.#",
  l: "#..|#..|#..|#..|###",
  m: "#.#|###|###|#.#|#.#",
  n: "##.|#.#|#.#|#.#|#.#",
  o: "###|#.#|#.#|#.#|###",
  p: "###|#.#|###|#..|#..",
  q: "###|#.#|#.#|###|..#",
  r: "###|#.#|##.|#.#|#.#",
  s: "###|#..|###|..#|###",
  t: "###|.#.|.#.|.#.|.#.",
  u: "#.#|#.#|#.#|#.#|###",
  v: "#.#|#.#|#.#|#.#|.#.",
  w: "#.#|#.#|###|###|#.#",
  x: "#.#|#.#|.#.|#.#|#.#",
  y: "#.#|#.#|###|.#.|.#.",
  z: "###|..#|.#.|#..|###",
  "-": "...|...|###|...|...",
  ".": "...|...|...|...|.#.",
  " ": "...|...|...|...|...",
};

export const GLYPH_WIDTH = 3;
export const GLYPH_HEIGHT = 5;

/**
 * Width in pixels that `text` will occupy at `scale`, including the one-cell
 * gap between characters but not after the last one.
 */
export function measure(text, scale = 1) {
  if (text.length === 0) return 0;
  return (text.length * (GLYPH_WIDTH + 1) - 1) * scale;
}

/**
 * Rectangles covering the lit cells of `text`, with (x, y) as the top-left
 * corner. Returned in a fixed order so the output is byte-stable.
 */
export function textRects(text, { x = 0, y = 0, scale = 1 } = {}) {
  const rects = [];
  for (const [index, character] of [...text.toLowerCase()].entries()) {
    const glyph = GLYPHS[character];
    if (glyph === undefined) {
      throw new Error(
        `micro-font has no glyph for ${JSON.stringify(character)} (in ${JSON.stringify(text)}); ` +
          "add it to GLYPHS in scripts/lib/microfont.mjs",
      );
    }
    const originX = x + index * (GLYPH_WIDTH + 1) * scale;
    for (const [row, cells] of glyph.split("|").entries()) {
      // Merge horizontally adjacent lit cells into one rect. At three cells
      // wide the saving is small, but it keeps the rectangle count down and the
      // pixels are identical either way.
      let run = 0;
      for (let column = 0; column <= GLYPH_WIDTH; column += 1) {
        const lit = cells[column] === "#";
        if (lit) {
          run += 1;
          continue;
        }
        if (run > 0) {
          rects.push({
            x: originX + (column - run) * scale,
            y: y + row * scale,
            width: run * scale,
            height: scale,
          });
          run = 0;
        }
      }
    }
  }
  return rects;
}
