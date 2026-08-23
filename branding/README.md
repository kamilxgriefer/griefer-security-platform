# GRIEFER brand assets

Everything here derives from one approved file. Nothing is redrawn by hand and
nothing is exported manually — one command regenerates the lot.

```bash
pnpm generate:brand-assets   # rebuild every asset from the vector masters
pnpm verify:brand-assets     # check sizes, alpha, safe zones, manifests
```

## The mark

A shield outline enclosing the letter **G**, in brand cyan on a near-black
field.

| | |
|---|---|
| Source | `branding/source/GRIEFER_shield_G_logo_source.png` |
| Dimensions | 1254 × 1254, 8-bit RGB, no alpha |
| SHA-256 | `a13a0df8895f9fe95cadc4b9e8c04830045591b4a67fcdade5551ff1fecb023a` |

The source is a **presentation sheet**, not an isolated logo: the approved mark
sits at the top above a horizontal rule, with size samples and labels below.
The mark's ink occupies **x 447–806, y 73–500** within that sheet, and only that
region is used.

It also carries a private `caBX` ancillary chunk, which is legal PNG but which
libvips refuses outright. `scripts/lib/png-normalize.mjs` strips it by copying
the chunks a decoder needs and dropping the rest — byte surgery, not a re-encode,
so the decoded pixels stay bit-identical. The original file is never modified.

## Colours

Measured from the source, not chosen. A colour census over the mark's ink gives:

| Token | Value | Where it came from |
|---|---|---|
| `--griefer-cyan` | `#1AD7CE` | Weighted mean of the mark's cyan ink |
| `--griefer-cyan-bright` | `#1CD9D1` | Brightest sustained cyan — the glow core |
| `--griefer-cyan-dim` | `#12776F` | Darkened for borders and disabled states |
| `--griefer-field` | `#010104` | The mark's own background |
| `--griefer-surface` | `#08090C` | The console's raised surface |
| `--griefer-text` | `#E7ECF3` | Console body text |
| `--griefer-text-muted` | `#9AA6B8` | Console secondary text |

The console previously used `#38D9C8` for its accent — close to the logo but
measurably different in hue and lightness. It now uses `#1AD7CE`. Two
near-identical cyans in one product is exactly what a brand token exists to
prevent.

## Vector masters

Real paths, traced from the approved artwork. No embedded raster, no `<image>`
element, no `<text>` element, and no dependency on a font — verified on every
run by `pnpm verify:brand-assets`.

| File | Use |
|---|---|
| `vector/griefer-shield-g.svg` | The full mark. Anything 64 px and above. |
| `vector/griefer-shield-g-small.svg` | Simplified: heavier strokes, less detail. Below 64 px. |
| `vector/griefer-shield-g-monochrome.svg` | `currentColor`, no background. Mask icons, pinned tabs, single-colour print. |

### Why the letter is a path

The GRIEFER wordmark in the console uses a system monospace stack
(`ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace`) with
no font file in the repository. There is nothing to trace and nothing that could
be embedded legally — and an SVG that depends on a font renders differently on
every machine that opens it. The G is therefore traced from the approved
artwork as path data.

### Why below 64 px is a different drawing

At 16 px the full mark's outline falls below one device pixel: the shield
washes out and the letter's counter fills in. The small master is dilated
before tracing, which thickens every stroke, and simplified more aggressively,
which drops detail that cannot be resolved at that size anyway.

## Safe margins and minimum sizes

| Context | Inset | Reason |
|---|---|---|
| Plain icon | 0 | The frame is the mark's own field |
| Apple touch icon | 8 % | iOS applies its own mask over whatever is supplied |
| Maskable (Android) | 20 % | Only the central circle of 80 % diameter survives every launcher mask |
| Android adaptive foreground | 28 % | The launcher animates foreground and background independently |
| macOS | 6 % | Some contexts show the icon as supplied |

**Minimum size: 16 px**, using the small master. Below that the shield and the
letter are no longer distinguishable and the monochrome mark should be used
instead.

Never add rounded corners. Every platform that wants them applies its own mask,
and a pre-rounded icon gets rounded twice.

## Where the generated assets live

| Platform | Format | Sizes | Location |
|---|---|---|---|
| Web | ICO, SVG, PNG | 16–256 | `generated/web/` |
| PWA | PNG | 192, 512, + maskable | `generated/web/` |
| iOS | PNG + `Contents.json` | 20–1024 pt | `generated/ios/AppIcon.appiconset/` |
| Android | PNG + XML | mdpi–xxxhdpi, adaptive | `generated/android/` |
| Windows | ICO, PNG | 16–1024 | `generated/windows/` |
| macOS | ICNS + iconset | 16–1024 | `generated/macos/` |
| Neutral | PNG | 128–1024, opaque and transparent | `generated/png/` |

`generated/web/` is copied into `console/public/` and `site/public/` by the
same command, so the applications and the asset store cannot drift apart.

`generated/preview/contact-sheet.png` is for quality control only. It is not an
icon and must never be shipped as one.

## Regenerating

```bash
pnpm install                 # once
node scripts/build-brand-svg.mjs      # source PNG  → vector masters
pnpm generate:brand-assets            # vector masters → every platform asset
pnpm verify:brand-assets              # 84 checks
```

Output is deterministic: the same source and the same constants produce
byte-identical files, so regenerating never churns the repository. CI asserts
this — if a regeneration changes the tree, the committed assets and the masters
have drifted and the build fails.
