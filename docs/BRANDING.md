# Branding

The full asset reference lives in [`branding/README.md`](../branding/README.md).
This page covers how the mark is used inside the project.

## The mark

A shield outline enclosing the letter **G**. It reads as protection and as the
project's initial at the same time, which is the whole job of the mark.

Three masters, chosen by size rather than by preference:

| Master | When |
|---|---|
| `griefer-shield-g.svg` | 64 px and above |
| `griefer-shield-g-small.svg` | Below 64 px — favicons, tab icons, small system glyphs |
| `griefer-shield-g-monochrome.svg` | One colour available: mask icons, pinned tabs, stencils, print |

Picking the small master below 64 px is not a nicety. The full mark's outline is
about 6 % of its width; at 16 px that is under one device pixel, and the shield
disappears while the letter's counter fills in.

## Colours

`#1AD7CE` is the brand cyan, measured from the approved artwork rather than
picked. `#010104` is the field it sits on.

The console's `--color-brand` token now carries the same value. It previously
held `#38D9C8` — close enough to look intentional, different enough to be
visible side by side.

Full token table with provenance: [`branding/README.md`](../branding/README.md#colours).

## Using the mark

**Do**

- Give it room. The insets in the asset table are minimums, not targets.
- Use the field colour behind it, or a background dark enough that the cyan
  carries.
- Use the monochrome master when only one colour is available.

**Do not**

- Add rounded corners. Every platform applies its own mask, and a pre-rounded
  icon gets rounded twice.
- Recolour it. The cyan is measured from the approved artwork.
- Stretch it. The shield's 0.84 width-to-height ratio is part of the mark.
- Scale the full master below 64 px.
- Ship `branding/generated/preview/contact-sheet.png` as an icon. It is a
  quality-control sheet.

## Regenerating

```bash
pnpm generate:brand-assets
pnpm verify:brand-assets
```

CI fails if regenerating changes the tree, which is what stops the committed
assets and the vector masters from quietly diverging.
