# Icons for future applications

**No native application exists.** Nothing here has been built, submitted or
signed. This is an asset pack prepared ahead of time so that whenever a client
is started, its icons are already correct, already measured from the approved
artwork, and already regenerable from one command.

Everything below is produced by `pnpm generate:brand-assets` and validated by
`pnpm verify:brand-assets`.

## iOS and iPadOS

```
branding/generated/ios/AppIcon.appiconset/
├── Contents.json
└── icon-{20,29,40,58,60,76,80,87,120,152,167,180,1024}.png
```

Drop the whole `AppIcon.appiconset` directory into `Assets.xcassets`. Xcode
reads `Contents.json` and fills every slot.

Two things the App Store enforces, both already handled:

- **No alpha channel.** App Store Connect rejects an icon that has one, even if
  every pixel is opaque. The generator strips the channel rather than relying on
  the pixels happening to be solid.
- **No rounded corners.** iOS applies its own mask. A pre-rounded icon is
  rounded twice and ends up visibly wrong next to everything else on the home
  screen.

The mark is inset 8 % so the shield's tip is not clipped by that mask.

## Android

```
branding/generated/android/
├── mipmap-{mdpi,hdpi,xhdpi,xxhdpi,xxxhdpi}/
│   ├── ic_launcher.png
│   ├── ic_launcher_foreground.png
│   └── ic_launcher_monochrome.png
├── mipmap-anydpi-v26/ic_launcher.xml
└── values/ic_launcher_background.xml
```

Copy into `app/src/main/res/`. The adaptive icon is already wired: a flat
background colour, a transparent foreground, and a monochrome layer for themed
icons on Android 13 and later.

The foreground is inset 28 %, because the launcher animates the two layers
independently and moves the foreground within the frame. The legacy
`ic_launcher.png` is the full mark for devices predating adaptive icons.

## Windows

```
branding/generated/windows/
├── griefer.ico                       16, 24, 32, 48, 64, 128, 256
└── griefer-{44,50,150,310,256,512,1024}x*.png
```

`griefer.ico` is the application icon. The PNGs cover Start tiles and Store
listings. The `.ico` carries the simplified mark at small sizes and the full
mark above 64 px, so the taskbar and the title bar both stay legible.

## macOS

```
branding/generated/macos/
├── griefer.icns
└── griefer.iconset/    icon_16x16.png … icon_512x512@2x.png
```

`griefer.icns` is ready to use. The `.iconset` directory is the source form and
uses the filenames `iconutil` expects, so it can be rebuilt with
`iconutil -c icns griefer.iconset` on any Mac.

The `.icns` is written directly by `scripts/lib/icns.mjs` rather than shelling
out to `iconutil`, so the asset pipeline produces identical output on Linux CI
and on a developer's Mac.

## Framework-neutral

```
branding/generated/png/griefer-{128,256,512,1024}.png
branding/generated/png/griefer-{128,256,512,1024}-transparent.png
```

For anything that wants plain PNGs.

| Framework | What it wants |
|---|---|
| **Tauri** | `tauri icon branding/generated/png/griefer-1024.png` generates the rest |
| **Electron** | `griefer.icns` (mac), `griefer.ico` (win), `griefer-512.png` (linux) |
| **Flutter** | `flutter_launcher_icons` pointed at `griefer-1024.png` |
| **Capacitor** | The iOS and Android packs above, directly |

## Choosing a framework

Not decided, and deliberately not decided here. These assets work with any of
them, which is the point of preparing them before the choice rather than after.

## Regenerating

```bash
pnpm generate:brand-assets
pnpm verify:brand-assets
```

Deterministic — same masters, same bytes. If you change a size or an inset,
change it in `scripts/generate-brand-assets.mjs` and regenerate; do not edit a
generated file, because the next run will overwrite it.
