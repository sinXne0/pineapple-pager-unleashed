# Pager Themes

Community themes for the Hak5 WiFi Pineapple Pager (480 × 222, firmware
2.0.0-stable). Each theme is a complete UI set: dashboard, menus, dialogs,
status bars, keyboards, boot animation and screen assets.

## Install

Copy a theme directory into `/root/themes/` (or `/mmc/root/themes/`) on the
Pager, then select it under **Settings → General → Theme** and confirm the UI
reload.

```text
/root/themes/<theme>/
├── theme.json
├── components/
└── assets/
```

The Pager looks for `theme.json` directly inside `/root/themes/<theme>/`. If a
theme is nested one level deeper, the Pager cannot find it and falls back to
`wargames`.

### Prebuilt zips

Prebuilt archives live in [`zips/`](zips/). Each zip extracts to a single
top-level theme folder with `theme.json` at its root:

| Zip | Theme folder |
| --- | --- |
| `darkseclabz-glitch.zip` | `darkseclabz-glitch/` |
| `darksecflipper.zip` | `darksecflipper/` |
| `darksecskeleton.zip` | `darksecskeleton/` |
| `darkseclabz-numeric.zip` | `darkseclabz-numeric/` |
| `darkseclabz-desktop.zip` | `darkseclabz-desktop/` |
| `darkseclabz-hadal.zip` | `darkseclabz-hadal/` |

## Catalog

| Theme | Internal name | Version | Description |
| --- | --- | --- | --- |
| `darkseclabz-glitch` | Darkseclabz Glitch | 1.0.1 | Glitch-art wargames variant |
| `darksecflipper` | Darksec Flipper | 1.0.0 | Flipper Zero monochrome dashboard with the L1_Tv dolphin artwork |
| `darksecskeleton` | Darksec Skeleton | 1.2.0 | Original pixel-art skeleton dashboard |
| `darkseclabz-numeric` | Darkseclabz Numeric | 1.0.0 | 1990s alphanumeric pager: olive LCD, segmented menu numbers, inbox-style payload menu |
| `darkseclabz-desktop` | Darkseclabz Desktop | 11.0.2 | macOS Tahoe-inspired glass dock, magnified selection and six dashboard cards |
| `darkseclabz-hadal` | Darkseclabz Hadal Station | 1.0.2 | Underwater research station with six selectable rooms and a startup self-test |

## Changelog

### 2026-11-13

**Theme validation fixes (Glitch 1.0.1, Desktop 11.0.2, Hadal Station 1.0.2)**

- `components/lock_screen.json`: turned `windowed_canvas` off. The lock screen
  background is a fully opaque 480 × 222 image, so the windowed canvas was
  keeping an unused copy of the previous screen and never canvas-caching it.
- `components/os_licenses.json`: both pages now use `back` instead of
  targeting `dashboard`. Targeting the boot dashboard pushed another copy of
  it onto the navigation stack on every round.

**Dashboard fixes**

- **Darkseclabz Desktop 11.0.1** — removed the six dashboard dock labels drawn
  by JSON over artwork that already contains the card titles, which caused
  overlapping words across the dock. The dashboard now uses empty `layers` plus
  full-screen `selected_layers`, so the baked-in dock and magnified selection
  render once.
- **Darkseclabz Hadal Station 1.0.1** — removed the duplicate room labels
  (`PAGER PORTAL`, `ALERTS`, `PAYLOADS`, `RECON`, `PINEAP`, `SETTINGS`) that were
  drawn over the background's baked-in labels. Selected rooms now show the room
  frame and room code (`AIRLOCK`, `EMERGENCY BEACON`, `SPECIMEN VAULT`,
  `SONAR ROOM`, `ANTENNA BAY`, `CONTROL ROOM`) without stacking text.
- Rebuilt every archive in `zips/` with a flat top-level theme folder.
- Removed a nested `darkseclabz-hadal/darkseclabz-hadal/` duplicate that had
  doubled the Hadal archive size.

### Earlier

- `darksecflipper`, `darksecskeleton` and `darkseclabz-numeric` were flattened
  from their wrapper folders and given unique internal theme names so they load
  instead of falling back to `wargames`.

## Credits

- Wargames base layouts by Hak5.
- Pocket Pager LCD base by Korben.
- Flipper Zero dolphin artwork from Flipper Devices (GPL-3.0; source and
  license are in `darksecflipper/artwork-source/`).

Physical device validation is still pending for parts of these themes. If you
find a layout problem on real hardware, open an issue or PR with a photo.

## Submitting a theme

1. Add `themes/<your-theme>/` with `theme.json`, `components/` and `assets/`.
2. Make sure every `components/` / `assets/` path in `theme.json` resolves.
3. Add the theme to the catalog and changelog above.
4. Rebuild its zip in `themes/zips/` with the theme folder at the archive root.
5. Open a PR.

Theme PRs are also welcome upstream at
[hak5/wifipineapplepager-themes](https://github.com/hak5/wifipineapplepager-themes).
