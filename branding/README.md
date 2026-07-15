# Egret — Brand assets

This directory is the **single source of truth** for Egret's visual identity.
It is **duplicated verbatim** in both repositories:

- `NX1X/Egret` — the agent (CLI + GitHub Action)
- `NX1X/Egret-Nest-Dashboard` — the dashboard

Both projects share the **same logo, icon, wordmark, palette, and typography** —
they are one product family. The **only** asset that differs between the two is
the GitHub **social preview** (`social-preview.svg`), whose title names the
specific component:

| Repo | Social-preview title |
|---|---|
| Egret (agent) | **Egret** — runtime egress security for CI/CD |
| Egret Nest Dashboard | **Egret Nest** — the dashboard for your Egret fleet |

Keep the two copies in sync: when an asset changes, update it in **both** repos
in the same change. Only `social-preview.svg` is allowed to differ.

## Assets

| File | Use | Shared? |
|---|---|---|
| `logo.svg` | Horizontal wordmark (README header, docs, dashboard nav) | ✅ identical |
| `icon.svg` | Square app icon / avatar / **favicon** source (256²) | ✅ identical |
| `app-icon.svg` | Marketplace / GitHub App **listing icon** (512², padded tile + teal egress glow) | ✅ identical |
| `social-preview.svg` | GitHub repo social preview (1280×640) | ⚠️ per-repo title |
| `export.sh` | Rasterize all SVGs → `png/` at the sizes GitHub/marketplaces need | ✅ identical |

## Palette

| Token | Hex | Use |
|---|---|---|
| Ink | `#0B1B2B` | Primary ground (dark) |
| Slate | `#13293D` | Panels / secondary ground |
| Egret white | `#F5F7FA` | The bird, on-dark text |
| Feather teal | `#2DD4BF` | Primary accent (the "egress" line) |
| Signal amber | `#F5B54B` | Warning / block-mode accent (use sparingly) |

## Typography

- **Display / wordmark:** a geometric humanist sans (e.g. *Space Grotesk*,
  *Inter Tight*). The SVGs ship the wordmark as **outlined paths / system
  fallback** so they render without a webfont.
- **Body:** *Inter* / system-ui.

## Exporting raster assets

The SVGs are the masters. Run `./export.sh` to generate every PNG into `png/`
(favicon 32, apple-touch 180, app-icon 512, logo, social-preview 1280×640). It
uses whichever rasterizer is installed — `rsvg-convert` (`sudo apt-get install
librsvg2-bin`), `inkscape`, or `cairosvg`:

```bash
./export.sh
```

Then upload `png/social-preview.png` under **repo → Settings → Social preview**,
and use `png/app-icon-512.png` for the GitHub App / Marketplace listing icon.
(`png/` is git-ignored — regenerate as assets change.)

## Status

Vector identity is complete: `logo.svg`, `icon.svg` (favicon source),
`app-icon.svg` (marketplace/App listing icon), per-repo `social-preview.svg`, and
the `export.sh` raster pipeline. The dashboard UI renders this palette directly in
its stylesheet. Remaining polish (an animated logo variant, hand-kerned wordmark
outlines) is tracked in each repo's `docs/ROADMAP.md` under **Branding**.
