#!/usr/bin/env bash
# Rasterize the Egret brand SVGs to PNGs for places that need bitmaps (GitHub
# social preview, Marketplace/App listing icon, apple-touch-icon). The SVGs are
# the source of truth; regenerate PNGs whenever they change.
#
# Uses whichever rasterizer is installed (in order): rsvg-convert, inkscape,
# cairosvg. Install one, e.g.:  sudo apt-get install librsvg2-bin
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p png

render() { # <in.svg> <out.png> <w> <h>
  local in="$1" out="png/$2" w="$3" h="$4"
  if command -v rsvg-convert >/dev/null 2>&1; then
    rsvg-convert -w "$w" -h "$h" "$in" -o "$out"
  elif command -v inkscape >/dev/null 2>&1; then
    inkscape "$in" --export-type=png --export-filename="$out" -w "$w" -h "$h" >/dev/null 2>&1
  elif command -v cairosvg >/dev/null 2>&1; then
    cairosvg "$in" -o "$out" --output-width "$w" --output-height "$h"
  else
    echo "No SVG rasterizer found (install librsvg2-bin / inkscape / cairosvg)." >&2
    exit 1
  fi
  echo "  $out (${w}x${h})"
}

echo "Rendering PNGs:"
render icon.svg           favicon-32.png        32   32
render icon.svg           favicon-180.png       180  180   # apple-touch-icon
render app-icon.svg       app-icon-512.png      512  512   # Marketplace / App listing
render logo.svg           logo.png              640  180
render social-preview.svg social-preview.png    1280 640   # GitHub Settings → Social preview
echo "Done. PNGs are in branding/png/ (git-ignored — regenerate as needed)."
