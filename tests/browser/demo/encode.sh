#!/usr/bin/env bash
# Turns the raw Playwright capture into the files shipped with the docs.
#
#   ./encode.sh            # encode out/autentico-demo.webm
#   ./encode.sh path.webm  # encode a specific capture
#
# Produces, next to the source:
#   autentico-demo.mp4       H.264, the version to embed (GitHub, docs, social)
#   autentico-demo-vp9.webm  VP9, smaller, for the docs site
#   autentico-demo.gif       short teaser loop for the README
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${1:-$HERE/out/autentico-demo.webm}"
OUT="$(dirname "$SRC")"

# The teaser covers onboarding through the client being created.
GIF_START=${GIF_START:-14}
GIF_LEN=${GIF_LEN:-16}

echo "source: $SRC"

# H.264 — yuv420p and faststart so it plays everywhere, including Safari and
# in-browser previews.
ffmpeg -v error -stats -y -i "$SRC" \
  -c:v libx264 -preset slow -crf 22 -pix_fmt yuv420p \
  -movflags +faststart -an \
  "$OUT/autentico-demo.mp4"

# VP9 — noticeably smaller than the VP8 capture at the same quality.
ffmpeg -v error -stats -y -i "$SRC" \
  -c:v libvpx-vp9 -crf 34 -b:v 0 -row-mt 1 -deadline good -cpu-used 2 -an \
  "$OUT/autentico-demo-vp9.webm"

# GIF teaser — two passes so the palette is built from the clip itself.
ffmpeg -v error -y -ss "$GIF_START" -t "$GIF_LEN" -i "$SRC" \
  -vf "fps=12,scale=800:-1:flags=lanczos,palettegen=stats_mode=diff" \
  "$OUT/.palette.png"
ffmpeg -v error -stats -y -ss "$GIF_START" -t "$GIF_LEN" -i "$SRC" -i "$OUT/.palette.png" \
  -lavfi "fps=12,scale=800:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=3" \
  "$OUT/autentico-demo.gif"
rm -f "$OUT/.palette.png"

echo
ls -lh "$OUT"/autentico-demo.mp4 "$OUT"/autentico-demo-vp9.webm "$OUT"/autentico-demo.gif
