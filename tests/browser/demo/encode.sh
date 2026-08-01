#!/usr/bin/env bash
# Turns the raw Playwright capture into the files shipped with the docs.
#
#   ./encode.sh            # encode out/autentico-demo.webm
#   ./encode.sh path.webm  # encode a specific capture
#
# Produces, next to the source:
#   autentico-demo.webp      full-length animated WebP, the README hero
#   autentico-demo.mp4       H.264, for docs, social and click-to-play embeds
#   autentico-demo-vp9.webm  VP9, smaller, for the docs site
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${1:-$HERE/out/autentico-demo.webm}"
OUT="$(dirname "$SRC")"

# Frame rate and width of the animated WebP hero.
WEBP_FPS=${WEBP_FPS:-12}
WEBP_WIDTH=${WEBP_WIDTH:-800}
WEBP_Q=${WEBP_Q:-70}

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

# Animated WebP. GitHub strips `autoplay` and `loop` from <video>, so the only
# thing that plays by itself in a README is an animated image; WebP is roughly
# an order of magnitude smaller than the equivalent GIF and keeps full colour.
ffmpeg -v error -stats -y -i "$SRC" \
  -vf "fps=$WEBP_FPS,scale=$WEBP_WIDTH:-1:flags=lanczos" \
  -c:v libwebp_anim -q:v "$WEBP_Q" -compression_level 6 -loop 0 -an \
  "$OUT/autentico-demo.webp"

echo
ls -lh "$OUT"/autentico-demo.webp "$OUT"/autentico-demo.mp4 "$OUT"/autentico-demo-vp9.webm
