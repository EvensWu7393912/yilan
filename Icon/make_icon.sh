#!/bin/zsh
# Regenerates Icon/AppIcon.icns and Icon/AppIcon.png from make_icon.swift.
set -euo pipefail
cd "$(dirname "$0")"
SET="$(mktemp -d)/AppIcon.iconset"
mkdir -p "$SET"
for sz in 16 32 128 256 512; do
    swift make_icon.swift "$SET/icon_${sz}x${sz}.png" $sz
    swift make_icon.swift "$SET/icon_${sz}x${sz}@2x.png" $((sz * 2))
done
iconutil -c icns "$SET" -o AppIcon.icns
cp "$SET/icon_512x512@2x.png" AppIcon.png
echo "Wrote $PWD/AppIcon.icns"
