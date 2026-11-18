#!/bin/zsh
# Builds 一览.app next to this script.
#   ./build.sh            build only
#   ./build.sh --install  build, replace /Applications/一览.app and relaunch it
set -euo pipefail
cd "$(dirname "$0")"

swift build -c release

APP="build/一览.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp .build/release/VolumeMixer "$APP/Contents/MacOS/VolumeMixer"
cp Info.plist "$APP/Contents/Info.plist"

# A stable signing identity keeps the permissions (audio capture, accessibility, Desktop, keychain)
# across rebuilds; an ad-hoc signature changes every build and loses them each time.
# Override with YILAN_SIGN_IDENTITY, or set it to "-" to force ad-hoc.
IDENTITY="${YILAN_SIGN_IDENTITY-$(security find-identity -v -p codesigning 2>/dev/null \
    | awk -F'"' '/Apple Development|Developer ID Application/ { print $2; exit }')}"
if [[ -n "$IDENTITY" && "$IDENTITY" != "-" ]] && codesign --force --sign "$IDENTITY" "$APP" 2>/dev/null; then
    echo "Signed with: ${IDENTITY%% \(*}"
else
    codesign --force --sign - "$APP"
    echo "Signed ad-hoc (permissions will need to be granted again)"
fi

echo "Built $PWD/$APP"

if [[ "${1:-}" == "--install" ]]; then
    DEST="/Applications/一览.app"
    if pgrep -x VolumeMixer >/dev/null; then
        pkill -TERM -x VolumeMixer || true
        for _ in {1..50}; do pgrep -x VolumeMixer >/dev/null || break; sleep 0.1; done
    fi
    rm -rf "$DEST"
    cp -R "$APP" "$DEST"
    open "$DEST"
    echo "Installed and relaunched $DEST"
fi
