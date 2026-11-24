#!/bin/sh
set -eu

cd "$(dirname "$0")"
configuration="${1:-debug}"
case "$configuration" in debug|release) ;; *) exit 2 ;; esac

swift build -c "$configuration" --product QualysClient >&2
bin_dir="$(swift build -c "$configuration" --show-bin-path)"
app="$bin_dir/Qualys Client.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin_dir/QualysClient" "$app/Contents/MacOS/"
cp QualysClient-Info.plist "$app/Contents/Info.plist"
cp Resources/QualysClient.icns "$app/Contents/Resources/"
codesign --force --sign - "$app"
printf '%s\n' "$app"
