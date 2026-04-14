#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/release-artifacts/macos}"
APP_NAME="ProjectX"
APP_BUNDLE="$OUT_DIR/$APP_NAME.app"
CONTENTS_DIR="$APP_BUNDLE/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
ICONSET_DIR="$OUT_DIR/icon.iconset"
SOURCE_ICON_DIR="$OUT_DIR/icon-source"
DMG_STAGE_DIR="$OUT_DIR/dmg"
DMG_PATH="$OUT_DIR/$APP_NAME-macos.dmg"
BIN_PATH="$ROOT_DIR/target/release/$APP_NAME"
VERSION="${PROJECTX_VERSION:-$(sed -n 's/^version = \"\\(.*\\)\"/\\1/p' "$ROOT_DIR/Cargo.toml" | head -n1)}"
VERSION="${VERSION#v}"
BUILD_NUMBER="${PROJECTX_BUILD_NUMBER:-1}"
ADHOC_SIGN="${PROJECTX_ADHOC_SIGN:-1}"

if [[ ! -x "$BIN_PATH" ]]; then
  echo "Missing release binary at $BIN_PATH" >&2
  echo "Run: cargo build --release --locked" >&2
  exit 1
fi

rm -rf "$APP_BUNDLE" "$ICONSET_DIR" "$SOURCE_ICON_DIR" "$DMG_STAGE_DIR" "$DMG_PATH"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR" "$ICONSET_DIR" "$SOURCE_ICON_DIR" "$DMG_STAGE_DIR"

cp "$BIN_PATH" "$MACOS_DIR/$APP_NAME"
chmod +x "$MACOS_DIR/$APP_NAME"
cp "$ROOT_DIR/README.md" "$ROOT_DIR/LICENSE" "$RESOURCES_DIR/"

python3 "$ROOT_DIR/scripts/make_px_icon.py" "$SOURCE_ICON_DIR"
MASTER_PNG="$SOURCE_ICON_DIR/icon_512x512@2x.png"
sips -z 16 16 "$MASTER_PNG" --out "$ICONSET_DIR/icon_16x16.png" >/dev/null
sips -z 32 32 "$MASTER_PNG" --out "$ICONSET_DIR/icon_16x16@2x.png" >/dev/null
sips -z 32 32 "$MASTER_PNG" --out "$ICONSET_DIR/icon_32x32.png" >/dev/null
sips -z 64 64 "$MASTER_PNG" --out "$ICONSET_DIR/icon_32x32@2x.png" >/dev/null
sips -z 128 128 "$MASTER_PNG" --out "$ICONSET_DIR/icon_128x128.png" >/dev/null
sips -z 256 256 "$MASTER_PNG" --out "$ICONSET_DIR/icon_128x128@2x.png" >/dev/null
sips -z 256 256 "$MASTER_PNG" --out "$ICONSET_DIR/icon_256x256.png" >/dev/null
sips -z 512 512 "$MASTER_PNG" --out "$ICONSET_DIR/icon_256x256@2x.png" >/dev/null
sips -z 512 512 "$MASTER_PNG" --out "$ICONSET_DIR/icon_512x512.png" >/dev/null
cp "$MASTER_PNG" "$ICONSET_DIR/icon_512x512@2x.png"
ICON_PLIST_BLOCK=""
if iconutil -c icns "$ICONSET_DIR" -o "$RESOURCES_DIR/$APP_NAME.icns"; then
  ICON_PLIST_BLOCK=$'  <key>CFBundleIconFile</key>\n  <string>'"$APP_NAME"$'.icns</string>'
else
  rm -f "$RESOURCES_DIR/$APP_NAME.icns"
  echo "iconutil could not produce an .icns file; continuing with the default macOS app icon." >&2
fi

cat > "$CONTENTS_DIR/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>$APP_NAME</string>
  <key>CFBundleExecutable</key>
  <string>$APP_NAME</string>
$ICON_PLIST_BLOCK
  <key>CFBundleIdentifier</key>
  <string>com.coltgorman.projectx</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>$APP_NAME</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$VERSION</string>
  <key>CFBundleVersion</key>
  <string>$BUILD_NUMBER</string>
  <key>LSApplicationCategoryType</key>
  <string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
EOF

xattr -cr "$APP_BUNDLE" || true
/usr/libexec/PlistBuddy -c "Add :CFBundleSignature string PXSC" "$CONTENTS_DIR/Info.plist" || true

if [[ "$ADHOC_SIGN" == "1" ]]; then
  codesign --force --deep --sign - "$APP_BUNDLE"
  codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"
fi

cp -R "$APP_BUNDLE" "$DMG_STAGE_DIR/"
ln -s /Applications "$DMG_STAGE_DIR/Applications"
hdiutil create -volname "$APP_NAME" -srcfolder "$DMG_STAGE_DIR" -ov -format UDZO -fs HFS+ "$DMG_PATH"
shasum -a 256 "$DMG_PATH" > "$DMG_PATH.sha256"

echo "Created macOS app bundle: $APP_BUNDLE"
echo "Created macOS DMG: $DMG_PATH"
