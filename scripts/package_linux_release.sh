#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/release-artifacts/linux}"
APP_NAME="ProjectX"
BIN_PATH="$ROOT_DIR/target/release/$APP_NAME"
PACKAGE_DIR="$OUT_DIR/$APP_NAME-linux-portable"
ICONSET_DIR="$OUT_DIR/icon.iconset"
ICON_PATH="$PACKAGE_DIR/share/icons/hicolor/256x256/apps/projectx.png"
DESKTOP_DIR="$PACKAGE_DIR/share/applications"
DESKTOP_PATH="$DESKTOP_DIR/projectx.desktop"
ARCHIVE_PATH="$OUT_DIR/$APP_NAME-linux.tar.gz"

if [[ ! -x "$BIN_PATH" ]]; then
  echo "Missing release binary at $BIN_PATH" >&2
  echo "Run: cargo build --release --locked" >&2
  exit 1
fi

rm -rf "$PACKAGE_DIR" "$ICONSET_DIR" "$ARCHIVE_PATH" "$ARCHIVE_PATH.sha256"
mkdir -p "$PACKAGE_DIR/bin" "$(dirname "$ICON_PATH")" "$DESKTOP_DIR" "$ICONSET_DIR"

cp "$BIN_PATH" "$PACKAGE_DIR/bin/$APP_NAME"
chmod +x "$PACKAGE_DIR/bin/$APP_NAME"
cp "$ROOT_DIR/README.md" "$ROOT_DIR/LICENSE" "$PACKAGE_DIR/"
python3 "$ROOT_DIR/scripts/make_px_icon.py" "$ICONSET_DIR"
cp "$ICONSET_DIR/icon_256x256.png" "$ICON_PATH"
cp "$ROOT_DIR/packaging/linux/install.sh" "$PACKAGE_DIR/install.sh"
chmod +x "$PACKAGE_DIR/install.sh"

sed \
  -e "s|@APP_NAME@|$APP_NAME|g" \
  -e "s|@ICON_NAME@|projectx|g" \
  "$ROOT_DIR/packaging/linux/projectx.desktop.in" > "$DESKTOP_PATH"

tar -czf "$ARCHIVE_PATH" -C "$OUT_DIR" "$(basename "$PACKAGE_DIR")"
sha256sum "$ARCHIVE_PATH" > "$ARCHIVE_PATH.sha256"

echo "Created Linux portable release: $ARCHIVE_PATH"
