#!/usr/bin/env bash
set -euo pipefail

APP_NAME="ProjectX"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_SOURCE="$ROOT_DIR/bin/$APP_NAME"
DESKTOP_SOURCE="$ROOT_DIR/share/applications/projectx.desktop"
ICON_SOURCE="$ROOT_DIR/share/icons/hicolor/256x256/apps/projectx.png"

BIN_TARGET="$HOME/.local/bin/$APP_NAME"
DESKTOP_TARGET="$HOME/.local/share/applications/projectx.desktop"
ICON_TARGET="$HOME/.local/share/icons/hicolor/256x256/apps/projectx.png"

mkdir -p "$(dirname "$BIN_TARGET")" "$(dirname "$DESKTOP_TARGET")" "$(dirname "$ICON_TARGET")"
cp "$BIN_SOURCE" "$BIN_TARGET"
chmod +x "$BIN_TARGET"
sed "s|@EXEC_PATH@|$BIN_TARGET|g" "$DESKTOP_SOURCE" > "$DESKTOP_TARGET"
cp "$ICON_SOURCE" "$ICON_TARGET"

echo "Installed $APP_NAME to $BIN_TARGET"
echo "Desktop entry written to $DESKTOP_TARGET"
