#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /path/to/ProjectX.app" >&2
  exit 1
fi

TARGET="$1"
xattr -dr com.apple.quarantine "$TARGET"
echo "Removed com.apple.quarantine from $TARGET"
