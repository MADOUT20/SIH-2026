#!/bin/bash
# Resolve symlinks to find the actual script location (macOS/Linux compatible)
TARGET_SCRIPT="$0"
while [ -L "$TARGET_SCRIPT" ]; do
  TARGET_SCRIPT="$(readlink "$TARGET_SCRIPT")"
done
SCRIPT_DIR="$(cd "$(dirname "$TARGET_SCRIPT")" && pwd)"

cd "$SCRIPT_DIR"
python3 launch.py "$@"
