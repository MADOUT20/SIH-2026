#!/bin/bash
# Resolve symlinks to find the actual script location (macOS/Linux compatible)
TARGET_SCRIPT="$0"
while [ -L "$TARGET_SCRIPT" ]; do
  TARGET_SCRIPT="$(readlink "$TARGET_SCRIPT")"
done
SCRIPT_DIR="$(cd "$(dirname "$TARGET_SCRIPT")" && pwd)"

cd "$SCRIPT_DIR"

# Use the bundled virtual environment if it exists, otherwise fallback to system python3
if [ -f "$SCRIPT_DIR/venv/bin/python" ]; then
  "$SCRIPT_DIR/venv/bin/python" launch.py "$@"
else
  python3 launch.py "$@"
fi
