#!/bin/bash
# NetGuard Global Installer
# This script is designed to be run via: curl -sSL https://your-domain.com/install.sh | bash

set -e

# --- CONFIGURATION ---
# Use the verified GitHub Release asset
PACKAGE_URL="https://github.com/MADOUT20/SIH-2026/releases/download/v1.0.0/netguard-cli.zip"
INSTALL_DIR="$HOME/.netguard"
BIN_LINK="/usr/local/bin/netguard"

echo "------------------------------------------------------------"
echo "🚀 Installing NetGuard Offline AI Attack Forecaster"
echo "------------------------------------------------------------"

# 1. Create installation directory
echo "[*] Creating installation directory at $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# 2. Download the package
echo "[*] Downloading NetGuard assets..."
curl -L "$PACKAGE_URL" -o "$INSTALL_DIR/netguard-cli.zip"

# 3. Unzip the package
echo "[*] Extracting files..."
unzip -q "$INSTALL_DIR/netguard-cli.zip" -d "$INSTALL_DIR"
rm "$INSTALL_DIR/netguard-cli.zip"

# 4. Resolve actual extracted directory
# Since the ZIP contains a root folder 'netguard-cli', the files are in $INSTALL_DIR/netguard-cli/
# We look for the folder that contains 'requirements.txt' to be absolutely sure.
ACTUAL_DIR=""
for d in "$INSTALL_DIR"/*; do
    if [ -f "$d/requirements.txt" ]; then
        ACTUAL_DIR="$d"
        break
    fi
done

if [ -z "$ACTUAL_DIR" ]; then
    echo "Error: Could not find requirements.txt in the extracted package."
    exit 1
fi

echo "[*] Found application directory: $ACTUAL_DIR"

# 5. Install Dependencies
echo "[*] Installing AI dependencies (PyTorch, Scapy, Pandas)..."
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed. Please install Python 3.8+ first."
    exit 1
fi

# CORRECTED: Use pip to install requirements
python3 -m pip install -r "$ACTUAL_DIR/requirements.txt"

# 6. Create Global Symbolic Link
echo "[*] Creating global command 'netguard'..."
# The executable is run.sh inside the actual directory
TARGET_EXEC="$ACTUAL_DIR/run.sh"

if [ -w "/usr/local/bin" ]; then
    ln -sf "$TARGET_EXEC" "$BIN_LINK"
else
    echo "[!] Requesting sudo to create global link in /usr/local/bin..."
    sudo ln -sf "$TARGET_EXEC" "$BIN_LINK"
fi

echo "------------------------------------------------------------"
echo "✅ Installation Complete!"
echo "You can now analyze network traffic from any folder using:"
echo "  netguard --file /path/to/your/file.pcap"
echo "------------------------------------------------------------"
