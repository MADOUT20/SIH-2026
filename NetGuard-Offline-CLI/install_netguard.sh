#!/bin/bash
# NetGuard Global Installer
# This script is designed to be run via: curl -sSL https://your-domain.com/install.sh | bash

set -e

# --- CONFIGURATION ---
# Replace these URLs with the actual links where you host the files
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

# 4. Install Dependencies
echo "[*] Installing AI dependencies (PyTorch, Scapy, Pandas)..."
# Check if python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed. Please install Python 3.8+ first."
    exit 1
fi

# Install requirements from the extracted folder
python3 "$INSTALL_DIR/requirements.txt" || python3 -m pip install -r "$INSTALL_DIR/requirements.txt"

# 5. Create Global Symbolic Link
echo "[*] Creating global command 'netguard'..."
if [ -w "/usr/local/bin" ]; then
    ln -sf "$INSTALL_DIR/run.sh" "$BIN_LINK"
else
    echo "[!] Requesting sudo to create global link..."
    sudo ln -sf "$INSTALL_DIR/run.sh" "$BIN_LINK"
fi

echo "------------------------------------------------------------"
echo "✅ Installation Complete!"
echo "You can now analyze network traffic from any folder using:"
echo "  netguard --file /path/to/your/file.pcap"
echo "------------------------------------------------------------"
