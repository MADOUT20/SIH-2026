#!/bin/bash
# NetGuard Global Setup for Mac/Linux

# Get the absolute path of the current directory
INSTALL_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BIN_LINK="/usr/local/bin/netguard"

echo "[*] Installing NetGuard as a global command..."

# Check if we have sudo permissions to write to /usr/local/bin
if [ -w "/usr/local/bin" ]; then
    ln -sf "$INSTALL_DIR/run.sh" "$BIN_LINK"
else
    echo "[!] Permission denied. Requesting sudo to create the global link..."
    sudo ln -sf "$INSTALL_DIR/run.sh" "$BIN_LINK"
fi

if [ -L "$BIN_LINK" ]; then
    echo "[+] Success! You can now run 'netguard' from any folder."
    echo "Example: netguard --file /path/to/your/file.pcap"
else
    echo "[-] Failed to create the global link."
fi
