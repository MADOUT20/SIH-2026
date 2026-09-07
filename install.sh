#!/bin/bash
REPO_URL="https://github.com/MADOUT20/SIH-2026.git"
FOLDER_NAME="NetGuard-CLI"
echo "🚀 Starting NetGuard Universal Installation..."
git clone $REPO_URL $FOLDER_NAME
cd $FOLDER_NAME
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install .
echo "✅ Installation Complete!"
echo "👉 To run the tool, use: source venv/bin/activate && python3 -m NetGuard-Offline-CLI.main --demo"
