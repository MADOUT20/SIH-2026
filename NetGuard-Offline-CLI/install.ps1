@(
$REPO_URL = "https://github.com/MADOUT20/SIH-2026.git"
$FOLDER_NAME = "NetGuard-CLI"
Write-Host "🚀 Starting NetGuard Universal Installation..." -ForegroundColor Cyan
git clone $REPO_URL $FOLDER_NAME
Set-Location "$FOLDER_NAME\NetGuard-Offline-CLI"

python -m venv venv
# Use direct path to pip to bypass execution policy blocks
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe -m pip install .

Write-Host "✅ Installation Complete!" -ForegroundColor Green
Write-Host "👉 To run the tool, use: .\venv\Scripts\python.exe -m main --demo"
)
