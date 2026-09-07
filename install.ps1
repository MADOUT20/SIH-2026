@(
$REPO_URL = "https://github.com/MADOUT20/SIH-2026.git"
$FOLDER_NAME = "NetGuard-CLI"
Write-Host "🚀 Starting NetGuard Universal Installation..." -ForegroundColor Cyan
git clone $REPO_URL $FOLDER_NAME
Set-Location $FOLDER_NAME
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install .
Write-Host "✅ Installation Complete!" -ForegroundColor Green
Write-Host "👉 To run the tool, use: .\venv\Scripts\python.exe -m NetGuard-Offline-CLI.main --demo"
)
