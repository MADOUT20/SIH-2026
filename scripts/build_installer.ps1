$ErrorActionPreference = "Stop"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$DistDir = Join-Path $RootDir "dist\NetGuard"
$ZipFile = Join-Path $RootDir "dist\NetGuard-v1.0.0-Windows-x64.zip"

Write-Host "==================================================="
Write-Host "      BUILDING NETGUARD PRODUCTION INSTALLER       "
Write-Host "==================================================="
Write-Host ""

if (-not (Test-Path $DistDir)) {
    Write-Error "Portable package not found at $DistDir. Run package_dist.ps1 first!"
    exit 1
}

if (Test-Path $ZipFile) {
    Remove-Item -Force $ZipFile
}

Write-Host "Compressing NetGuard portable package into production installer archive:"
Write-Host "  Source: $DistDir"
Write-Host "  Destination: $ZipFile"
Write-Host ""

Compress-Archive -Path "$DistDir\*" -DestinationPath $ZipFile -CompressionLevel Optimal

$SizeBytes = (Get-Item $ZipFile).Length
$SizeMB = [math]::Round($SizeBytes / 1MB, 2)

Write-Host ""
Write-Host "==================================================="
Write-Host "INSTALLER CREATED SUCCESSFULLY!"
Write-Host "Archive Path: $ZipFile"
Write-Host "Package Size: $SizeMB MB ($SizeBytes bytes)"
Write-Host "==================================================="
