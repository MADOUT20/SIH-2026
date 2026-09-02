$ErrorActionPreference = "Stop"

$CertDir = Join-Path $PSScriptRoot "..\certs"
if (-not (Test-Path $CertDir)) {
    New-Item -ItemType Directory -Path $CertDir | Out-Null
}

$CrtPath = Join-Path $CertDir "localhost.crt"
$KeyPath = Join-Path $CertDir "localhost.key"

if ((Test-Path $CrtPath) -and (Test-Path $KeyPath)) {
    Write-Host "Localhost certificate already exists at $CertDir"
    exit 0
}

Write-Host "Generating trusted localhost SSL certificate for NetGuard..."

# Check Administrator privileges to choose CertStoreLocation
$isAdmin = $false
try {
    net session >$null 2>&1
    if ($LASTEXITCODE -eq 0) { $isAdmin = $true }
} catch {}

$storeLocation = if ($isAdmin) { "Cert:\LocalMachine\My" } else { "Cert:\CurrentUser\My" }
$rootStoreLocation = if ($isAdmin) { "LocalMachine" } else { "CurrentUser" }

Write-Host "Using Certificate Store: $storeLocation (Admin: $isAdmin)"

$cert = New-SelfSignedCertificate -Subject "CN=localhost" -DnsName "localhost", "127.0.0.1" -CertStoreLocation $storeLocation -NotAfter (Get-Date).AddYears(5) -KeyExportPolicy Exportable -KeyUsage DigitalSignature, KeyEncipherment -Type Custom -HashAlgorithm SHA256

# Add to Trusted Root Certification Authorities so Edge/Chrome/Brave trust https://localhost/
try {
    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", $rootStoreLocation)
    $rootStore.Open("ReadWrite")
    $rootStore.Add($cert)
    $rootStore.Close()
    Write-Host "Imported localhost cert into $rootStoreLocation Root store."
} catch {
    Write-Host "Notice: Root store import note: $_"
}

# Export public CRT (PEM)
$certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$certPem = "-----BEGIN CERTIFICATE-----`n" + [System.Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks) + "`n-----END CERTIFICATE-----`n"
Set-Content -Path $CrtPath -Value $certPem -Encoding ascii

# Export private KEY (PEM) via RSACertificateExtensions
try {
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if ($rsa) {
        $keyBytes = $rsa.ExportPkcs8PrivateKey()
        $keyPem = "-----BEGIN PRIVATE KEY-----`n" + [System.Convert]::ToBase64String($keyBytes, [System.Base64FormattingOptions]::InsertLineBreaks) + "`n-----END PRIVATE KEY-----`n"
        Set-Content -Path $KeyPath -Value $keyPem -Encoding ascii
        Write-Host "Exported private key to $KeyPath"
    }
} catch {
    Write-Host "Key export warning: $_"
}

Write-Host "Localhost SSL certificate generated successfully!"
