$ErrorActionPreference = "Stop"

$CertDir = Join-Path $PSScriptRoot "..\certs"
if (-not (Test-Path $CertDir)) {
    New-Item -ItemType Directory -Path $CertDir | Out-Null
}

$CrtPath = Join-Path $CertDir "localhost.crt"
$KeyPath = Join-Path $CertDir "localhost.key"

Write-Host "Creating localhost RSA SSL Certificate..."

$cert = New-SelfSignedCertificate -Subject "CN=localhost" -DnsName "localhost", "127.0.0.1" -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(5) -KeyExportPolicy Exportable -KeyUsage DigitalSignature, KeyEncipherment -Type Custom -HashAlgorithm SHA256

$certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$certPem = "-----BEGIN CERTIFICATE-----`n" + [System.Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks) + "`n-----END CERTIFICATE-----`n"
Set-Content -Path $CrtPath -Value $certPem -Encoding ascii

$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
$keyBytes = $rsa.ExportRSAPrivateKey()
$keyPem = "-----BEGIN RSA PRIVATE KEY-----`n" + [System.Convert]::ToBase64String($keyBytes, [System.Base64FormattingOptions]::InsertLineBreaks) + "`n-----END RSA PRIVATE KEY-----`n"
Set-Content -Path $KeyPath -Value $keyPem -Encoding ascii

Write-Host "SUCCESS: Generated CRT ($CrtPath) and KEY ($KeyPath)"
