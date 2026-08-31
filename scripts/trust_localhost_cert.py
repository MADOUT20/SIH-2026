import os
import sys
import datetime
import subprocess
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def setup_trusted_cert():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    certs_dir = os.path.join(root_dir, "certs")
    os.makedirs(certs_dir, exist_ok=True)

    crt_path = os.path.join(certs_dir, "localhost.crt")
    key_path = os.path.join(certs_dir, "localhost.key")

    print("Generating trusted 2048-bit RSA localhost SSL Certificate & Private Key...")

    # Generate Private Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate Certificate with SAN for localhost and 127.0.0.1
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"NetGuard"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1825))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"localhost"),
                x509.IPAddress(python_ip_address("127.0.0.1"))
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    crt_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(crt_path, "wb") as f:
        f.write(crt_pem)
    with open(key_path, "wb") as f:
        f.write(key_pem)

    # Also copy into dist/NetGuard/certs if present
    dist_certs = os.path.join(root_dir, "dist", "NetGuard", "certs")
    if os.path.exists(os.path.join(root_dir, "dist", "NetGuard")):
        os.makedirs(dist_certs, exist_ok=True)
        with open(os.path.join(dist_certs, "localhost.crt"), "wb") as f:
            f.write(crt_pem)
        with open(os.path.join(dist_certs, "localhost.key"), "wb") as f:
            f.write(key_pem)

    print(f"  [PASS] Written CRT ({crt_path}) and KEY ({key_path})")

    # Import CRT into Windows Trusted Root Store via PowerShell / certutil
    print("Importing localhost certificate into Windows Trusted Root Certification Authorities...")
    ps_import = f"""
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{crt_path}')
    try {{
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
        $store.Open("ReadWrite")
        $store.Add($cert)
        $store.Close()
        Write-Host "SUCCESS: Certificate imported into CurrentUser Root store."
    }} catch {{
        Write-Host "CurrentUser Root store import failed: $_"
    }}

    try {{
        net session >$null 2>&1
        if ($LASTEXITCODE -eq 0) {{
            $lmStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
            $lmStore.Open("ReadWrite")
            $lmStore.Add($cert)
            $lmStore.Close()
            Write-Host "SUCCESS: Certificate imported into LocalMachine Root store."
        }}
    }} catch {{}}
    """

    res = subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_import], capture_output=True, text=True)
    print("  Import Output:\n", res.stdout.strip())
    return True

def python_ip_address(ip_str):
    import ipaddress
    return ipaddress.ip_address(ip_str)

if __name__ == "__main__":
    setup_trusted_cert()
