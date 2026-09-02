import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_cert():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    certs_dir = os.path.join(root_dir, "certs")
    os.makedirs(certs_dir, exist_ok=True)

    crt_path = os.path.join(certs_dir, "localhost.crt")
    key_path = os.path.join(certs_dir, "localhost.key")

    print("Generating 2048-bit RSA localhost SSL Certificate & Key...")

    # Generate Private Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate Certificate
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
        .sign(private_key, hashes.SHA256())
    )

    # Write Private Key (PEM, Traditional OpenSSL RSA Key format)
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Write Certificate (PEM)
    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Also copy into dist/NetGuard/certs if it exists
    dist_certs = os.path.join(root_dir, "dist", "NetGuard", "certs")
    if os.path.exists(os.path.join(root_dir, "dist", "NetGuard")):
        os.makedirs(dist_certs, exist_ok=True)
        with open(os.path.join(dist_certs, "localhost.crt"), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(os.path.join(dist_certs, "localhost.key"), "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    print(f"SUCCESS: Generated CRT ({crt_path}) and KEY ({key_path})")

def python_ip_address(ip_str):
    import ipaddress
    return ipaddress.ip_address(ip_str)

if __name__ == "__main__":
    generate_cert()
