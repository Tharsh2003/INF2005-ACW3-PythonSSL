
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Create certificates folder
CERT_DIR = Path(__file__).resolve().parent / "certs"
CERT_DIR.mkdir(exist_ok=True)

# Set certificate validity period
now = datetime.now(timezone.utc)

# Generate CA private key
ca_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Create CA certificate
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "ACW3 Test CA")
])

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(minutes=1))
    .not_valid_after(now + timedelta(days=7))
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(
            ca_key.public_key()
        ),
        critical=False
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    .sign(ca_key, hashes.SHA256())
)

# Generate TLS server private key
server_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Create TLS server certificate
server_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "attacker.test")
])

server_cert = (
    x509.CertificateBuilder()
    .subject_name(server_name)
    .issuer_name(ca_name)
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(minutes=1))
    .not_valid_after(now + timedelta(days=7))
    .add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("attacker.test")
        ]),
        critical=False
    )
    .add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH
        ]),
        critical=False
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(
            server_key.public_key()
        ),
        critical=False
    )
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            ca_key.public_key()
        ),
        critical=False
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    .sign(ca_key, hashes.SHA256())
)

# Save private keys
def save_key(filename, key):
    with open(CERT_DIR / filename, "wb") as file:
        file.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

# Save certificates
def save_cert(filename, cert):
    with open(CERT_DIR / filename, "wb") as file:
        file.write(
            cert.public_bytes(serialization.Encoding.PEM)
        )

# Save CA certificate and private key
save_key("ca.key", ca_key)
save_cert("ca.crt", ca_cert)

# Save TLS server certificate and private key
save_key("server.key", server_key)
save_cert("server.crt", server_cert)

print("TLS certificates generated successfully!")
print("CA certificate: certs/ca.crt")
print("Server certificate: certs/server.crt")
print("Server hostname: attacker.test")
