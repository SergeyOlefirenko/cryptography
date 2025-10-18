from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime, timedelta, timezone

# Private key loading
with open("server.key", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Self-signed certificate generation
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Kyiv"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Robot_dreams"),
    x509.NameAttribute(NameOID.COMMON_NAME, "www.robotdreams.cc"),
    x509.NameAttribute(NameOID.EMAIL_ADDRESS, "youremail@example.com"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    .sign(private_key, hashes.SHA256())
)

# Certificate file saving
with open("server.crt", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))



