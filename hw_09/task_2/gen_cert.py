from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes

# Loading the private key

with open("server.key", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Generating the CSR

csr = (
    x509.CertificateSigningRequestBuilder()
    .subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Kyiv"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Robot_dreams"),
        x509.NameAttribute(NameOID.COMMON_NAME, "www.robotdreams.cc"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "youremail@example.com"),
    ]))
    .sign(private_key, hashes.SHA256())
)

# Saving the CSR to a file

with open("server.csr", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))
