from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from binascii import hexlify
from hashlib import sha256
import os, sys


# Functions for saving or loading RSA keys

def generate_and_save_rsa_keys(private_path: str, public_path: str):
    """Generates an RSA key pair and saves them to PEM files."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(private_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    with open(public_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(f"New RSA key pair generated and saved: {private_path}, {public_path}")
    return private_key, public_key


def load_rsa_keys(private_path: str, public_path: str):
    """Loads RSA keys from files (or generates them if they don’t exist)."""
    if not (os.path.exists(private_path) and os.path.exists(public_path)):
        return generate_and_save_rsa_keys(private_path, public_path)

    with open(private_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(public_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key


def fingerprint_rsa(pubkey):
    """Computes the SHA256 fingerprint of an RSA public key."""
    pem = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return sha256(pem).hexdigest()

# 1. Load or generate RSA keys for Alice and Bob


alice_priv_path = "alice_private.pem"
alice_pub_path = "alice_public.pem"
bob_priv_path = "bob_private.pem"
bob_pub_path = "bob_public.pem"

alice_rsa_private, alice_rsa_public = load_rsa_keys(alice_priv_path, alice_pub_path)
bob_rsa_private, bob_rsa_public = load_rsa_keys(bob_priv_path, bob_pub_path)

print("Alice RSA public fingerprint (SHA256):", fingerprint_rsa(alice_rsa_public))
print("Bob   RSA public fingerprint (SHA256):", fingerprint_rsa(bob_rsa_public))
print()

# 2. Generate shared DH parameters (p, g)


parameters = dh.generate_parameters(generator=2, key_size=2048)
print("DH parameters generated.\n")

# 3. Each party generates their DH key pair


alice_private_dh = parameters.generate_private_key()
bob_private_dh = parameters.generate_private_key()
alice_public_dh = alice_private_dh.public_key()
bob_public_dh = bob_private_dh.public_key()

alice_pub_bytes = alice_public_dh.public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo
)
bob_pub_bytes = bob_public_dh.public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo
)


# 4. Alice signs her DH public key


alice_nonce = os.urandom(16)
alice_to_sign = b"Alice||" + alice_nonce + b"||" + alice_pub_bytes

alice_signature = alice_rsa_private.sign(
    alice_to_sign,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

channel_alice_to_bob = {
    "pub_bytes": alice_pub_bytes,
    "signature": alice_signature,
    "nonce": alice_nonce,
    "rsa_pub_bytes": alice_rsa_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ),
}

# 5. Bob verifies Alice’s signature


received = channel_alice_to_bob
received_pub = received["pub_bytes"]
received_sig = received["signature"]
received_nonce = received["nonce"]
received_rsa_pem = received["rsa_pub_bytes"]

alice_pub_from_channel = serialization.load_pem_public_key(received_rsa_pem)
expected_data = b"Alice||" + received_nonce + b"||" + received_pub

try:
    alice_pub_from_channel.verify(
        received_sig,
        expected_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("Alice’s signature verified by Bob.")
except InvalidSignature:
    sys.exit("Signature verification failed on Bob’s side.")



# 6. Bob signs his DH public key


bob_nonce = os.urandom(16)
bob_to_sign = b"Bob||" + bob_nonce + b"||" + bob_pub_bytes

bob_signature = bob_rsa_private.sign(
    bob_to_sign,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

channel_bob_to_alice = {
    "pub_bytes": bob_pub_bytes,
    "signature": bob_signature,
    "nonce": bob_nonce,
    "rsa_pub_bytes": bob_rsa_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ),
}


# 7. Alice verifies Bob’s signature


received_bob = channel_bob_to_alice
rb_pub = received_bob["pub_bytes"]
rb_sig = received_bob["signature"]
rb_nonce = received_bob["nonce"]
rb_rsa_pem = received_bob["rsa_pub_bytes"]

bob_pub_from_channel = serialization.load_pem_public_key(rb_rsa_pem)
expected_bob_data = b"Bob||" + rb_nonce + b"||" + rb_pub

try:
    bob_pub_from_channel.verify(
        rb_sig,
        expected_bob_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("Bob’s signature verified by Alice.")
except InvalidSignature:
    sys.exit("Signature verification failed on Alice’s side.")


# 8. Compute shared secret


alice_shared = alice_private_dh.exchange(bob_public_dh)
bob_shared = bob_private_dh.exchange(alice_public_dh)


# 9. Derive symmetric key using HKDF


derived_alice = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'auth handshake'
).derive(alice_shared)

derived_bob = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'auth handshake'
).derive(bob_shared)

print("\nShared keys equal?\t", derived_alice == derived_bob)
print("Derived key:\t", hexlify(derived_alice))

