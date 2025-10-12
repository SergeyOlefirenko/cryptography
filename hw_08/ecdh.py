from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from binascii import hexlify, unhexlify
import os

# Path to Alice's files (first generate them by running the script: alice_files_gen to avoid hardcoding keys directly into the script)
alice_sign_pub_file = "alice_sign_pub.pem"
alice_ecdh_pub_file = "alice_ecdh_pub.hex"
alice_ecdh_sign_file = "alice_ecdh_sign.hex"

# 1. Load Alice's public keys

# Public signing key — PEM format (bytes)
with open(alice_sign_pub_file, "rb") as f:
    alice_sign_pub_key = serialization.load_pem_public_key(f.read())

# ECDH public key and its signature — read as text (hex -> bytes)
with open(alice_ecdh_pub_file, "r") as f:
    alice_ecdh_pub_bytes = unhexlify(f.read().strip())

with open(alice_ecdh_sign_file, "r") as f:
    alice_ecdh_sign = unhexlify(f.read().strip())

# 2. Verify Alice's ECDH key signature
try:
    alice_sign_pub_key.verify(
        alice_ecdh_sign,
        alice_ecdh_pub_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    print("Alice's ECDH public key signature verified.")
except InvalidSignature:
    raise SystemExit("ERROR: Alice's signature verification failed!")

# 3. Generation or loading of Bob’s long-term signing key (it can also be generated separately using SSL — see file: bob_keys_gen_comands)
bob_sign_key_file = "bob_sign_priv.pem"
bob_sign_pub_file = "bob_sign_pub.pem"

if os.path.exists(bob_sign_key_file) and os.path.exists(bob_sign_pub_file):
    # Load existing keys
    with open(bob_sign_key_file, "rb") as f:
        bob_sign_private = serialization.load_pem_private_key(f.read(), password=None)
    with open(bob_sign_pub_file, "rb") as f:
        bob_sign_public = serialization.load_pem_public_key(f.read())
    print("OK, loaded Bob's long-term signing key pair.")
else:
    # Generate a new SECP256K1 key pair
    bob_sign_private = ec.generate_private_key(ec.SECP256K1())
    bob_sign_public = bob_sign_private.public_key()

    # Save the private key
    with open(bob_sign_key_file, "wb") as f:
        f.write(
            bob_sign_private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save the public key
    with open(bob_sign_pub_file, "wb") as f:
        f.write(
            bob_sign_public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print("OK, generated and saved Bob's long-term signing key pair.")

# 4. Generate Bob's private key for ECDH (X25519)
bob_ecdh_private = x25519.X25519PrivateKey.generate()
bob_ecdh_public = bob_ecdh_private.public_key()

bob_ecdh_pub_bytes = bob_ecdh_public.public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw
)
bob_ecdh_pub_hex = hexlify(bob_ecdh_pub_bytes).decode()
print("Bob's ECDH public key (hex):", bob_ecdh_pub_hex)

# 5. Sign Bob's ECDH public key
bob_ecdh_sign = bob_sign_private.sign(
    bob_ecdh_pub_bytes,
    ec.ECDSA(hashes.SHA256())
)
bob_ecdh_sign_hex = hexlify(bob_ecdh_sign).decode()
print("Bob's ECDH key signature (hex):", bob_ecdh_sign_hex)

# 6. Save all generated data
with open("bob_keys.txt", "w") as f:
    f.write("Bob long-term signing public key (PEM):\n")
    f.write(
        bob_sign_public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    )
    f.write("\nBob ECDH public key (hex):\n")
    f.write(bob_ecdh_pub_hex + "\n")
    f.write("Signature of Bob's ECDH key (hex):\n")
    f.write(bob_ecdh_sign_hex + "\n")

print("\nOK, all values saved to bob_keys.txt")
