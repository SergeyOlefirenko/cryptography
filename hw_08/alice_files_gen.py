from binascii import unhexlify

# Path to files
alice_sign_pub_file = "alice_sign_pub.pem"
alice_ecdh_pub_file = "alice_ecdh_pub.hex"
alice_ecdh_sign_file = "alice_ecdh_sign.hex"

# Data from the assignment
alice_sign_pub_pem = b"""-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAES/35y89DRx2XEh6pJvCckadQ9Awuys84
HORPVVaDksVxWfSkngYrz/c+HwVS9tV5ivnVwCHxyJ8gTQob/0LDDg==
-----END PUBLIC KEY-----
"""

alice_ecdh_pub_hex = b"92ce3bc6d941238da92639c72a7d3bb483d3c18fdca9f42164459a3751638433"

alice_ecdh_sign_hex = b"3045022034b7944bf92bfaa2791b5fe929d915add4ee59dbd9e776c1520568fbf2503048022100f09c9113f38fadb33b05332eab9a4982f7dda35fb1f503bb46da806c8e8dbaa2"

# Saving Alice’s signing public key (PEM)
with open(alice_sign_pub_file, "wb") as f:
    f.write(alice_sign_pub_pem)
print(f"Saved Alice's signing public key - {alice_sign_pub_file}")

# Saving Alice’s ECDH public key (hex)
with open(alice_ecdh_pub_file, "wb") as f:
    f.write(alice_ecdh_pub_hex)
print(f"Saved Alice's ECDH public key - {alice_ecdh_pub_file}")

# Saving the signature of Alice’s ECDH public key (hex)
with open(alice_ecdh_sign_file, "wb") as f:
    f.write(alice_ecdh_sign_hex)
print(f"Saved Alice's ECDH signature - {alice_ecdh_sign_file}")
