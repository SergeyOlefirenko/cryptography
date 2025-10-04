from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization

# Load the public key
with open("task_pub.pem", "rb") as f:
    pub_key = serialization.load_pem_public_key(f.read())

# Load the message
with open("task_message.txt", "r") as f:
    message = bytes.fromhex(f.read().strip())  # for example "6d657373616765" -> b'message'

# Load the signature
with open("task_signature.txt", "r") as f:
    signature = bytes.fromhex(f.read().strip())

# Verify the signature
try:
    pub_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),  # MGF1 с SHA-256
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()  # Message hash sum
    )
    print("The signature has been successfully verified")
except Exception as e:
    print("The signature is invalid")
    print(e)
