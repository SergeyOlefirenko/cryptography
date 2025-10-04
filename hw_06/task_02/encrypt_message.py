from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Load the obtained public key from task_pub.pem
with open("task_pub.pem", "rb") as f:
    pub_key = serialization.load_pem_public_key(f.read())

# Message text (encode the string in UTF-8)
message = """Hi Ruslan,I have only the most positive impressions of both you and the course. Wishing you a nice day, my friend, and a fantastic mood. I’m really glad we got to meet.""".encode("utf-8")

# Encrypt using RSA-OAEP with SHA-256
ciphertext = pub_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Save in hex format
with open("message.txt", "w", encoding="utf-8") as f:
    f.write(ciphertext.hex())

print("The message has been encrypted and saved in message.txt")
