import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

rng = random.Random()
key = rng.getrandbits(128)


def encrypt(filename, key):
    key_bytes = key.to_bytes(16, "little")

    with open(filename, "rb") as f:
        data = bytearray(f.read())

    cipher = Cipher(algorithms.AES128(key_bytes), modes.ECB())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data)
    data_enc = encryptor.update(padded_data)

    with open(filename + ".enc", "wb") as f:
        f.write(data_enc)


def decrypt(filename, key):
    key_bytes = key.to_bytes(16, "little")

    with open(filename, "rb") as f:
        data = bytearray(f.read())

    cipher = Cipher(algorithms.AES128(key_bytes), modes.ECB())
    decryptor = cipher.decryptor()
    padder = padding.PKCS7(128).unpadder()
    padded_data = decryptor.update(data) + decryptor.finalize()
    data = padder.update(padded_data)

    return data


encrypt("data.bmp", key)
