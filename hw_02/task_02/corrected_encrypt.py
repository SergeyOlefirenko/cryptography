import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

rng = random.Random()
key = rng.getrandbits(128)


def encrypt(filename, key):
    key_bytes = key.to_bytes(16, "little")

    with open(filename, "rb") as f:
        data = f.read()

    # PKCS#7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # AES-128-ECB  cipher
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    encryptor = cipher.encryptor()
    data_enc = encryptor.update(padded_data) + encryptor.finalize()

    with open(filename + ".enc", "wb") as f:
        f.write(data_enc)


def decrypt(filename, key):
    key_bytes = key.to_bytes(16, "little")

    with open(filename, "rb") as f:
        data = f.read()

    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data

encrypt("data.bmp", key)
decrypted_data = decrypt("data.bmp.enc", key)

with open("data_decrypted.bmp", "wb") as f:
    f.write(decrypted_data)
