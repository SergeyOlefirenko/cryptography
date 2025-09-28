import requests
from binascii import unhexlify, hexlify

URL = "https://aes.cryptohack.org/lazy_cbc"

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def get_encrypted():
    # choose 3 identical 16-byte blocks (here: b'b'*48)
    pt = b"b" * 48
    pt_hex = pt.hex()
    url = f"{URL}/encrypt/{pt_hex}/"
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    data = r.json()
    if "ciphertext" not in data:
        raise RuntimeError("encrypt did not return ciphertext: " + str(data))
    return bytes.fromhex(data["ciphertext"])

def send_and_get(ct_bytes: bytes):
    # ciphertext: C0 || 0(16 bytes) || C0
    if len(ct_bytes) < 16:
        raise ValueError("ciphertext too short")
    C0 = ct_bytes[:16]
    crafted = C0 + (b"\x00" * 16) + C0
    crafted_hex = crafted.hex()
    url = f"{URL}/receive/{crafted_hex}/"
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    data = r.json()
    # If server returns error with invalid plaintext, it includes hex of decrypted plaintext.
    # Example: {"error": "Invalid plaintext: <hex...>"}
    if "error" in data and data["error"].startswith("Invalid plaintext: "):
        hexpart = data["error"].split("Invalid plaintext: ")[1].strip()
        return bytes.fromhex(hexpart)
    else:
        # If server returned success or other message, print it for debugging
        raise RuntimeError("Unexpected response from receive: " + str(data))

def get_flag(key_bytes: bytes):
    key_hex = key_bytes.hex()
    url = f"{URL}/get_flag/{key_hex}/"
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    data = r.json()
    if "plaintext" in data:
        return bytes.fromhex(data["plaintext"])
    else:
        raise RuntimeError("get_flag did not return plaintext: " + str(data))

def main():
    print("\nRequesting encryption\n")
    ct = get_encrypted()
    print("Received ciphertext (hex):\n\n" + ct.hex() + "\n")
    decrypted = send_and_get(ct)
    # decrypted is the raw plaintext bytes that server produced when decrypting our ciphertext
    if len(decrypted) < 48:
        raise RuntimeError("decrypted length unexpected: " + str(len(decrypted)))
    B1 = decrypted[0:16]
    B3 = decrypted[32:48]
    key = xor_bytes(B1, B3)
    print("Recovered key:", key.hex(), "\n")
    print("Recovered flag\n")
    flag = get_flag(key)
    print("FLAG:", flag.decode(), "\n")

if __name__ == "__main__":
    main()
