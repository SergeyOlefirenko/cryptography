import requests
from binascii import hexlify
import time
import sys

API = "https://aes.cryptohack.org/ecb_oracle/encrypt/"

# Settings
REQUEST_TIMEOUT = 10
DELAY_BETWEEN_REQUESTS = 0.05  # To avoid overloading the server

def encrypt_plaintext_str(pt: str) -> str:
    """
	Send the ASCII string `pt` to the server and return the ciphertext as a hex string.
	If `pt == ""`, substitute a single null byte ("00") to avoid a 404 response.
    """
    if pt == "":
        hx = "00"
    else:
        hx = hexlify(pt.encode()).decode()
    url = API + hx
    r = requests.get(url, timeout=REQUEST_TIMEOUT)
    if r.status_code != 200:
        # Show part of the response body for diagnostics, but not the entire content (to avoid cluttering the console)
        raise RuntimeError(f"HTTP {r.status_code} for URL {url}\nBody: {r.text[:400]}")
    j = r.json()
    if "ciphertext" not in j:
        raise RuntimeError(f"No ciphertext in response: {j}")
    return j["ciphertext"]


def split_blocks(hex_ct: str, block_size_bytes: int = 16):
    bl = block_size_bytes * 2
    return [hex_ct[i:i+bl] for i in range(0, len(hex_ct), bl)]

def detect_block_size():
    """
       Determines the AES block size (in bytes).
       Do not send a request with an empty string (the server returns 404) — start with 'A'.
    """
    prev_len = len(encrypt_plaintext_str("A"))
    for i in range(2, 64):   # We start from 2 because we've already taken 1
        l = len(encrypt_plaintext_str("A" * i))
        if l != prev_len:
            return (l - prev_len) // 2
    return 16


def is_ecb(block_size):
    """If entering many identical bytes produces repeated blocks -> ECB"""
    inp = "A" * (block_size * 4)
    ct = encrypt_plaintext_str(inp)
    blocks = split_blocks(ct, block_size)
    # If there are duplicates in the list of blocks -> ECB
    return len(blocks) != len(set(blocks))

def recover_flag(max_len=300):
    block_size = detect_block_size()
    print(f"Detected block size = {block_size}")
    if not is_ecb(block_size):
        print("[-] Server does not appear to use ECB (or detection failed). Aborting.")
        return None
    print("ECB detected")

    recovered = ""
    candidates = list("abcdefghijklmnopqrstuvwxyz0123456789_{}-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    for i in range(max_len):
        pad_len = (block_size - ((len(recovered) + 1) % block_size)) % block_size
        if pad_len == 0:
            pad_len = block_size
        prefix = "A" * pad_len

        ct = encrypt_plaintext_str(prefix)
        blocks = split_blocks(ct, block_size)
        block_index = (len(prefix) + len(recovered)) // block_size
        if block_index >= len(blocks):
            print("Target block index outside ciphertext blocks.")
            break
        target_block = blocks[block_index]

        found = False
        for c in candidates:
            trial = prefix + recovered + c
            trial_ct = encrypt_plaintext_str(trial)
            trial_block = split_blocks(trial_ct, block_size)[block_index]
            if trial_block == target_block:
                recovered += c
                print(f"Recovered: {recovered}")
                found = True
                break
            time.sleep(DELAY_BETWEEN_REQUESTS)

        if not found:
            for b in range(256):
                c = bytes([b]).decode('latin1')
                trial = prefix + recovered + c
                trial_ct = encrypt_plaintext_str(trial)
                trial_block = split_blocks(trial_ct, block_size)[block_index]
                if trial_block == target_block:
                    recovered += c
                    print(f"Recovered (byte): {recovered!r}")
                    found = True
                    break
                time.sleep(DELAY_BETWEEN_REQUESTS)

        if not found:
            print("Failed to find the next byte")
            break

        if recovered.endswith("}"):
            print("End of FLAG (}) found.")
            break
    return recovered

if __name__ == "__main__":
    try:
        flag = recover_flag(max_len=200)
        if flag:
            print("\nFLAG")
            # If the server adds a prefix, for example 'crypto{', then recovered will already include "crypto{...}"
            print(flag)
        else:
            print("Flag not recovered.")
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(1)
    except Exception as e:
        print("Error:", e)
        sys.exit(2)
