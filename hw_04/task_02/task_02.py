import sys
from binascii import unhexlify
from typing import Tuple

# Change admin rights "False" -> "True;" (5 bytes)
ORIGINAL = b"False"
TARGET = b"True;"
OFFSET_IN_BLOCK = 6  # position of "F" in "admin=False" (0-based inside first 16-byte block)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def compute_new_iv(iv_hex: str) -> str:
    iv_hex = iv_hex.strip()
    if len(iv_hex) != 32:
        raise ValueError(f"IV hex length must be exactly 32, got {len(iv_hex)}")
    try:
        iv = unhexlify(iv_hex)
    except Exception as e:
        raise ValueError("IV is not valid hex") from e

    # 5 bytes difference between "False" and "True;"
    diff = xor_bytes(ORIGINAL, TARGET)  
    # delta_block: 16 bytes, non-zero only at positions OFFSET_IN_BLOCK OFFSET_IN_BLOCK+len(diff)
    delta_block = bytearray(16)
    delta_block[OFFSET_IN_BLOCK:OFFSET_IN_BLOCK + len(diff)] = diff

    # new iv = extracted iv XOR delta_block
    new_iv_bytes = bytes(x ^ y for x, y in zip(iv, delta_block))

   # Produce a correct hex string (two hex digits per byte)
    new_iv_hex = ''.join(f"{b:02x}" for b in new_iv_bytes)
    return new_iv_hex

def split_full_cookie(full_hex: str) -> Tuple[str, str]:
    full_hex = full_hex.strip()
    if len(full_hex) < 32:
        raise ValueError("full cookie too short (need at least 32 hex chars for IV)")
    if len(full_hex) % 2 != 0:
        raise ValueError("full cookie hex must have even number of characters")
    iv_hex = full_hex[:32]
    ct_hex = full_hex[32:]
    return iv_hex, ct_hex

def main():
    if len(sys.argv) >= 2:
        full = sys.argv[1].strip()
    else:
        full = input("\nInsert obtained cookie from 'https://aes.cryptohack.org/flipping_cookie/' from Output and press Enter: ").strip()

    try:
        iv_hex, ct_hex = split_full_cookie(full)
        new_iv = compute_new_iv(iv_hex)
    except Exception as e:
        print("Error:", e)
        sys.exit(1)

    print("\nDATA\n ")
    print("Original Extracted IV: ", iv_hex, "\n")
    print("Insert Modified IV in IV window in 'https://aes.cryptohack.org/flipping_cookie/': \n")
    print("Modified IV:", new_iv, "\n")
    print("Insert Cookie in Cookie window in 'https://aes.cryptohack.org/flipping_cookie/': \n")
    print("Cookie: ", ct_hex, "\n")
   

if __name__ == "__main__":
    main()
