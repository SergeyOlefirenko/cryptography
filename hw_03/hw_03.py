import requests
import json

from binascii import hexlify


def encrypt(pt):
    """Obtain ciphertext (encryption) for plaintext"""
    hex = hexlify(pt.encode()).decode()
    url = "http://aes.cryptohack.org/ecb_oracle/encrypt/" + hex
    r = requests.get(url)
    ct = (json.loads(r.text))["ciphertext"]
    return ct


def print_ciphertext(ct):
    """Print ciphertext by block"""
    parts = [ct[i : i + 32] for i in range(0, len(ct), 32)]
    for p in parts:
        print(p)

#             0123456789abcdef
# abcdefghijklmnopqrstuvwxyz
# Solution ct = encrypt("0123456789crypto0123456789")
# Check:
ct = encrypt("0123456789crypto0123456789crypto")
print_ciphertext(ct)

#crypto

#.\task_1.py
#71b3919a2ba5099b76a203f26983049a
#71b3919a2ba5099b76a203f26983049a
#75829521ed58d56e0acbf0641ddee18e
#10501d0c4f881962fb6fd997db9ae87b