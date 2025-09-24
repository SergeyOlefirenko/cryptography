import ast
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class MT19937:
    def __init__(self, state):
        self.MT = list(state)
        self.index = 624
        self.n = 624
        self.m = 397
        self.a = 0x9908B0DF
        self.u, self.d = 11, 0xFFFFFFFF
        self.s, self.b = 7, 0x9D2C5680
        self.t, self.c = 15, 0xEFC60000
        self.l = 18

    def twist(self):
        for i in range(self.n):
            y = (self.MT[i] & 0x80000000) + (self.MT[(i+1) % self.n] & 0x7FFFFFFF)
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ (y >> 1)
            if y % 2 != 0:
                self.MT[i] ^= self.a
        self.index = 0

    def extract_number(self):
        if self.index >= self.n:
            self.twist()
        y = self.MT[self.index]
        y ^= (y >> self.u) & self.d
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= (y >> self.l)
        self.index += 1
        return y & 0xFFFFFFFF


def decrypt_aes_ecb(data, key):
    key_bytes = key.to_bytes(16, "little")
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    return decrypted


if __name__ == "__main__":
   
    with open("sequence.txt", "r") as f:
        numbers = ast.literal_eval(f.read().strip())

    if len(numbers) < 624:
        raise ValueError("Error, need 624 numbers")

 
    mt = MT19937(numbers[:624])

    with open("data.bmp.enc", "rb") as f:
        enc_data = f.read()

    attempt = 0
    found = False
    while True:
        #128-bit key (4 * 32)
        key = (mt.extract_number() << 96) | (mt.extract_number() << 64) | \
              (mt.extract_number() << 32) | mt.extract_number()
        attempt += 1

        decrypted = decrypt_aes_ecb(enc_data, key)
        if decrypted[:2] == b'BM':  
            print(f"[FOUND] Ключ найден после {attempt} попыток!")
            print(f"Ключ (hex): {hex(key)[2:].rjust(32,'0')}")
            with open("data_dec.bmp", "wb") as f:
                f.write(decrypted)
            with open("key.hex", "w") as f:
                f.write(hex(key)[2:].rjust(32,'0'))
            found = True
            break

        if attempt % 50000 == 0:
            print(f"Попробовано {attempt} ключей...")

    if not found:
        print("Ключ не найден")







