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

def decrypt_check(filename, key):
    key_bytes = key.to_bytes(16, 'little')
    with open(filename, 'rb') as f:
        data = f.read()
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    if decrypted[:2] == b'BM':
        return decrypted
    return None

# Check and decrypt BMP (with_padding)

#def decrypt_check(filename, key):
    #key_bytes = key.to_bytes(16, 'little')
    #with open(filename, 'rb') as f:
        #data = f.read()
    #cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    #decryptor = cipher.decryptor()
    #decrypted_padded = decryptor.update(data) + decryptor.finalize()

    # Unpack PKCS7
    #unpadder = padding.PKCS7(128).unpadder()
    #try:
        #decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    #except ValueError:
        # if the padding false
        #return None

    # Check header BMP
    #if decrypted[:2] == b'BM':
        #return decrypted
    #return None


if __name__ == "__main__":
   
    with open("sequence.txt", "r") as f:
        numbers = ast.literal_eval(f.read().strip())

    if len(numbers) < 624:
        raise ValueError("Error, need 624 numbers")

    # use first 624 numbers
    mt = MT19937(numbers[:624])

    max_attempts = 2000000  
    found = False

    for attempt in range(max_attempts):
      
        key = (mt.extract_number() << 96) | (mt.extract_number() << 64) | \
              (mt.extract_number() << 32) | mt.extract_number()

        decrypted = decrypt_check("data.bmp.enc", key)
        if decrypted:
            with open("data.bmp", "wb") as f:
                f.write(decrypted)
            with open("key.hex", "w") as f:
                f.write(hex(key)[2:].rjust(32, '0'))
            print(f"[FOUND] Ключ найден после {attempt+1} попыток!")
            found = True
            break

        if attempt % 50000 == 0:
            print(f"Попробовано {attempt} ключей...")

    if not found:
        print("Ключ не найден")
