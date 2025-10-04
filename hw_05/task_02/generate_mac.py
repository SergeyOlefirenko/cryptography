import hmac, hashlib, binascii

main_key_hex = "63e353ae93ecbfe00271de53b6f02a46"
iv_hex = "75b777fc8f70045c6006b39da1b3d622"
ciphertext_hex = "76c3ada7f1f7563ff30d7290e58fb4476eb12997d02a6488201c075da52ff3890260e2c89f631e7f919af96e4e47980a"

main_key = binascii.unhexlify(main_key_hex)
iv = binascii.unhexlify(iv_hex)
ciphertext = binascii.unhexlify(ciphertext_hex)

# 1) Derive MAC key from main key (so we don't reuse encryption key directly)
label = b"mac-key-derivation"
mac_key = hmac.new(main_key, label, hashlib.sha256).digest()

# 2) Data to authenticate: IV || ciphertext
data_to_mac = iv + ciphertext

# 3) Compute HMAC-SHA256
mac_hex = hmac.new(mac_key, data_to_mac, hashlib.sha256).hexdigest()

# 4) Save to file
with open("mac_hex.txt", "w") as f:
    f.write(mac_hex + "\n")

print("MAC (hex):", mac_hex)
