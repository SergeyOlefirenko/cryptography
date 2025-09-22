import secrets

with open("rnd-secrets.bin", "wb") as f:
    for _ in range(1000000000):  # 1 Gb
        f.write(secrets.randbits(8).to_bytes(1, "little"))
