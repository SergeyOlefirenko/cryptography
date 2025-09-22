import random

with open("rnd-random.bin", "wb") as f:
    for _ in range(1000000000):  # 1 Gb
        f.write(random.randint(0, 255).to_bytes(1, "little"))
