from argon2 import PasswordHasher

# Create a hasher object
ph = PasswordHasher(
    time_cost=3,         # Number of iterations (the higher — the slower, the more secure)
    memory_cost=64 * 1024,  # Memory in KB (64 MB)
    parallelism=4,       # Parallelism (number of threads)
    hash_len=32,         # Hash length
)

passwords = [
    "qwertyuiop",
    "sofPed-westag-jejzo1",
    "f3Fg#Puu$EA1mfMx2",
    "TIMCfJDkKBRm9/zwcFbHhE6zaMcSxR7nke1mJKcVqXpvCzg69d7Mf2quanMoAfmPJXyqT4gyGpLoL1lTHoqmwVmaUwrpOPRecB8GAU17eUJJHiksv3qrqcVxhgpMkX/UlKaLdFSwFIr7cVoJmBqQ/buWzxJNCIo7qbtIi3fSi62NwMHh"
]

# Generate hashes
hashes = [ph.hash(pw) for pw in passwords]

# Write to file
with open("hashed_passwords.txt", "w") as f:
    for h in hashes:
        f.write(h + "\n")

print("Hashes have been saved to hashed_passwords.txt")
