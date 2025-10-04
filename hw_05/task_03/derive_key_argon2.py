import os
import json
import base64
from argon2 import PasswordHasher
from argon2.low_level import Type, hash_secret_raw

USERS_FILE = "users.json"

def derive_key(username, password, users_file=USERS_FILE):
    """
    Derive AES-128 key from user's password using Argon2id.
    If user is new, generate salt and save to users.json.
    """

    # 1. Load or create user database
    if os.path.exists(users_file):
        with open(users_file, "r") as f:
            users = json.load(f)
    else:
        users = []

    # 2. Check if user exists
    user_entry = next((u for u in users if u["username"] == username), None)

    # 3. If new user -> create salt and save
    if user_entry is None:
        salt = os.urandom(16)  # 128-bit random salt
        user_entry = {"username": username, "salt": salt.hex()}
        users.append(user_entry)
        with open(users_file, "w") as f:
            json.dump(users, f, indent=4)
    else:
        salt = bytes.fromhex(user_entry["salt"])

    # 4. Derive AES-128 key using Argon2id
    key = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,       # Number of iterations
        memory_cost=64*1024, # Memory in KB (64 MB)
        parallelism=4,     # Number of threads
        hash_len=16,       # AES-128 → 16 bytes
        type=Type.ID       # Argon2id (secure against side-channel attacks)
    )

    # Return in hex or base64 for storage/printing
    return base64.b16encode(key).decode("utf-8")


if __name__ == "__main__":
    key = derive_key("Alice", "qwerty123")
    print("AES-128 key:", key)
