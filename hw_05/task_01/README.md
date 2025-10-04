## Task Description
The goal of this task is to securely hash user passwords before storing them in a database.  
For this purpose, the modern **Argon2id** algorithm was chosen, which is currently the most reliable method for password storage in web applications.

### Passwords to be hashed:

qwertyuiop
sofPed-westag-jejzo1
f3Fg#Puu$EA1mfMx2
TIMCfJDkKBRm9/zwcFbHhE6zaMcSxR7nke1mJKcVqXpvCzg69d7Mf2quanMoAfmPJXyqT4gyGpLoL1lTHoqmwVmaUwrpOPRecB8GAU17eUJJHiksv3qrqcVxhgpMkX/UlKaLdFSwFIr7cVoJmBqQ/buWzxJNCIo7qbtIi3fSi62NwMHh


---

## Selected Hashing Method
**Algorithm:** `Argon2id`

### Reasons for selection:
- A modern standard for password storage (winner of the *Password Hashing Competition*, recommended by *OWASP*).  
- Resistant to GPU and brute-force attacks due to tunable memory and time costs.  
- Supports long passwords, unlike bcrypt (which has a ~72-character limit).  
- Includes built-in salting — identical passwords will always produce different hashes.  

---

## Parameters Used

| Parameter | Value | Description |
|------------|--------|-------------|
| `time_cost` | `3` | Number of iterations — affects hash computation time. Higher values increase security. |
| `memory_cost` | `64 * 1024 (64 MB)` | Amount of memory used by the algorithm. Makes GPU-based attacks more difficult. |
| `parallelism` | `4` | Number of threads for parallel processing — optimal for modern CPUs. |
| `hash_len` | `32` | Length of the resulting hash in bytes. Sufficient for cryptographic strength. |

---

## Execution Result
As a result of running the program, a file  
**`hashed_passwords.txt`** is created, containing **4 lines** — one hash for each password.

---

## Entropy Analysis

| Password | Entropy | Comment |
|-----------|----------|----------|
| `qwertyuiop` | Low | Simple and easy to guess. |
| `sofPed-westag-jejzo1` | Medium | Contains words and numbers, but no special characters. |
| `f3Fg#Puu$EA1mfMx2` | High | Combination of upper/lowercase letters, digits, and special characters. |
| Very long password | Very high | High entropy, requires an algorithm without length limitations (hence Argon2id). |

---

## Conclusion
The **Argon2id** algorithm provides:
- strong protection even for weak passwords (due to its adjustable parameters);
- the ability to process long passwords without losing security;
- a good balance between performance and resistance to attacks.

Therefore, **Argon2id** with parameters  
`time_cost=3`, `memory_cost=64MB`, `parallelism=4` —  
is the optimal choice for password hashing in modern web systems.
