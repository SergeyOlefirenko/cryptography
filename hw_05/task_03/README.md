# AES-128 Key Derivation from User Passwords

## Objective
The goal of this task is to **derive a cryptographically secure AES-128 key** from a user’s password.  
Since user passwords often have **low entropy**, the derived key must be **high-entropy and suitable for encryption**.

---

## Chosen Algorithm for Key Derivation

### Argon2id
- **Argon2id** is a modern standard for password protection and the winner of the *Password Hashing Competition (PHC)*.  
- Generates **strong, secure keys even from weak passwords**.  
- Resistant to brute-force attacks and memory-based attacks thanks to its configurable parameters: `time_cost`, `memory_cost`, and `parallelism`.  

### Key Derivation Parameters
| Parameter | Value | Purpose |
|-----------|-------|---------|
| `time_cost` | 3 | Number of iterations — increases computational difficulty. |
| `memory_cost` | 64 * 1024 KB (64 MB) | Memory usage — protects against GPU attacks. |
| `parallelism` | 4 | Number of threads — leverages modern CPU cores. |
| `hash_len` | 16 bytes (128 bits) | Output key length — suitable for AES-128 encryption. |

---

## Salt

- Each user receives a **unique 128-bit salt** (`os.urandom(16)`).  
- Salt is stored in a per-user metadata file (`users.json`).  
- Ensures that **identical passwords generate different keys** for different users.  
- Protects against **rainbow table attacks** and precomputed key attacks.

---

## Key Format and Output

- Derived key is returned as **hexadecimal or Base64**, making it safe for storage or direct use in AES-128 encryption.  
- Example output format:

AES-128 key: 5A7B6D9C1E2F3A4B5C6D7E8F9A0B1C2D


---

## Security Summary

- **Algorithm:** Argon2id — modern, memory-hard, and resistant to side-channel attacks.  
- **Salt:** unique per user, 128 bits.  
- **Derived Key:** 128-bit key suitable for AES encryption.  
- **Configurable parameters:** provide strong defense against brute-force and GPU attacks.  
- **Output format:** safe for storage or use in cryptographic operations.

---

## JSON 
User metadata can be stored as:
```json
[
    {
        "username": "Alice",
        "salt": "ecbc2028bd331f552407d1d3af0d7756"
    }
]
