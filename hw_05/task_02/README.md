# Generation of Message Authentication Code (MAC)

## Objective
The goal of this task is to **generate a Message Authentication Code (MAC)** to verify the **integrity and authenticity** of encrypted data.

---

## Input Data

- **Main key:**

63e353ae93ecbfe00271de53b6f02a46


- **Ciphertext:**

76c3ada7f1f7563ff30d7290e58fb4476eb12997d02a6488201c075da52ff3890260e2c89f631e7f919af96e4e47980a

- **Initialization Vector (IV):**

75b777fc8f70045c6006b39da1b3d622

---

## Selected Algorithm and Key for MAC

### Authentication Algorithm
The **HMAC-SHA256** algorithm was used to compute the MAC.

**Reasons for selection:**
- HMAC is a well-established and widely used standard for message authentication.  
- SHA-256 provides strong cryptographic resistance (256-bit security).  
- Implemented in Python’s standard library (`hmac`, `hashlib`) — no external dependencies required.  
- Simple, reliable, and recommended by *NIST* and *IETF (RFC 2104)*.

---

### Key for MAC Calculation
It is **not recommended** to use the same key for both encryption and MAC generation.  
Therefore, a **separate MAC key** was derived from the main encryption key using HMAC derivation:

mac_key = HMAC-SHA256(main_key, b"mac-key-derivation")


This approach allows:
- Separation of cryptographic functions (encryption vs. authentication);  
- Avoiding key reuse across different operations;  
- Better overall security isolation.

---

### Data Included in the MAC
To generate the MAC, the **concatenation of IV and ciphertext** is used:

data_to_mac = IV || ciphertext


This ensures:
- Integrity verification of both the message and the IV;  
- Protection against tampering attacks that modify the IV;  
- A simple and unambiguous data structure.

---

## Execution Result

After running the script, a file  
**`mac_hex.txt`** is created containing the computed MAC in hex format:

b8799e020468bedd5874c85b5cb2332558b11cf18da6356b34b082925319c7a0


---

## Justification of Choices

| Component | Rationale |
|------------|------------|
| **HMAC-SHA256** | Proven and cryptographically strong message authentication algorithm. |
| **Separate MAC key** | Prevents key reuse and ensures better security isolation. |
| **IV + Ciphertext** | Ensures that neither the IV nor the ciphertext can be tampered with. |
| **Python standard library** | Easy to reproduce, no external dependencies, transparent implementation. |

---

## Alternatives

- **AES-CMAC** — if a block cipher–based MAC is preferred.  
- **HMAC-SHA512** — for a longer and more secure MAC.  
- **HKDF (RFC 5869)** — a more formal and robust key derivation approach.  
- **AEAD (AES-GCM, ChaCha20-Poly1305)** — modern authenticated encryption modes that combine encryption and authentication.

---

## Conclusion
The **HMAC-SHA256** algorithm, using a key derived from the main encryption key (`mac-key-derivation`)  
and the data combination **IV || ciphertext**, provides:

- Reliable integrity and authenticity verification of encrypted data;  
- A simple and effective implementation;  
- Compliance with best modern cryptographic practices.

The result is stored in **`mac_hex.txt`**.

