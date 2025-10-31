# CLI chat with End-to-End Encryption (E2EE)

## Project description

The project implements a simple command-line chat between two users: Alice and Bob, using end-to-end encryption (E2EE).
The goal is to ensure the confidentiality, integrity, and authentication of messages between the parties without trusting the network or intermediaries.

The project is implemented using Python and the cryptography library.

---

## Main features

1.Connection Initialization

- Alice starts the server (alice.py) on the local host.
- Bob connects to the server (bob.py).
- Users exchange ephemeral X25519 keys via the Diffie-Hellman protocol, signed with long-term Ed25519 keys.
- Public key fingerprints are displayed in the console for manual verification to prevent MITM attacks.

2.Message Exchange

- Each message is encrypted using AES-GCM.
- Ed25519 signatures are used for authentication.
- The Double Ratchet algorithm updates session keys after each message.
- Message counters Ns, Nr, PN prevent message replay attacks.

3.CLI Interface

- Green prompt >>> — for typing messages.
- Red prompt <<< — for received messages.

---

## Project structure

```text
app
│
├─ alice.py                 # Alice Server/Client
├─ bob.py                   # Bob Client
├─ utils.py                 # Helper Functions: Cryptography and Console Handling
├─ state_alice.json         # Alice Double Ratchet State
├─ state_bob.json           # Bob Double Ratchet State
├─ alice_ed25519_priv.pem
├─ alice_ed25519_pub.pem
├─ bob_ed25519_priv.pem
├─ bob_ed25519_pub.pem
└─ README.md


---

## Cryptographic algorithms and security

| Mechanism                      | Purpose   |
|--------------------------------|-----------|
| **Ed25519**                    | Signatures and Long-Term Key Authentication|
| **X25519**                     | Ephemeral Diffie-Hellman Key Agreement |
| **AES-GCM**                    | Symmetric Message Encryption with Integrity Verification|
| **Double Ratchet**             | Session Key Update After Each Message (Forward Secrecy) |
| **Ns, Nr, PN**                 | Message Counters for Replay Attack Protection |

### Motivation for algorithm selection

- **Ed25519**: Fast and secure signatures, minimal implementation risk
- **X25519**: Compact and secure ephemeral key agreement, compatible with double ratchet
- **AES-GCM**: Ensures data confidentiality and integrity in a single call
- **Double Ratchet**: Guarantees forward secrecy and key updates after each message
- **Message сounters**: Prevent replay of legitimate messages

---

## Requirements

1. Python 3.12
2. Dependencies:

pip install cryptography
pip install customtkinter

Running:

Running Alice (Server): .\alice in PowerShell
Running Bob (Client) in another terminal: .\bob in PowerShell

Confirmation fingerprint

Alice and Bob compare the fingerprints of their public keys and manually confirm them to protect against MITM attacks

Message exchange:

- Type the text and press Enter
- Messages are automatically encrypted and signed, and decryption is performed on the recipient's side

## Key and Message Exchange Diagram

```text
Alice                        Bob
-----                        ---
Ed25519 Keys                  Ed25519 Keys
Generate ephemeral X25519 --->|  Receive ephemeral X25519
Sign ephemeral key            |  Verify signature
<--- ephemeral X25519          Sign ephemeral key
Verify signature               |  Store DH shared secret
Initialize Double Ratchet       Initialize Double Ratchet

Message 1:
Encrypt(AES-GCM, Msg, ChainKey) ---> Decrypt and verify
Update ChainKeys (Double Ratchet)
Message 2:
Encrypt(AES-GCM, Msg, ChainKey) ---> Decrypt and verify
...
