import json
import base64
import secrets
from pathlib import Path
from typing import Optional, Dict, Tuple
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import asyncio
import sys

# File names and constants
ALICE_PRIV = "alice_ed25519_priv.pem"
ALICE_PUB = "alice_ed25519_pub.pem"
BOB_PRIV = "bob_ed25519_priv.pem"
BOB_PUB = "bob_ed25519_pub.pem"
STATE_ALICE = "state_alice.json"
STATE_BOB = "state_bob.json"

NONCE_SIZE = 12
AES_KEY_SIZE = 32
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888

YOUR_PROMPT = "\033[32m>>> \033[0m"
THEIR_PROMPT = "\033[31m<<< \033[0m"

# Base64
def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode())

# Key
def ensure_ed25519_keys(priv: str, pub: str):
    if Path(priv).exists() and Path(pub).exists():
        return
    privk = ed25519.Ed25519PrivateKey.generate()
    pubk = privk.public_key()
    with open(priv, "wb") as f:
        f.write(privk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    with open(pub, "wb") as f:
        f.write(pubk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))

def load_ed25519_private(path: str):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)

def load_ed25519_public(path: str):
    return serialization.load_pem_public_key(Path(path).read_bytes())

def fingerprint_pubkey(pem_bytes: bytes) -> str:
    import hashlib
    h = hashlib.sha256(pem_bytes).hexdigest()
    return ":".join([h[i:i+2] for i in range(0, len(h), 2)])

# HKDF
def hkdf(length: int, ikm: bytes, salt: Optional[bytes], info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)

# Double Ratchet
class DoubleRatchet:
    def __init__(self):
        self.root_key: Optional[bytes] = None
        self.send_chain_key: Optional[bytes] = None
        self.recv_chain_key: Optional[bytes] = None
        self.DHs: Optional[x25519.X25519PrivateKey] = None
        self.DHr: Optional[bytes] = None
        self.Ns = 0
        self.Nr = 0
        self.PN = 0
        self.skipped_message_keys: Dict[str, bytes] = {}

    # Key serialization
    @staticmethod
    def x25519_priv_to_bytes(priv: x25519.X25519PrivateKey) -> bytes:
        return priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

    @staticmethod
    def x25519_priv_from_bytes(b: bytes) -> x25519.X25519PrivateKey:
        return x25519.X25519PrivateKey.from_private_bytes(b)

    @staticmethod
    def x25519_pub_from_bytes(b: bytes) -> x25519.X25519PublicKey:
        return x25519.X25519PublicKey.from_public_bytes(b)

    # Ratchet key derivation
    @staticmethod
    def kdf_root(root_key: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
        out = hkdf(64, root_key + dh_out, None, b"ratchet-root")
        return out[:32], out[32:]

    @staticmethod
    def kdf_chain(chain_key: bytes) -> Tuple[bytes, bytes]:
        out = hkdf(64, chain_key, None, b"ratchet-chain")
        return out[:32], out[32:]

    @staticmethod
    def message_key_to_aeskey(msg_key: bytes) -> bytes:
        return hkdf(AES_KEY_SIZE, msg_key, None, b"msg-aes")

    # Ratchet step on receiving new DH
    def ratchet_step_on_receive(self, their_pub_bytes: bytes):
        self.PN = self.Ns
        self.Ns = 0
        self.Nr = 0
        self.DHr = their_pub_bytes
        their_pub = self.x25519_pub_from_bytes(self.DHr)
        dh_out = self.DHs.exchange(their_pub)
        rk, recv_ck = self.kdf_root(self.root_key, dh_out)
        self.root_key = rk
        self.recv_chain_key = recv_ck
        new_our = x25519.X25519PrivateKey.generate()
        dh2 = new_our.exchange(their_pub)
        rk2, send_ck = self.kdf_root(self.root_key, dh2)
        self.root_key = rk2
        self.send_chain_key = send_ck
        self.DHs = new_our
        self.Ns = 0
        self.Nr = 0

    # Encrypt / decrypt
    def encrypt_message(self, plaintext: bytes) -> Tuple[dict, bytes]:
        if self.send_chain_key is None:
            if self.DHr is None:
                raise RuntimeError("No remote DH public to derive keys")
            self.DHs = x25519.X25519PrivateKey.generate()
            their_pub = self.x25519_pub_from_bytes(self.DHr)
            dh_out = self.DHs.exchange(their_pub)
            rk, send_ck = self.kdf_root(self.root_key, dh_out)
            self.root_key = rk
            self.send_chain_key = send_ck
            self.Ns = 0

        next_ck, mk = self.kdf_chain(self.send_chain_key)
        self.send_chain_key = next_ck
        aes_key = self.message_key_to_aeskey(mk)
        ns = self.Ns
        self.Ns += 1
        nonce = secrets.token_bytes(NONCE_SIZE)
        aad = ns.to_bytes(8, "big") + self.PN.to_bytes(8, "big")
        ct = AESGCM(aes_key).encrypt(nonce, plaintext, aad)
        dh_pub = self.DHs.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        header = {"dh_pub": b64(dh_pub), "pn": self.PN, "ns": ns}
        payload = {"header": header, "nonce": b64(nonce), "ciphertext": b64(ct)}
        return payload, aes_key

    def decrypt_message(self, payload: dict) -> bytes:
        header = payload["header"]
        dh_pub_b64 = header.get("dh_pub")
        ns = int(header.get("ns", 0))
        nonce = ub64(payload["nonce"])
        ciphertext = ub64(payload["ciphertext"])
        if dh_pub_b64 is not None and self.recv_chain_key is None:
            self.ratchet_step_on_receive(ub64(dh_pub_b64))

        if self.recv_chain_key is None:
            raise RuntimeError("No recv_chain_key available")
        next_ck, mk = self.kdf_chain(self.recv_chain_key)
        self.recv_chain_key = next_ck
        aes_key = self.message_key_to_aeskey(mk)
        self.Nr += 1
        aad = ns.to_bytes(8, "big") + self.PN.to_bytes(8, "big")
        return AESGCM(aes_key).decrypt(nonce, ciphertext, aad)

    # Save/load state
    def save_state(self, path: str):
        obj = {
            "root_key": b64(self.root_key) if self.root_key else None,
            "send_chain_key": b64(self.send_chain_key) if self.send_chain_key else None,
            "recv_chain_key": b64(self.recv_chain_key) if self.recv_chain_key else None,
            "DHs": b64(self.x25519_priv_to_bytes(self.DHs)) if self.DHs else None,
            "DHr": b64(self.DHr) if self.DHr else None,
            "Ns": self.Ns,
            "Nr": self.Nr,
            "PN": self.PN,
            "skipped": {k: b64(v) for k, v in self.skipped_message_keys.items()},
        }
        Path(path).write_text(json.dumps(obj))

    def load_state(self, path: str):
        if not Path(path).exists():
            return
        obj = json.loads(Path(path).read_text())
        self.root_key = ub64(obj.get("root_key")) if obj.get("root_key") else None
        self.send_chain_key = ub64(obj.get("send_chain_key")) if obj.get("send_chain_key") else None
        self.recv_chain_key = ub64(obj.get("recv_chain_key")) if obj.get("recv_chain_key") else None
        self.DHs = self.x25519_priv_from_bytes(ub64(obj.get("DHs"))) if obj.get("DHs") else None
        self.DHr = ub64(obj.get("DHr")) if obj.get("DHr") else None
        self.Ns = int(obj.get("Ns", 0))
        self.Nr = int(obj.get("Nr", 0))
        self.PN = int(obj.get("PN", 0))
        self.skipped_message_keys = {k: ub64(v) for k, v in obj.get("skipped", {}).items()}

# Packet helpers
def pack_payload(header: dict, nonce: bytes, ciphertext: bytes, signature: bytes) -> bytes:
    return (json.dumps({
        "header": header,
        "nonce": b64(nonce),
        "ciphertext": b64(ciphertext),
        "signature": b64(signature)
    }) + "\n").encode()

def unpack_payload(raw: bytes) -> dict:
    return json.loads(raw.decode())

# Signing helpers
def sign(priv: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    return priv.sign(data)

def verify(pub: ed25519.Ed25519PublicKey, sig: bytes, data: bytes) -> bool:
    try:
        pub.verify(sig, data)
        return True
    except Exception:
        return False

# Async
def prompt():
    print(YOUR_PROMPT, end="", flush=True)

def show(msg):
    if isinstance(msg, bytes):
        msg = msg.decode()
    print(f"{THEIR_PROMPT}{msg}", flush=True)

async def read_message_from_stdin():
    return await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
