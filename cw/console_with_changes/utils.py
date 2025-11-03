import json
import base64
import secrets
import time
from pathlib import Path
from typing import Optional, Dict, Tuple
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sys
import asyncio

# Config 
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
MAX_SKIPPED = 2000
MAX_REPLAY_AGE = 300  # секунд, 5 минут

# Base64 
def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode())

# Zeroize 
def zeroize(b: Optional[bytes]):
    if not b:
        return
    try:
        if isinstance(b, bytearray):
            for i in range(len(b)):
                b[i] = 0
    except Exception:
        pass

# Key management
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
        self.Ns = self.Nr = self.PN = 0
        self.skipped_message_keys: Dict[Tuple[str, int], bytes] = {}
        self.last_ts: Dict[str, int] = {}  # DH_pub -> last timestamp

    # X25519 
    @staticmethod
    def x25519_priv_to_bytes(priv: x25519.X25519PrivateKey) -> bytes:
        return priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption())

    @staticmethod
    def x25519_priv_from_bytes(b: bytes) -> x25519.X25519PrivateKey:
        return x25519.X25519PrivateKey.from_private_bytes(b)

    @staticmethod
    def x25519_pub_from_bytes(b: bytes) -> x25519.X25519PublicKey:
        return x25519.X25519PublicKey.from_public_bytes(b)

    # KDFs 
    @staticmethod
    def kdf_root(root_key: bytes, dh_out: bytes, role_label: bytes = b"") -> Tuple[bytes, bytes]:
        out = hkdf(64, (root_key or b"") + dh_out, salt=b"root_salt", info=b"root" + role_label)
        return out[:32], out[32:]

    @staticmethod
    def kdf_chain(chain_key: bytes) -> Tuple[bytes, bytes]:
        out = hkdf(64, chain_key, salt=b"chain_salt", info=b"chain_step")
        return out[:32], out[32:]

    @staticmethod
    def message_key_to_aeskey(msg_key: bytes) -> bytes:
        return hkdf(AES_KEY_SIZE, msg_key, salt=b"msg_salt", info=b"msg_aes")

    # Skipped keys management 
    def store_skipped_key(self, ratchet_pub_b64: str, index: int, mk: bytes):
        if len(self.skipped_message_keys) >= MAX_SKIPPED:
            oldest = next(iter(self.skipped_message_keys))
            del self.skipped_message_keys[oldest]
        self.skipped_message_keys[(ratchet_pub_b64, index)] = mk

    def try_decrypt_skipped(self, ratchet_pub_b64: str, index: int, ciphertext: bytes, nonce: bytes, aad: bytes) -> Optional[bytes]:
        key = self.skipped_message_keys.pop((ratchet_pub_b64, index), None)
        if key is None:
            return None
        aes_key = self.message_key_to_aeskey(key)
        pt = AESGCM(aes_key).decrypt(nonce, ciphertext, aad)
        zeroize(key)
        zeroize(aes_key)
        return pt

    # Ratchet 
    def ratchet_step_on_receive(self, their_pub_bytes: bytes):
        self.PN = self.Ns
        self.Ns = self.Nr = 0
        self.DHr = their_pub_bytes
        their_pub = self.x25519_pub_from_bytes(their_pub_bytes)
        dh_out = self.DHs.exchange(their_pub)
        rk, recv_ck = self.kdf_root(self.root_key, dh_out, b"_recv")
        self.root_key = rk
        self.recv_chain_key = recv_ck
        zeroize(dh_out)
        self.DHs = x25519.X25519PrivateKey.generate()

    # Encrypt with timestamp 
    def encrypt_message(self, plaintext: bytes) -> dict:
        next_ck, mk = self.kdf_chain(self.send_chain_key)
        self.send_chain_key = next_ck
        aes_key = self.message_key_to_aeskey(mk)

        nonce = self.Ns.to_bytes(NONCE_SIZE, "big")
        ts = int(time.time())
        aad = nonce + self.Ns.to_bytes(8, "big") + self.PN.to_bytes(8, "big") + ts.to_bytes(8, "big")
        ct = AESGCM(aes_key).encrypt(nonce, plaintext, aad)

        dh_pub = self.DHs.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        header = {"dh_pub": b64(dh_pub), "pn": self.PN, "ns": self.Ns, "ts": ts}

        self.Ns += 1
        zeroize(aes_key)
        zeroize(mk)
        return {"header": header, "nonce": b64(nonce), "ciphertext": b64(ct)}

    # Decrypt with timestamp 
    def decrypt_message(self, payload: dict) -> bytes:
        header = payload.get("header")
        if not header or "dh_pub" not in header or "ns" not in header or "pn" not in header or "ts" not in header:
            raise ValueError("Invalid header format")
        dh_pub_b64 = header["dh_pub"]
        ns = int(header["ns"])
        ts = int(header["ts"])
        nonce = ub64(payload["nonce"])
        ciphertext = ub64(payload["ciphertext"])
        aad = nonce + ns.to_bytes(8, "big") + self.PN.to_bytes(8, "big") + ts.to_bytes(8, "big")

        # Replay protection 
        now = int(time.time())
        last_seen = self.last_ts.get(dh_pub_b64, 0)
        if ts <= last_seen:
            raise ValueError("Replay attack detected: timestamp too old")
        if abs(now - ts) > MAX_REPLAY_AGE:
            raise ValueError("Message timestamp out of acceptable range")
        self.last_ts[dh_pub_b64] = ts

        # Skipped keys
        pt = self.try_decrypt_skipped(dh_pub_b64, ns, ciphertext, nonce, aad)
        if pt is not None:
            return pt

        their_pub_bytes = ub64(dh_pub_b64)
        if self.DHr != their_pub_bytes:
            self.ratchet_step_on_receive(their_pub_bytes)

        while self.Nr < ns:
            next_ck, mk = self.kdf_chain(self.recv_chain_key)
            self.recv_chain_key = next_ck
            self.store_skipped_key(dh_pub_b64, self.Nr, mk)
            self.Nr += 1

        next_ck, mk = self.kdf_chain(self.recv_chain_key)
        self.recv_chain_key = next_ck
        aes_key = self.message_key_to_aeskey(mk)
        pt = AESGCM(aes_key).decrypt(nonce, ciphertext, aad)
        zeroize(mk)
        zeroize(aes_key)
        self.Nr += 1
        return pt

    # State persistence 
    def save_state(self, path: str):
        data = {
            "root_key": b64(self.root_key or b""),
            "send_chain_key": b64(self.send_chain_key or b""),
            "recv_chain_key": b64(self.recv_chain_key or b""),
            "DHs": b64(self.x25519_priv_to_bytes(self.DHs)) if self.DHs else None,
            "DHr": b64(self.DHr or b""),
            "Ns": self.Ns,
            "Nr": self.Nr,
            "PN": self.PN,
            "skipped": {f"{k[0]}|{k[1]}": b64(v) for k, v in self.skipped_message_keys.items()},
            "last_ts": self.last_ts
        }
        Path(path).write_text(json.dumps(data))

    def load_state(self, path: str):
        if not Path(path).exists():
            return
        obj = json.loads(Path(path).read_text())
        self.root_key = ub64(obj.get("root_key", "")) or None
        self.send_chain_key = ub64(obj.get("send_chain_key", "")) or None
        self.recv_chain_key = ub64(obj.get("recv_chain_key", "")) or None
        if obj.get("DHs"):
            self.DHs = self.x25519_priv_from_bytes(ub64(obj["DHs"]))
        self.DHr = ub64(obj.get("DHr", "")) or None
        self.Ns = obj.get("Ns", 0)
        self.Nr = obj.get("Nr", 0)
        self.PN = obj.get("PN", 0)
        self.skipped_message_keys = {}
        for k, v in obj.get("skipped", {}).items():
            pub, idx = k.split("|")
            self.skipped_message_keys[(pub, int(idx))] = ub64(v)
        self.last_ts = obj.get("last_ts", {})

# Payload 
def pack_payload(header: dict, nonce: bytes, ciphertext: bytes, signature: bytes) -> bytes:
    return (json.dumps({
        "header": header,
        "nonce": b64(nonce),
        "ciphertext": b64(ciphertext),
        "signature": b64(signature)
    }, separators=(',', ':'), sort_keys=True) + "\n").encode()

def unpack_payload(raw: bytes) -> dict:
    return json.loads(raw.decode())

# Sign, verification 
def sign(priv: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    return priv.sign(data)

def verify(pub: ed25519.Ed25519PublicKey, sig: bytes, data: bytes) -> bool:
    try:
        pub.verify(sig, data)
        return True
    except Exception:
        return False

# CLI helpers 
def prompt():
    print(YOUR_PROMPT, end="", flush=True)

def show(msg):
    print(f"{THEIR_PROMPT}{msg.decode() if isinstance(msg, bytes) else msg}", flush=True)

async def read_message_from_stdin():
    return await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
