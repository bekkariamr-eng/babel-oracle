"""
Babel Oracle Protocol - Core Cryptographic Primitives
=====================================================
Offline mode: SHA-256 CTR as deterministic OTP generator.
Zero network traffic. Both parties derive identical keystreams
from a shared secret + timestamp.

Author: Amr Bekkari
"""

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


# =============================================================================
# 1. KEY EXCHANGE — ECDH (Curve25519)
# =============================================================================

@dataclass
class KeyPair:
    """An ECDH keypair (Curve25519)."""
    private_key: X25519PrivateKey
    public_bytes: bytes  # 32 bytes raw public key

    @classmethod
    def generate(cls) -> "KeyPair":
        sk = X25519PrivateKey.generate()
        pk_bytes = sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return cls(private_key=sk, public_bytes=pk_bytes)

    def derive_shared_secret(self, peer_public_bytes: bytes) -> bytes:
        """Compute ECDH shared secret with peer's public key."""
        peer_pk = X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared = self.private_key.exchange(peer_pk)
        return shared  # 32 bytes


# =============================================================================
# 2. KEY DERIVATION — HKDF via HMAC-SHA256
# =============================================================================

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869): PRK = HMAC-SHA256(salt, ikm)"""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869): derive `length` bytes from PRK."""
    n = (length + 31) // 32
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def derive_master_key(shared_secret: bytes) -> bytes:
    """Derive master key from ECDH shared secret."""
    prk = hkdf_extract(b"babel-oracle-v1-salt", shared_secret)
    return hkdf_expand(prk, b"babel-oracle-master-key", 32)


def derive_session_key(master_key: bytes, session_id: int) -> bytes:
    """Derive per-session key (e.g., one per day)."""
    info = b"babel-session-" + struct.pack(">Q", session_id)
    prk = hkdf_extract(master_key, info)
    return hkdf_expand(prk, b"session-key", 32)


def derive_slot_seed(session_key: bytes, timestamp: int) -> bytes:
    """Derive per-slot seed from session key + time slot."""
    return hmac.new(
        session_key,
        struct.pack(">Q", timestamp),
        hashlib.sha256,
    ).digest()


# =============================================================================
# 3. OTP GENERATOR — SHA-256 Counter Mode (offline, zero network)
# =============================================================================

class SHA256_CTR_OTP:
    """
    Deterministic OTP generator using SHA-256 in counter mode.
    
    Given a 32-byte seed, produces an infinite stream of pseudo-random
    bytes: OTP[i] = SHA-256(seed || counter_i)
    
    Properties:
    - Deterministic: same seed → same stream (both parties)
    - CSPRNG: SHA-256 pre-image resistance guarantees unpredictability
    - Offline: zero network traffic
    - Speed: ~300 MB/s on modern CPU
    - 32 bytes output per iteration
    """

    def __init__(self, seed: bytes):
        assert len(seed) == 32, "Seed must be 32 bytes"
        self.seed = seed
        self.counter = 0
        self.buffer = b""

    def generate(self, length: int) -> bytes:
        """Generate `length` bytes of OTP."""
        while len(self.buffer) < length:
            block = hashlib.sha256(
                self.seed + struct.pack(">Q", self.counter)
            ).digest()
            self.buffer += block
            self.counter += 1

        result = self.buffer[:length]
        self.buffer = self.buffer[length:]
        return result

    def reset(self):
        """Reset to beginning of stream."""
        self.counter = 0
        self.buffer = b""


def get_otp_generator(seed: bytes, backend: str = "sha256-ctr"):
    """Factory: create an OTP generator by backend name."""
    if backend == "chacha20":
        # ChaCha20 will be added in a later step; for now fall back to SHA256
        return SHA256_CTR_OTP(seed)
    return SHA256_CTR_OTP(seed)


# =============================================================================
# 4. XOR ENCRYPTION (Vernam cipher)
# =============================================================================

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR data with key (Vernam cipher)."""
    assert len(data) <= len(key), f"Key too short: {len(key)} < {len(data)}"
    return bytes(a ^ b for a, b in zip(data, key))


# =============================================================================
# 5. MESSAGE FRAMING — with HMAC integrity
# =============================================================================

MAGIC = b"BABEL01"
PAD_BUCKETS = [256, 512, 1024, 2048, 4096]


def pad_plaintext(plaintext: bytes) -> bytes:
    """Pad plaintext to a fixed bucket size to defeat length-based analysis."""
    size = len(plaintext)
    for bucket in PAD_BUCKETS:
        if size <= bucket:
            return plaintext + os.urandom(bucket - size)
    # Larger than max bucket: pad to next multiple of 4096
    target = ((size + 4095) // 4096) * 4096
    return plaintext + os.urandom(target - size)


def frame_message(plaintext: bytes, session_key: bytes, pad: bool = True) -> bytes:
    """
    Frame a message with length + HMAC for integrity verification.
    Format: MAGIC(7) || LENGTH(4) || PLAINTEXT(N) || HMAC(32)
    LENGTH stores the original (unpadded) size so unframe recovers exact plaintext.
    """
    original_length = len(plaintext)
    if pad:
        plaintext = pad_plaintext(plaintext)
    length = struct.pack(">I", original_length)
    mac_data = MAGIC + length + plaintext
    mac = hmac.new(session_key, mac_data, hashlib.sha256).digest()
    return mac_data + mac


def unframe_message(frame: bytes, session_key: bytes) -> Optional[bytes]:
    """
    Unframe and verify a message. Returns plaintext or None if MAC fails.
    """
    if len(frame) < 7 + 4 + 32:
        return None
    if frame[:7] != MAGIC:
        return None

    mac_received = frame[-32:]
    mac_data = frame[:-32]
    mac_computed = hmac.new(session_key, mac_data, hashlib.sha256).digest()

    if not hmac.compare_digest(mac_received, mac_computed):
        return None

    length = struct.unpack(">I", frame[7:11])[0]
    plaintext = frame[11 : 11 + length]

    if len(plaintext) != length:
        return None

    return plaintext


# =============================================================================
# 6. HIGH-LEVEL PROTOCOL — Party abstraction
# =============================================================================

@dataclass
class Party:
    """
    A protocol participant (Alice or Bob).

    Holds key material and can encrypt/decrypt messages in a given time slot.
    """
    name: str
    keypair: KeyPair = field(default_factory=KeyPair.generate)
    master_key: Optional[bytes] = None
    session_key: Optional[bytes] = None
    _session_id: int = 0
    backend: str = "sha256-ctr"

    @property
    def public_key(self) -> bytes:
        return self.keypair.public_bytes

    def establish_key(self, peer_public: bytes):
        """Phase 0: Derive shared master key from peer's public key."""
        shared = self.keypair.derive_shared_secret(peer_public)
        self.master_key = derive_master_key(shared)

    def open_session(self, session_id: int = 0):
        """Phase 1a: Derive session key."""
        assert self.master_key is not None, "Call establish_key first"
        self._session_id = session_id
        self.session_key = derive_session_key(self.master_key, session_id)

    def get_otp(self, slot_timestamp: int, length: int, seed_override: bytes = None) -> bytes:
        """Phase 1b: Generate OTP for a given time slot."""
        assert self.session_key is not None, "Call open_session first"
        seed = seed_override or derive_slot_seed(self.session_key, slot_timestamp)
        gen = get_otp_generator(seed, self.backend)
        return gen.generate(length)

    def encrypt(self, plaintext: bytes, slot_timestamp: int, pad: bool = True) -> bytes:
        """Phase 2: Frame + encrypt with per-message nonce and backend byte."""
        frame = frame_message(plaintext, self.session_key, pad=pad)
        nonce = os.urandom(16)
        seed = derive_slot_seed(self.session_key, slot_timestamp)
        effective_seed = hmac.new(seed, nonce, hashlib.sha256).digest()
        gen = get_otp_generator(effective_seed, self.backend)
        otp = gen.generate(len(frame))
        ciphertext = xor_bytes(frame, otp)
        backend_byte = b"\x01" if self.backend == "chacha20" else b"\x00"
        return nonce + backend_byte + ciphertext

    def decrypt(self, ciphertext: bytes, slot_timestamp: int,
                seen_slots: set = None) -> Optional[bytes]:
        """Phase 4: Decrypt + verify. Supports nonce+backend and legacy formats."""
        # Try new format: nonce(16) || backend(1) || ciphertext
        if len(ciphertext) > 17:
            nonce = ciphertext[:16]
            backend_byte = ciphertext[16]
            ct = ciphertext[17:]
            backend = "chacha20" if backend_byte == 0x01 else "sha256-ctr"
            replay_key = f"{slot_timestamp}:{nonce.hex()}"
            if seen_slots is not None and replay_key in seen_slots:
                return None
            seed = derive_slot_seed(self.session_key, slot_timestamp)
            effective_seed = hmac.new(seed, nonce, hashlib.sha256).digest()
            gen = get_otp_generator(effective_seed, backend)
            otp = gen.generate(len(ct))
            frame = xor_bytes(ct, otp)
            result = unframe_message(frame, self.session_key)
            if result is not None:
                if seen_slots is not None:
                    seen_slots.add(replay_key)
                return result

        # Fallback: legacy format (no nonce, no backend byte)
        if seen_slots is not None and slot_timestamp in seen_slots:
            return None
        seed = derive_slot_seed(self.session_key, slot_timestamp)
        gen = SHA256_CTR_OTP(seed)
        otp = gen.generate(len(ciphertext))
        frame = xor_bytes(ciphertext, otp)
        result = unframe_message(frame, self.session_key)
        if result is not None and seen_slots is not None:
            seen_slots.add(slot_timestamp)
        return result
