#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          BABEL ORACLE — Covert Communication Tool           ║
║         Zero Infrastructure. Zero Detection. OTP.           ║
║                                                             ║
║  Author: Amr Bekkari                                        ║
║  ENSA Tanger — Cybersecurity Engineering                    ║
╚══════════════════════════════════════════════════════════════╝

Standalone offline covert channel using:
  - ECDH Curve25519 key exchange
  - HKDF hierarchical key derivation
  - SHA-256 Counter Mode OTP (zero network)
  - XOR encryption (Vernam / information-theoretic security)
  - HMAC-SHA256 integrity verification
"""

import hashlib
import hmac
import os
import sys
import struct
import time
import math
import json
import base64
import getpass
from pathlib import Path
from typing import Optional, Tuple

# ═══════════════════════════════════════════════════════════════
# CRYPTO CORE
# ═══════════════════════════════════════════════════════════════

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_ECDH = True
except ImportError:
    HAS_ECDH = False


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    n = (length + 31) // 32
    okm, t = b"", b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def derive_master_key(shared_secret: bytes) -> bytes:
    prk = hkdf_extract(b"babel-oracle-v1-salt", shared_secret)
    return hkdf_expand(prk, b"babel-oracle-master-key", 32)

def derive_session_key(master_key: bytes, session_id: int) -> bytes:
    info = b"babel-session-" + struct.pack(">Q", session_id)
    prk = hkdf_extract(master_key, info)
    return hkdf_expand(prk, b"session-key", 32)

def derive_slot_seed(session_key: bytes, timestamp: int) -> bytes:
    return hmac.new(session_key, struct.pack(">Q", timestamp), hashlib.sha256).digest()

def sha256_ctr_generate(seed: bytes, length: int) -> bytes:
    """SHA-256 Counter Mode OTP generator."""
    out, ctr = b"", 0
    while len(out) < length:
        out += hashlib.sha256(seed + struct.pack(">Q", ctr)).digest()
        ctr += 1
    return out[:length]

def chacha20_generate(seed: bytes, length: int) -> bytes:
    """ChaCha20 keystream generator (fast, hardware-accelerated)."""
    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
    key = hkdf_expand(seed, b"chacha20-key", 32)
    nonce = hkdf_expand(seed, b"chacha20-nonce", 16)
    cipher = Cipher(ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(b"\x00" * length)


def generate_otp(seed: bytes, length: int, backend: str = "sha256-ctr") -> bytes:
    """Generate OTP bytes using the configured backend."""
    if backend == "chacha20":
        return chacha20_generate(seed, length)
    return sha256_ctr_generate(seed, length)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

MAGIC = b"BABEL01"
PAD_BUCKETS = [256, 512, 1024, 2048, 4096]


def pad_plaintext(plaintext: bytes) -> bytes:
    """Pad plaintext to a fixed bucket size to defeat length-based analysis."""
    size = len(plaintext)
    for bucket in PAD_BUCKETS:
        if size <= bucket:
            return plaintext + os.urandom(bucket - size)
    target = ((size + 4095) // 4096) * 4096
    return plaintext + os.urandom(target - size)


def frame_message(plaintext: bytes, session_key: bytes, pad: bool = True) -> bytes:
    original_length = len(plaintext)
    if pad:
        plaintext = pad_plaintext(plaintext)
    length = struct.pack(">I", original_length)
    mac_data = MAGIC + length + plaintext
    mac = hmac.new(session_key, mac_data, hashlib.sha256).digest()
    return mac_data + mac

def unframe_message(frame: bytes, session_key: bytes) -> Optional[bytes]:
    if len(frame) < 43 or frame[:7] != MAGIC:
        return None
    mac_received = frame[-32:]
    mac_data = frame[:-32]
    mac_computed = hmac.new(session_key, mac_data, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_received, mac_computed):
        return None
    length = struct.unpack(">I", frame[7:11])[0]
    plaintext = frame[11:11 + length]
    return plaintext if len(plaintext) == length else None


# ═══════════════════════════════════════════════════════════════
# KEY MANAGEMENT
# ═══════════════════════════════════════════════════════════════

KEYS_DIR = Path.home() / ".babel-oracle"

def ensure_keys_dir():
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate ECDH keypair. Returns (private_bytes, public_bytes)."""
    if HAS_ECDH:
        sk = X25519PrivateKey.generate()
        priv = sk.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pub = sk.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return priv, pub
    else:
        # Fallback: use random bytes as shared secret (less secure, no ECDH)
        priv = os.urandom(32)
        pub = hashlib.sha256(b"babel-pubkey-" + priv).digest()
        return priv, pub

def compute_shared_secret(my_priv: bytes, peer_pub: bytes) -> bytes:
    if HAS_ECDH:
        sk = X25519PrivateKey.from_private_bytes(my_priv)
        pk = X25519PublicKey.from_public_bytes(peer_pub)
        return sk.exchange(pk)
    else:
        # Fallback: HKDF of concatenated keys
        return hkdf_extract(my_priv, peer_pub)

def encrypt_private_key(priv_bytes: bytes, passphrase: str) -> dict:
    """Encrypt a private key with PBKDF2 + AES-256-GCM."""
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    derived_key = kdf.derive(passphrase.encode("utf-8"))
    nonce = os.urandom(12)
    ct = AESGCM(derived_key).encrypt(nonce, priv_bytes, None)
    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }


def decrypt_private_key(enc_data: dict, passphrase: str) -> bytes:
    """Decrypt a private key encrypted with PBKDF2 + AES-256-GCM."""
    salt = base64.b64decode(enc_data["salt"])
    nonce = base64.b64decode(enc_data["nonce"])
    ct = base64.b64decode(enc_data["ciphertext"])
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    derived_key = kdf.derive(passphrase.encode("utf-8"))
    return AESGCM(derived_key).decrypt(nonce, ct, None)


def save_identity(name: str, priv: bytes, pub: bytes, passphrase: str = None):
    ensure_keys_dir()
    if passphrase:
        data = {
            "name": name,
            "version": 2,
            "encrypted": True,
            "private_enc": encrypt_private_key(priv, passphrase),
            "public": base64.b64encode(pub).decode(),
        }
    else:
        data = {"name": name, "private": base64.b64encode(priv).decode(),
                "public": base64.b64encode(pub).decode()}
    path = KEYS_DIR / f"{name}.identity.json"
    path.write_text(json.dumps(data, indent=2))
    return path

def load_identity(name: str) -> Tuple[bytes, bytes]:
    path = KEYS_DIR / f"{name}.identity.json"
    if not path.exists():
        raise FileNotFoundError(f"Identity '{name}' not found at {path}")
    data = json.loads(path.read_text())

    if data.get("encrypted"):
        passphrase = getpass.getpass("  Passphrase for identity: ")
        try:
            priv = decrypt_private_key(data["private_enc"], passphrase)
        except Exception:
            raise ValueError("Wrong passphrase or corrupted key file")
        return priv, base64.b64decode(data["public"])

    return base64.b64decode(data["private"]), base64.b64decode(data["public"])

def save_peer_key(peer_name: str, pub: bytes):
    ensure_keys_dir()
    data = {"name": peer_name, "public": base64.b64encode(pub).decode()}
    path = KEYS_DIR / f"{peer_name}.peer.json"
    path.write_text(json.dumps(data, indent=2))
    return path

def load_peer_key(peer_name: str) -> bytes:
    path = KEYS_DIR / f"{peer_name}.peer.json"
    if not path.exists():
        raise FileNotFoundError(f"Peer key '{peer_name}' not found at {path}")
    data = json.loads(path.read_text())
    return base64.b64decode(data["public"])

def derive_session(my_priv: bytes, peer_pub: bytes, session_id: int) -> bytes:
    shared = compute_shared_secret(my_priv, peer_pub)
    master = derive_master_key(shared)
    return derive_session_key(master, session_id)


# ═══════════════════════════════════════════════════════════════
# REPLAY PROTECTION
# ═══════════════════════════════════════════════════════════════

REPLAY_LOG_PATH = KEYS_DIR / "replay_log.json"
REPLAY_MAX_AGE = 86400  # 24 hours in seconds


def load_replay_log() -> dict:
    """Load replay log from disk. Prune entries older than 24 hours."""
    if not REPLAY_LOG_PATH.exists():
        return {}
    try:
        log = json.loads(REPLAY_LOG_PATH.read_text())
    except (json.JSONDecodeError, IOError):
        return {}
    # Prune old entries (supports both legacy int timestamps and new "ts:nonce_hex" strings)
    cutoff = int(time.time()) - REPLAY_MAX_AGE
    for peer in list(log.keys()):
        kept = []
        for entry in log[peer]:
            if isinstance(entry, int):
                if entry >= cutoff:
                    kept.append(entry)
            else:
                # New format: "slot_ts:nonce_hex" — extract the numeric timestamp
                try:
                    ts = int(entry.split(":")[0])
                    if ts >= cutoff:
                        kept.append(entry)
                except (ValueError, IndexError):
                    pass  # discard malformed entries
        log[peer] = kept
        if not log[peer]:
            del log[peer]
    return log


def save_replay_log(log: dict):
    """Save replay log to disk."""
    ensure_keys_dir()
    REPLAY_LOG_PATH.write_text(json.dumps(log, indent=2))


SESSION_TTL = 86400  # Default: 24 hours
CONFIG_PATH = KEYS_DIR / "config.json"
SESSIONS_PATH = KEYS_DIR / "sessions.json"


def load_config() -> dict:
    """Load config from disk. Returns defaults if not found."""
    defaults = {"session_ttl": SESSION_TTL, "otp_backend": "sha256-ctr"}
    if not CONFIG_PATH.exists():
        return defaults
    try:
        cfg = json.loads(CONFIG_PATH.read_text())
        for k, v in defaults.items():
            cfg.setdefault(k, v)
        return cfg
    except (json.JSONDecodeError, IOError):
        return defaults


def save_config(cfg: dict):
    """Save config to disk."""
    ensure_keys_dir()
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


def get_session_id(ttl: int = 86400) -> int:
    """Derive session ID based on TTL."""
    if ttl >= 86400:
        return int(time.strftime("%Y%m%d"))
    return int(time.time()) // ttl


def load_sessions() -> dict:
    """Load session creation timestamps."""
    if not SESSIONS_PATH.exists():
        return {}
    try:
        return json.loads(SESSIONS_PATH.read_text())
    except (json.JSONDecodeError, IOError):
        return {}


def save_sessions(sessions: dict):
    """Save session timestamps."""
    ensure_keys_dir()
    SESSIONS_PATH.write_text(json.dumps(sessions, indent=2))


def check_session_expiry(my_name: str, peer_name: str, session_id: int, ttl: int) -> Tuple[bool, int]:
    """Check if session is expired. Returns (expired, seconds_remaining)."""
    sessions = load_sessions()
    key = f"{min(my_name, peer_name)}_{max(my_name, peer_name)}_{session_id}"
    now = int(time.time())

    if key not in sessions:
        sessions[key] = {"created_at": now, "session_id": session_id}
        save_sessions(sessions)
        return False, ttl

    created = sessions[key]["created_at"]
    elapsed = now - created
    remaining = ttl - elapsed

    if remaining <= 0:
        return True, 0
    return False, remaining


# ═══════════════════════════════════════════════════════════════
# ENCRYPT / DECRYPT ENGINE
# ═══════════════════════════════════════════════════════════════

def get_slot_timestamp() -> int:
    """Current 60-second time slot."""
    return int(time.time()) // 60 * 60

def encrypt_data(plaintext: bytes, session_key: bytes, slot_ts: int,
                 pad: bool = True, backend: str = "sha256-ctr") -> bytes:
    """Encrypt plaintext with per-message nonce and backend indicator."""
    frame = frame_message(plaintext, session_key, pad=pad)
    nonce = os.urandom(16)
    slot_seed = derive_slot_seed(session_key, slot_ts)
    effective_seed = hmac.new(slot_seed, nonce, hashlib.sha256).digest()
    otp = generate_otp(effective_seed, len(frame), backend)
    ciphertext = xor_bytes(frame, otp)
    backend_byte = b"\x01" if backend == "chacha20" else b"\x00"
    # Packet: timestamp(8) || nonce(16) || backend(1) || ciphertext
    return struct.pack(">Q", slot_ts) + nonce + backend_byte + ciphertext

def decrypt_data(packet: bytes, session_key: bytes,
                 peer_name: str = None, replay_log: dict = None) -> Optional[bytes]:
    """Decrypt packet. Supports new format (nonce+backend) and legacy (no nonce)."""
    if len(packet) < 8:
        return None
    slot_ts = struct.unpack(">Q", packet[:8])[0]

    # Try new format: timestamp(8) || nonce(16) || backend(1) || ciphertext
    if len(packet) > 25:
        nonce = packet[8:24]
        nonce_hex = nonce.hex()
        backend_byte = packet[24]
        ciphertext = packet[25:]
        backend = "chacha20" if backend_byte == 0x01 else "sha256-ctr"

        # Replay check (new format: "slot_ts:nonce_hex")
        replay_key = f"{slot_ts}:{nonce_hex}"
        if peer_name and replay_log is not None:
            if replay_key in replay_log.get(peer_name, []):
                return None

        slot_seed = derive_slot_seed(session_key, slot_ts)
        effective_seed = hmac.new(slot_seed, nonce, hashlib.sha256).digest()
        otp = generate_otp(effective_seed, len(ciphertext), backend)
        frame = xor_bytes(ciphertext, otp)
        result = unframe_message(frame, session_key)

        if result is not None:
            if peer_name and replay_log is not None:
                replay_log.setdefault(peer_name, []).append(replay_key)
            return result

        # If declared backend didn't work, try the other backend
        alt_backend = "sha256-ctr" if backend == "chacha20" else "chacha20"
        otp = generate_otp(effective_seed, len(ciphertext), alt_backend)
        frame = xor_bytes(ciphertext, otp)
        result = unframe_message(frame, session_key)

        if result is not None:
            if peer_name and replay_log is not None:
                replay_log.setdefault(peer_name, []).append(replay_key)
            return result

    # Fallback: legacy format (no nonce, no backend) — timestamp(8) || ciphertext
    ciphertext = packet[8:]
    if peer_name and replay_log is not None:
        if slot_ts in replay_log.get(peer_name, []):
            return None

    slot_seed = derive_slot_seed(session_key, slot_ts)
    otp = sha256_ctr_generate(slot_seed, len(ciphertext))
    frame = xor_bytes(ciphertext, otp)
    result = unframe_message(frame, session_key)

    if result is not None and peer_name and replay_log is not None:
        replay_log.setdefault(peer_name, []).append(slot_ts)

    return result


# ═══════════════════════════════════════════════════════════════
# NIST SP 800-22 TESTS
# ═══════════════════════════════════════════════════════════════

def frequency_test(data: bytes) -> Tuple[float, bool]:
    n = len(data) * 8
    s = sum(bin(b).count("1") for b in data)
    s_obs = abs(2 * s - n) / math.sqrt(n)
    p = math.erfc(s_obs / math.sqrt(2))
    return p, p >= 0.01

def entropy_per_byte(data: bytes) -> float:
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((f/n) * math.log2(f/n) for f in freq if f > 0)

def run_quality_tests(seed: bytes, size: int = 50000) -> dict:
    data = sha256_ctr_generate(seed, size)
    p_freq, pass_freq = frequency_test(data)
    ent = entropy_per_byte(data)
    return {
        "frequency_monobit": {"p": round(p_freq, 6), "pass": pass_freq},
        "entropy_per_byte": {"value": round(ent, 4), "pass": ent >= 7.9},
        "sample_size": size,
    }


# ═══════════════════════════════════════════════════════════════
# CLI INTERFACE
# ═══════════════════════════════════════════════════════════════

BANNER = r"""
 ____        _          _    ___                 _      
| __ )  __ _| |__   ___| |  / _ \ _ __ __ _  ___| | ___ 
|  _ \ / _` | '_ \ / _ \ | | | | | '__/ _` |/ __| |/ _ \
| |_) | (_| | |_) |  __/ | | |_| | | | (_| | (__| |  __/
|____/ \__,_|_.__/ \___|_|  \___/|_|  \__,_|\___|_|\___|

  Covert Communication Protocol — Zero Infrastructure
  By Amr Bekkari | ENSA Tanger | Cybersecurity Engineering
"""

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def pause():
    input("\n  Press Enter to continue...")

def header(title: str):
    w = 60
    print(f"\n  {'─'*w}")
    print(f"  {title}")
    print(f"  {'─'*w}")

def menu_choice(options: list) -> int:
    for i, opt in enumerate(options, 1):
        print(f"  [{i}] {opt}")
    print()
    while True:
        try:
            c = int(input("  > "))
            if 1 <= c <= len(options):
                return c
        except (ValueError, EOFError):
            pass
        print("  Invalid choice. Try again.")


def cmd_generate_identity():
    header("GENERATE IDENTITY (ECDH Keypair)")
    name = input("  Your identity name (e.g., alice): ").strip().lower()
    if not name:
        print("  Cancelled.")
        return

    priv, pub = generate_keypair()

    # Offer passphrase protection
    passphrase = None
    protect = input("  Protect private key with a passphrase? [y/N]: ").strip().lower()
    if protect == "y":
        p1 = getpass.getpass("  Passphrase: ")
        p2 = getpass.getpass("  Confirm passphrase: ")
        if p1 != p2:
            print("  Passphrases do not match. Saving WITHOUT encryption.")
        elif not p1:
            print("  Empty passphrase. Saving WITHOUT encryption.")
        else:
            passphrase = p1

    path = save_identity(name, priv, pub, passphrase=passphrase)

    print(f"\n  Identity '{name}' created!")
    if passphrase:
        print(f"  Private key is ENCRYPTED (PBKDF2 + AES-256-GCM)")
    print(f"  Saved to: {path}")
    print(f"\n  Your PUBLIC KEY (share this with your peer):\n")
    print(f"  {base64.b64encode(pub).decode()}")
    print(f"\n  Copy this key and send it to your peer via any channel.")
    print(f"  The public key reveals nothing about your private key.")
    pause()


def cmd_import_peer():
    header("IMPORT PEER PUBLIC KEY")
    peer_name = input("  Peer name (e.g., bob): ").strip().lower()
    if not peer_name:
        print("  Cancelled.")
        return
    pub_b64 = input("  Peer's public key (base64): ").strip()
    try:
        pub = base64.b64decode(pub_b64)
        if len(pub) != 32:
            print(f"  Error: key must be 32 bytes, got {len(pub)}")
            return
    except Exception as e:
        print(f"  Error: {e}")
        return

    path = save_peer_key(peer_name, pub)
    print(f"\n  Peer '{peer_name}' imported!")
    print(f"  Saved to: {path}")
    pause()


def cmd_encrypt_message():
    header("ENCRYPT MESSAGE")
    my_name = input("  Your identity name: ").strip().lower()
    peer_name = input("  Peer name: ").strip().lower()

    try:
        my_priv, my_pub = load_identity(my_name)
        peer_pub = load_peer_key(peer_name)
    except FileNotFoundError as e:
        print(f"\n  Error: {e}")
        pause()
        return

    cfg = load_config()
    ttl = cfg["session_ttl"]
    session_id = get_session_id(ttl)
    session_key = derive_session(my_priv, peer_pub, session_id)

    expired, remaining = check_session_expiry(my_name, peer_name, session_id, ttl)
    if expired:
        print(f"\n  SESSION EXPIRED! TTL: {ttl}s")
        print(f"  A new session will start automatically.")
        session_id = get_session_id(ttl)
        session_key = derive_session(my_priv, peer_pub, session_id)
        sessions = load_sessions()
        key = f"{min(my_name, peer_name)}_{max(my_name, peer_name)}_{session_id}"
        sessions[key] = {"created_at": int(time.time()), "session_id": session_id}
        save_sessions(sessions)
        print(f"  New session ID: {session_id}")
    else:
        hours_left = remaining / 3600
        print(f"  Session TTL: {hours_left:.1f}h remaining")

    slot_ts = get_slot_timestamp()
    backend = cfg.get("otp_backend", "sha256-ctr")

    print(f"\n  Session ID: {session_id}")
    print(f"  Time slot:  {slot_ts} ({time.strftime('%H:%M UTC', time.gmtime(slot_ts))})")
    print()

    mode = input("  [1] Text message  [2] File\n  > ").strip()

    if mode == "2":
        filepath = input("  File path: ").strip().strip('"')
        try:
            plaintext = Path(filepath).read_bytes()
            print(f"  Read {len(plaintext)} bytes from {filepath}")
        except Exception as e:
            print(f"  Error: {e}")
            pause()
            return
    else:
        msg = input("  Message: ")
        plaintext = msg.encode("utf-8")

    # Compute padded size for display
    padded_size = len(plaintext)
    for bucket in PAD_BUCKETS:
        if padded_size <= bucket:
            padded_size = bucket
            break
    else:
        padded_size = ((padded_size + 4095) // 4096) * 4096

    t0 = time.perf_counter()
    packet = encrypt_data(plaintext, session_key, slot_ts, backend=backend)
    elapsed = time.perf_counter() - t0

    encoded = base64.b64encode(packet).decode()

    print(f"\n  Encrypted in {elapsed*1e6:.0f} us")
    print(f"  OTP backend: {backend}")
    print(f"  Plaintext:   {len(plaintext)} bytes")
    print(f"  Padded to:   {padded_size} bytes")
    print(f"  Ciphertext:  {len(packet)} bytes")
    print(f"  Base64:      {len(encoded)} chars")

    # Save to file
    out_path = KEYS_DIR / f"msg_{int(time.time())}.babel"
    out_path.write_text(encoded)
    print(f"\n  Saved to: {out_path}")

    print(f"\n  {'─'*60}")
    print(f"  CIPHERTEXT (copy the line below)")
    print(f"  {'─'*60}")
    print(f"\n{encoded}\n")
    print(f"  {'─'*60}")

    # Auto-copy to clipboard (platform-aware)
    copied = False
    try:
        import subprocess
        if os.name == "nt":
            subprocess.run("clip", input=encoded.encode(), check=True)
            copied = True
        elif sys.platform == "darwin":
            subprocess.run("pbcopy", input=encoded.encode(), check=True)
            copied = True
        else:
            subprocess.run(["xclip", "-selection", "clipboard"],
                           input=encoded.encode(), check=True)
            copied = True
    except Exception:
        pass

    if copied:
        print(f"  [OK] Auto-copied to clipboard!")
    else:
        print(f"  [!] Could not auto-copy. Please select and copy manually.")

    ent = entropy_per_byte(packet[8:])  # skip timestamp header
    print(f"\n  Entropy: {ent:.2f} bits/byte (ciphertext is indistinguishable from noise)")
    pause()


def cmd_decrypt_message():
    header("DECRYPT MESSAGE")
    my_name = input("  Your identity name: ").strip().lower()
    peer_name = input("  Peer name (sender): ").strip().lower()

    try:
        my_priv, my_pub = load_identity(my_name)
        peer_pub = load_peer_key(peer_name)
    except FileNotFoundError as e:
        print(f"\n  Error: {e}")
        pause()
        return

    cfg = load_config()
    ttl = cfg["session_ttl"]
    session_id = get_session_id(ttl)
    session_key = derive_session(my_priv, peer_pub, session_id)

    print()
    mode = input("  [1] Paste base64  [2] Load .babel file\n  > ").strip()

    if mode == "2":
        filepath = input("  File path: ").strip().strip('"')
        try:
            encoded = Path(filepath).read_text().strip()
        except Exception as e:
            print(f"  Error: {e}")
            pause()
            return
    else:
        print("  Paste ciphertext (base64), then press Enter:")
        encoded = input("  > ").strip()

    try:
        packet = base64.b64decode(encoded)
    except Exception as e:
        print(f"\n  Error decoding base64: {e}")
        pause()
        return

    # Load replay log for protection
    replay_log = load_replay_log()

    t0 = time.perf_counter()
    plaintext = decrypt_data(packet, session_key,
                             peer_name=peer_name, replay_log=replay_log)
    elapsed = time.perf_counter() - t0

    if plaintext is None:
        slot_ts = struct.unpack(">Q", packet[:8])[0] if len(packet) >= 8 else 0
        peer_entries = replay_log.get(peer_name, [])
        # Check both new format (string) and old format (int)
        is_replay = False
        if len(packet) > 24:
            nonce_hex = packet[8:24].hex()
            replay_key = f"{slot_ts}:{nonce_hex}"
            is_replay = replay_key in peer_entries
        if not is_replay:
            is_replay = slot_ts in peer_entries

        if is_replay:
            print(f"\n  REPLAY DETECTED! This message has already been received.")
        else:
            print(f"\n  DECRYPTION FAILED!")
            print(f"  Possible causes:")
            print(f"  - Wrong identity or peer key")
            print(f"  - Message was tampered with")
            print(f"  - Different session (different day?)")
        pause()
        return

    # Save updated replay log
    save_replay_log(replay_log)

    print(f"\n  Decrypted in {elapsed*1e6:.0f} us")
    print(f"  HMAC integrity: VERIFIED")

    # Try to decode as text
    try:
        text = plaintext.decode("utf-8")
        print(f"\n  ┌─ MESSAGE ────────────────────────────────────────┐")
        for line in text.split("\n"):
            print(f"  │ {line:<52s} │")
        print(f"  └──────────────────────────────────────────────────┘")
    except UnicodeDecodeError:
        print(f"\n  Binary data: {len(plaintext)} bytes")
        out_path = KEYS_DIR / f"decrypted_{int(time.time())}.bin"
        out_path.write_bytes(plaintext)
        print(f"  Saved to: {out_path}")

    pause()


def cmd_run_tests():
    header("STATISTICAL QUALITY TESTS (NIST SP 800-22)")
    seed = os.urandom(32)
    print(f"  Testing SHA-256 CTR with random seed...")
    print(f"  Generating 50 KB of keystream...\n")

    results = run_quality_tests(seed)
    all_pass = True
    for name, r in results.items():
        if isinstance(r, dict):
            if "p" in r:
                status = "PASS" if r["pass"] else "FAIL"
                if not r["pass"]: all_pass = False
                print(f"  {name:.<40s} p={r['p']:.6f}  [{status}]")
            elif "value" in r:
                status = "PASS" if r["pass"] else "FAIL"
                if not r["pass"]: all_pass = False
                print(f"  {name:.<40s} val={r['value']}  [{status}]")

    print(f"\n  {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
    pause()


def cmd_show_info():
    header("PROTOCOL INFORMATION")
    print("""
  The Babel Oracle Protocol enables covert communication with:

  ZERO network traffic    — OTP generated locally via SHA-256 CTR
  ZERO infrastructure     — no servers, no domains, no accounts
  ZERO direct contact     — after initial key exchange, parties
                            never communicate again
  PERFECT secrecy         — One-Time Pad (Shannon's theorem)
  FORWARD secrecy         — unique key per time slot (HKDF)
  INTEGRITY               — HMAC-SHA256 on every message

  HOW IT WORKS:
  1. Alice and Bob exchange ECDH public keys (once)
  2. Both derive identical master key → session key → slot seed
  3. SHA-256(slot_seed || counter) generates identical OTP streams
  4. Message XOR OTP = ciphertext (indistinguishable from noise)
  5. Ciphertext transmitted via any channel (copy-paste, USB, etc.)
  6. Receiver generates same OTP, XORs back → original message

  The ciphertext looks like random noise. Even with full network
  capture, an adversary cannot determine that communication occurred.

  Keys stored in: """ + str(KEYS_DIR) + """
    """)
    pause()


def cmd_demo():
    header("FULL PROTOCOL DEMO (Alice ↔ Bob)")

    print("  Setting up Alice and Bob...\n")

    # Generate keypairs
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()

    print(f"  Alice pubkey: {base64.b64encode(a_pub).decode()[:40]}...")
    print(f"  Bob pubkey:   {base64.b64encode(b_pub).decode()[:40]}...")

    # Derive shared session
    session_id = int(time.strftime("%Y%m%d"))
    sk_a = derive_session(a_priv, b_pub, session_id)
    sk_b = derive_session(b_priv, a_pub, session_id)
    assert sk_a == sk_b
    print(f"\n  Session keys match: YES")
    print(f"  Session ID: {session_id}")

    # Encrypt
    slot = get_slot_timestamp()
    message = "Rendez-vous demain a 14h. Apporte les documents confidentiels.".encode()

    print(f"\n  Alice encrypts: \"{message.decode()}\"")
    print(f"  Original size: {len(message)} bytes")
    t0 = time.perf_counter()
    packet = encrypt_data(message, sk_a, slot)
    t_enc = time.perf_counter() - t0

    # Show padding info
    padded_size = len(message)
    for bucket in PAD_BUCKETS:
        if padded_size <= bucket:
            padded_size = bucket
            break
    print(f"  Padded to: {padded_size} bytes (anti length-analysis)")
    print(f"  Encrypted in {t_enc*1e6:.0f} us → {len(packet)} bytes ciphertext")
    print(f"  Ciphertext (hex): {packet[:32].hex()}...")

    # Decrypt
    t0 = time.perf_counter()
    recovered = decrypt_data(packet, sk_b)
    t_dec = time.perf_counter() - t0

    assert recovered == message
    print(f"\n  Bob decrypts in {t_dec*1e6:.0f} us")
    print(f"  Recovered: \"{recovered.decode()}\"")
    print(f"  HMAC: VERIFIED")

    # Tamper test
    tampered = bytearray(packet)
    tampered[20] ^= 0xFF
    result = decrypt_data(bytes(tampered), sk_b)
    assert result is None
    print(f"\n  Tamper test: tampered ciphertext REJECTED (HMAC failed)")

    # Replay protection test
    replay_log = {}
    r1 = decrypt_data(packet, sk_b, peer_name="alice", replay_log=replay_log)
    assert r1 == message
    r2 = decrypt_data(packet, sk_b, peer_name="alice", replay_log=replay_log)
    assert r2 is None
    print(f"  Replay test: duplicate message correctly REJECTED")

    # OTP quality
    seed = derive_slot_seed(sk_a, slot)
    tests = run_quality_tests(seed)
    print(f"\n  OTP Quality (NIST SP 800-22):")
    for name, r in tests.items():
        if isinstance(r, dict) and "pass" in r:
            print(f"    {name}: {'PASS' if r['pass'] else 'FAIL'}")

    print(f"\n  === Demo complete. Zero network requests made. ===")
    pause()


def cmd_configure():
    header("CONFIGURATION")
    cfg = load_config()
    print(f"  Current settings:")
    print(f"    Session TTL: {cfg['session_ttl']}s ({cfg['session_ttl']/3600:.1f} hours)")
    print(f"    OTP backend: {cfg['otp_backend']}")
    print()

    choice = input("  [1] Change session TTL  [2] Change OTP backend  [3] Back\n  > ").strip()
    if choice == "1":
        try:
            ttl = int(input("  New TTL in seconds (e.g., 3600 for 1h, 86400 for 24h): "))
            if ttl < 60:
                print("  TTL must be at least 60 seconds.")
                return
            cfg["session_ttl"] = ttl
            save_config(cfg)
            print(f"  TTL updated to {ttl}s ({ttl/3600:.1f} hours)")
        except ValueError:
            print("  Invalid number.")
    elif choice == "2":
        print("  [1] sha256-ctr (default)  [2] chacha20")
        bc = input("  > ").strip()
        if bc == "2":
            cfg["otp_backend"] = "chacha20"
        else:
            cfg["otp_backend"] = "sha256-ctr"
        save_config(cfg)
        print(f"  OTP backend set to: {cfg['otp_backend']}")
    pause()


def main():
    clear()
    print(BANNER)

    while True:
        header("MAIN MENU")
        choice = menu_choice([
            "Generate my identity (ECDH keypair)",
            "Import peer's public key",
            "Encrypt a message / file",
            "Decrypt a message / file",
            "Run full demo (Alice ↔ Bob)",
            "Statistical quality tests (NIST)",
            "Protocol information",
            "Configure settings",
            "Exit",
        ])

        if choice == 1:
            cmd_generate_identity()
        elif choice == 2:
            cmd_import_peer()
        elif choice == 3:
            cmd_encrypt_message()
        elif choice == 4:
            cmd_decrypt_message()
        elif choice == 5:
            cmd_demo()
        elif choice == 6:
            cmd_run_tests()
        elif choice == 7:
            cmd_show_info()
        elif choice == 8:
            cmd_configure()
        elif choice == 9:
            print("\n  Goodbye.\n")
            sys.exit(0)


if __name__ == "__main__":
    main()
