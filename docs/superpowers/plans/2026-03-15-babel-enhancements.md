# Babel Oracle Enhancements — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement 5 enhancements: fix ciphertext output, add per-message nonce, session expiry, ChaCha20 backend, and Babel B=3 support.

**Architecture:** Each enhancement is independent and builds on a stable base. The per-message nonce changes the wire format (adds 16-byte nonce after timestamp). ChaCha20 adds a 1-byte backend indicator. Session expiry adds config persistence. All changes go in both `babel_oracle.py` (standalone) and `core.py` (modular), keeping them in sync.

**Tech Stack:** Python 3.9+, `cryptography` library (already a dependency for X25519, PBKDF2, AES-GCM — now also used for ChaCha20).

**Spec:** `docs/superpowers/specs/2026-03-15-babel-enhancements-design.md`

---

## File Structure

| File | Role | Changes |
|------|------|---------|
| `babel_oracle.py` | Standalone CLI (self-contained) | All 5 enhancements inline |
| `core.py` | Modular crypto primitives | Nonce, ChaCha20 OTP class, Party updates |
| `babel.py` | Babel Index | B=3 support, progress callback |
| `demo.py` | E2E demo script | Nonce-aware encrypt/decrypt, ChaCha20 demo |
| `tests.py` | NIST statistical tests | No changes needed |
| `CLAUDE.md` | Project documentation | Update with all new features |

---

## Chunk 1: Fix Ciphertext Output Format

### Task 1: Fix output display and clipboard in `babel_oracle.py`

**Files:**
- Modify: `babel_oracle.py` → `cmd_encrypt_message()` (ciphertext display section)

- [ ] **Step 1: Fix the ciphertext display format**

In `babel_oracle.py`, replace the ciphertext output section in `cmd_encrypt_message()` (the `─── CIPHERTEXT ───` block and clipboard code) with:

```python
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
```

- [ ] **Step 2: Verify the change manually**

Run: `python babel_oracle.py`
Select option 3 (Encrypt), provide identity/peer, enter a test message.
Expected: Clean base64 on its own line with no box characters, clipboard copy confirmation.

- [ ] **Step 3: Commit**

```bash
git add babel_oracle.py
git commit -m "fix: clean ciphertext output format with reliable cross-platform clipboard"
```

---

## Chunk 2: Per-Message Nonce + Backend Byte

> **Design decision**: The nonce AND backend byte are introduced together in this chunk
> to avoid an intermediate wire format that would need its own backward-compat path.
> This means `encrypt_data()` immediately produces the final format:
> `timestamp(8) || nonce(16) || backend(1) || ciphertext`.
> Until ChaCha20 is implemented in Chunk 4, the backend byte is always `0x00`.

### Task 2: Add nonce + backend byte to `encrypt_data()` in `babel_oracle.py`

**Files:**
- Modify: `babel_oracle.py` → `encrypt_data()`, `decrypt_data()`, add `generate_otp()` stub

- [ ] **Step 0: Add `generate_otp()` stub for forward compatibility**

After `sha256_ctr_generate()`, add a stub that will be expanded in Chunk 4:

```python
def generate_otp(seed: bytes, length: int, backend: str = "sha256-ctr") -> bytes:
    """Generate OTP bytes using the configured backend.
    ChaCha20 support will be added in a later step."""
    # ChaCha20 path will be added in Chunk 4
    return sha256_ctr_generate(seed, length)
```

- [ ] **Step 1: Modify `encrypt_data()` to generate nonce and include backend byte**

Replace the current `encrypt_data()` function:

```python
def encrypt_data(plaintext: bytes, session_key: bytes, slot_ts: int,
                 pad: bool = True, backend: str = "sha256-ctr") -> bytes:
    """Encrypt plaintext → ciphertext with per-message nonce and backend indicator."""
    frame = frame_message(plaintext, session_key, pad=pad)
    nonce = os.urandom(16)
    slot_seed = derive_slot_seed(session_key, slot_ts)
    effective_seed = hmac.new(slot_seed, nonce, hashlib.sha256).digest()
    otp = generate_otp(effective_seed, len(frame), backend)
    ciphertext = xor_bytes(frame, otp)
    backend_byte = b"\x01" if backend == "chacha20" else b"\x00"
    # Packet: timestamp(8) || nonce(16) || backend(1) || ciphertext
    return struct.pack(">Q", slot_ts) + nonce + backend_byte + ciphertext
```

- [ ] **Step 2: Modify `decrypt_data()` with three-path backward compatibility**

Replace the current `decrypt_data()` function. Three paths:
1. New format: `timestamp(8) || nonce(16) || backend(1) || ciphertext`
2. Legacy format: `timestamp(8) || ciphertext` (no nonce, no backend)

```python
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

    # Replay check (legacy: slot_ts as int)
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
```

- [ ] **Step 3: Update `cmd_decrypt_message()` replay detection display**

In `cmd_decrypt_message()`, update the replay check after failed decryption to handle both key formats:

```python
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
```

- [ ] **Step 4: Test the nonce roundtrip**

Run: `python babel_oracle.py`
Test: Encrypt a message, then decrypt it. Verify it works.
Test: Encrypt the same message twice in the same time slot — verify different ciphertext (base64 output differs).

- [ ] **Step 5: Commit**

```bash
git add babel_oracle.py
git commit -m "feat: add per-message nonce to prevent OTP reuse in same time slot"
```

### Task 3: Add nonce to `core.py` Party class

**Files:**
- Modify: `core.py` → `Party.encrypt()`, `Party.decrypt()`

- [ ] **Step 1: Update `Party.encrypt()` to use nonce + backend byte**

Note: `Party.encrypt()` does NOT prepend the timestamp (that's done at the packet level by the caller). It returns `nonce(16) + backend(1) + ciphertext`.

```python
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
```

- [ ] **Step 2: Update `Party.decrypt()` with dual-path (new + legacy)**

```python
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
```

- [ ] **Step 3: Add `import os` to core.py** (needed for `os.urandom`)

At the top of `core.py`, verify `import os` is present (it is — line 14).

- [ ] **Step 4: Test with demo.py**

Run: `python demo.py`
Expected: All assertions pass, including encrypt/decrypt roundtrip, tamper detection, and replay protection.

- [ ] **Step 5: Commit**

```bash
git add core.py
git commit -m "feat: add per-message nonce to Party encrypt/decrypt in core.py"
```

### Task 4: Update `demo.py` for nonce-aware protocol

**Files:**
- Modify: `demo.py` → encryption/decryption sections

- [ ] **Step 1: Add multi-message-same-slot test to demo.py**

After the replay protection section (Phase 3c), add:

```python
    # Test multi-message in same slot (nonce prevents OTP reuse)
    section("PHASE 3d — Multi-Message Same Slot (Nonce)")

    msg_1 = "First message in this slot".encode()
    msg_2 = "Second message in this slot".encode()

    ct_1 = alice.encrypt(msg_1, slot_timestamp)
    ct_2 = alice.encrypt(msg_2, slot_timestamp)

    assert ct_1 != ct_2, "Same-slot messages should produce different ciphertext"
    ok("Different ciphertext for same slot (nonce working)")

    # Bob decrypts both
    r1 = bob.decrypt(ct_1, slot_timestamp)
    r2 = bob.decrypt(ct_2, slot_timestamp)
    assert r1 == msg_1
    assert r2 == msg_2
    ok(f"Message 1: {r1.decode()}")
    ok(f"Message 2: {r2.decode()}")
```

- [ ] **Step 2: Run demo**

Run: `python demo.py`
Expected: All phases pass including the new Phase 3d.

- [ ] **Step 3: Commit**

```bash
git add demo.py
git commit -m "feat: add multi-message same-slot test to demo"
```

---

## Chunk 3: Session Expiry

### Task 5: Add config and session management to `babel_oracle.py`

**Files:**
- Modify: `babel_oracle.py` → add config/session functions, modify encrypt/decrypt commands

- [ ] **Step 1: Add config constants and helper functions**

After the `REPLAY_MAX_AGE` constant, add:

```python
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
```

- [ ] **Step 2: Modify `cmd_encrypt_message()` to check session expiry**

After the session key derivation (after `session_key = derive_session(...)` and before the message input), add:

```python
    cfg = load_config()
    ttl = cfg["session_ttl"]
    session_id = get_session_id(ttl)
    session_key = derive_session(my_priv, peer_pub, session_id)

    expired, remaining = check_session_expiry(my_name, peer_name, session_id, ttl)
    if expired:
        print(f"\n  SESSION EXPIRED! TTL: {ttl}s")
        print(f"  The current session has exceeded its lifetime.")
        print(f"  A new session will start automatically.")
        # Re-derive session ID from current time (not +1, which breaks date-based IDs)
        session_id = get_session_id(ttl)
        session_key = derive_session(my_priv, peer_pub, session_id)
        # Reset session tracking
        sessions = load_sessions()
        key = f"{min(my_name, peer_name)}_{max(my_name, peer_name)}_{session_id}"
        sessions[key] = {"created_at": int(time.time()), "session_id": session_id}
        save_sessions(sessions)
        print(f"  New session ID: {session_id}")
    else:
        hours_left = remaining / 3600
        print(f"  Session TTL: {hours_left:.1f}h remaining")
```

Replace the existing `session_id = int(time.strftime(...))` line with the config-based version above.

- [ ] **Step 3: Modify `cmd_decrypt_message()` to use config-based session ID**

Replace `session_id = int(time.strftime("%Y%m%d"))` with:

```python
    cfg = load_config()
    ttl = cfg["session_ttl"]
    session_id = get_session_id(ttl)
    session_key = derive_session(my_priv, peer_pub, session_id)
```

And after successful decryption, add a warning if near expiry:

```python
    expired, remaining = check_session_expiry(my_name, peer_name, session_id, ttl)
    if expired:
        print(f"\n  [!] Warning: This message is from an expired session.")
```

- [ ] **Step 4: Add config menu option**

Add a new menu option "Configure settings" before "Exit":

```python
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
```

Update the main menu to include the new option (insert before Exit):

```python
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
```

And add `elif choice == 8: cmd_configure()` and update Exit to `choice == 9`.

- [ ] **Step 5: Test session expiry**

Run: `python babel_oracle.py`
Configure TTL to 60s. Encrypt a message. Wait 70s. Try to encrypt again. Verify the expired session message appears and a new session starts.

- [ ] **Step 6: Commit**

```bash
git add babel_oracle.py
git commit -m "feat: add configurable session expiry with TTL and auto-rotation"
```

---

## Chunk 4: ChaCha20 OTP Backend

### Task 6: Add `ChaCha20_OTP` class to `core.py`

**Files:**
- Modify: `core.py` → add ChaCha20_OTP class and factory function

- [ ] **Step 1: Add ChaCha20 import and class**

After the `SHA256_CTR_OTP` class in `core.py`, add:

```python
class ChaCha20_OTP:
    """
    Deterministic OTP generator using ChaCha20 stream cipher.

    Same interface as SHA256_CTR_OTP but ~100x faster via OpenSSL.
    Generates keystream by encrypting zeros.
    """

    def __init__(self, seed: bytes):
        assert len(seed) == 32, "Seed must be 32 bytes"
        from cryptography.hazmat.primitives.ciphers import Cipher
        from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
        # Derive key and nonce from seed using HKDF
        key = hkdf_expand(seed, b"chacha20-key", 32)
        nonce = hkdf_expand(seed, b"chacha20-nonce", 16)  # 4-byte counter + 12-byte nonce
        algorithm = ChaCha20(key, nonce)
        self._cipher = Cipher(algorithm, mode=None)
        self._encryptor = self._cipher.encryptor()  # stateful — maintains position
        self._seed = seed
        self._key = key
        self._nonce = nonce

    def generate(self, length: int) -> bytes:
        """Generate `length` bytes of keystream by encrypting zeros.
        Maintains state across calls (like SHA256_CTR_OTP)."""
        return self._encryptor.update(b"\x00" * length)

    def reset(self):
        """Reset to beginning of stream."""
        from cryptography.hazmat.primitives.ciphers import Cipher
        from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
        algorithm = ChaCha20(self._key, self._nonce)
        self._cipher = Cipher(algorithm, mode=None)
        self._encryptor = self._cipher.encryptor()


def get_otp_generator(seed: bytes, backend: str = "sha256-ctr"):
    """Factory: create an OTP generator by backend name."""
    if backend == "chacha20":
        return ChaCha20_OTP(seed)
    return SHA256_CTR_OTP(seed)
```

- [ ] **Step 2: Update `Party.encrypt()` and `Party.decrypt()` to use factory**

In `Party`, add a `backend` field and use the factory:

```python
@dataclass
class Party:
    name: str
    keypair: KeyPair = field(default_factory=KeyPair.generate)
    master_key: Optional[bytes] = None
    session_key: Optional[bytes] = None
    _session_id: int = 0
    backend: str = "sha256-ctr"
```

Update `get_otp` in the Party class:

```python
    def get_otp(self, slot_timestamp: int, length: int, seed_override: bytes = None) -> bytes:
        assert self.session_key is not None, "Call open_session first"
        seed = seed_override or derive_slot_seed(self.session_key, slot_timestamp)
        gen = get_otp_generator(seed, self.backend)
        return gen.generate(length)
```

- [ ] **Step 3: Test ChaCha20 backend**

Run: `python -c "from core import *; import time; seed=b'x'*32; g=ChaCha20_OTP(seed); t0=time.perf_counter(); d=g.generate(100000); t1=time.perf_counter(); print(f'{0.1/(t1-t0):.0f} MB/s'); from tests import entropy_per_byte; print(f'Entropy: {entropy_per_byte(d):.4f}')"`

Expected: High throughput and entropy >= 7.9 bits/byte.

- [ ] **Step 4: Commit**

```bash
git add core.py
git commit -m "feat: add ChaCha20 OTP backend with HKDF-derived key/nonce"
```

### Task 7: Add ChaCha20 implementation to `babel_oracle.py`

> Note: The wire format (nonce + backend byte) was already introduced in Chunk 2.
> This task only adds the actual ChaCha20 keystream generator and updates the
> `generate_otp()` stub to support it.

**Files:**
- Modify: `babel_oracle.py` → update `generate_otp()`, add `chacha20_generate()`

- [ ] **Step 1: Add `chacha20_generate()` and update `generate_otp()` stub**

Replace the `generate_otp()` stub from Chunk 2 with the full implementation:

```python
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
```

- [ ] **Step 2: Update `cmd_encrypt_message()` to pass backend from config**

After loading config, pass backend to `encrypt_data()`:

```python
    backend = cfg.get("otp_backend", "sha256-ctr")
    packet = encrypt_data(plaintext, session_key, slot_ts, backend=backend)
```

And display the backend used:

```python
    print(f"  OTP backend: {backend}")
```

- [ ] **Step 3: Test ChaCha20 mode end-to-end**

Run: `python babel_oracle.py`
Configure OTP backend to "chacha20" via settings menu.
Encrypt a message, then decrypt it. Verify roundtrip works.
Switch back to "sha256-ctr", decrypt the ChaCha20 message — should still work (backend byte auto-detection).

- [ ] **Step 4: Commit**

```bash
git add babel_oracle.py
git commit -m "feat: add ChaCha20 OTP backend to babel_oracle.py"
```

---

## Chunk 5: Babel B=3 Support

### Task 8: Add B=3 support to `babel.py`

**Files:**
- Modify: `babel.py` → `BabelConfig`, `BabelIndex.build()`

- [ ] **Step 1: Add progress callback to `BabelIndex.build()`**

Update the `build()` method signature and add callback support:

```python
    def build(self, verbose: bool = True, progress_callback=None) -> None:
```

Inside the build loop, after the verbose milestone print, add:

```python
            if progress_callback and (p + 1) % milestone == 0:
                progress_callback(p + 1, search_count)
```

- [ ] **Step 2: Add validation for block_size**

In `BabelConfig.__post_init__()`, add validation:

```python
    def __post_init__(self):
        if self.block_size not in (2, 3):
            raise ValueError(f"block_size must be 2 or 3, got {self.block_size}")
        self.max_param = 1 << (self.block_size * 8)
        self.search_space = self.max_param * 8
```

- [ ] **Step 3: Test B=3 build**

Run: `python -c "from babel import BabelConfig, BabelIndex; import os; cfg = BabelConfig(block_size=3); idx = BabelIndex(cfg, os.urandom(32)); idx.build(verbose=True)"`

Expected: Build completes in ~30s with >= 99% coverage. This is a long test — monitor memory usage (~400MB).

Note: This test is optional during development (slow). The B=2 roundtrip in `demo.py` is the primary correctness check.

- [ ] **Step 4: Commit**

```bash
git add babel.py
git commit -m "feat: add Babel B=3 support with progress callback"
```

### Task 8b: Add ChaCha20 test to `demo.py`

**Files:**
- Modify: `demo.py`

- [ ] **Step 1: Add ChaCha20 roundtrip and NIST test section**

After the Phase 3d (multi-message) section, add:

```python
    # Test ChaCha20 backend
    section("PHASE 3e — ChaCha20 Backend")

    alice_cc = Party(name="Alice-CC", backend="chacha20")
    bob_cc = Party(name="Bob-CC", backend="chacha20")
    alice_cc.establish_key(bob_cc.public_key)
    bob_cc.establish_key(alice_cc.public_key)
    alice_cc.open_session(session_id)
    bob_cc.open_session(session_id)

    assert alice_cc.session_key == bob_cc.session_key
    ok("ChaCha20 session keys match")

    cc_msg = "ChaCha20 encrypted message".encode()
    cc_ct = alice_cc.encrypt(cc_msg, slot_timestamp)
    cc_recovered = bob_cc.decrypt(cc_ct, slot_timestamp)
    assert cc_recovered == cc_msg
    ok(f"ChaCha20 roundtrip: {cc_recovered.decode()}")

    # NIST quality test on ChaCha20 keystream
    from core import ChaCha20_OTP
    cc_seed = derive_slot_seed(alice_cc.session_key, slot_timestamp)
    cc_gen = ChaCha20_OTP(cc_seed)
    cc_data = cc_gen.generate(50_000)
    cc_ent = entropy_per_byte(cc_data)
    kv("ChaCha20 entropy", f"{cc_ent:.4f} bits/byte")
    assert cc_ent >= 7.9, f"ChaCha20 entropy too low: {cc_ent}"
    ok("ChaCha20 NIST entropy test PASS")
```

- [ ] **Step 2: Update demo.py imports**

Add `ChaCha20_OTP` to the import from `core`:

```python
from core import (
    KeyPair, Party, PAD_BUCKETS, ChaCha20_OTP,
    derive_slot_seed, SHA256_CTR_OTP,
    xor_bytes, hkdf_extract, hkdf_expand,
)
```

- [ ] **Step 3: Commit**

```bash
git add demo.py
git commit -m "feat: add ChaCha20 backend roundtrip and NIST test to demo"
```

### Task 9: Update `demo.py` with B=3 option

**Files:**
- Modify: `demo.py`

- [ ] **Step 1: Add a B=3 section (skippable)**

After the B=2 Babel section in demo.py, add:

```python
    # Optional B=3 demo
    section("PHASE 4b — Babel Index B=3 (optional, ~30s build)")
    try_b3 = os.environ.get("BABEL_B3", "0") == "1"
    if try_b3:
        babel_config_3 = BabelConfig(block_size=3)
        babel_idx_3 = BabelIndex(babel_config_3, alice.master_key)
        t0 = time.perf_counter()
        babel_idx_3.build(verbose=True)
        t_build_3 = time.perf_counter() - t0
        kv("B=3 build time", f"{t_build_3:.1f}s")
        kv("B=3 coverage", f"{babel_idx_3.stats['coverage']*100:.2f}%")
        ok("B=3 index built successfully")
    else:
        print("  Skipped (set BABEL_B3=1 to run)")
```

- [ ] **Step 2: Commit**

```bash
git add demo.py
git commit -m "feat: add optional B=3 Babel demo (BABEL_B3=1 to enable)"
```

---

## Chunk 6: Update CLAUDE.md

### Task 10: Update CLAUDE.md with all enhancements

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update the Implemented Enhancements table**

In the "Known Limitations and TODOs" section, move the MEDIUM/LOW items to the "Implemented Enhancements" table:

```markdown
### Implemented Enhancements

| Priority | Item | Status | Description |
|----------|------|--------|-------------|
| HIGH | **Replay protection** | DONE | Tracks seen (peer, slot_ts, nonce) tuples. Supports both nonce-based (new) and slot-only (legacy) formats. Persisted to `~/.babel-oracle/replay_log.json` with 24-hour auto-pruning. |
| HIGH | **Key file encryption** | DONE | PBKDF2HMAC (SHA-256, 600K iterations) + AES-256-GCM. |
| HIGH | **Message padding** | DONE | `pad_plaintext()` pads to bucket sizes `[256, 512, 1024, 2048, 4096]` with `os.urandom` fill. |
| MEDIUM | **Per-message nonce** | DONE | 16-byte random nonce per message prevents OTP reuse in same time slot. Mixed into slot_seed via HMAC. Backward compatible with dual-path decryption. |
| MEDIUM | **Session expiry** | DONE | Configurable TTL via `~/.babel-oracle/config.json`. Sub-day sessions use epoch-based session_id. Auto-rotation on expiry. |
| LOW | **ChaCha20 backend** | DONE | `ChaCha20_OTP` class using `cryptography.hazmat`. 100x faster than SHA-256 CTR. Auto-detected via backend byte in packet. Configurable via settings menu. |
| LOW | **Babel B=3** | DONE | `BabelConfig(block_size=3)` with 16M targets. ~30s build time. Progress callback supported. |
```

- [ ] **Step 2: Update the Encrypted Packet data format**

Replace the packet format in Section 10 with:

```markdown
### Encrypted Packet (binary) — Current Format

```
[0:8]     slot_timestamp    uint64 big-endian
[8:24]    message_nonce     16 bytes (os.urandom)
[24]      backend_id        1 byte (0x00 = sha256-ctr, 0x01 = chacha20)
[25:25+F] ciphertext        F bytes (XOR'd frame)
```

Where F = 7 (magic) + 4 (length) + P (padded payload) + 32 (HMAC).

**Legacy format** (backward compatible, auto-detected):
```
[0:8]     slot_timestamp    uint64 big-endian
[8:8+F]   ciphertext        F bytes (XOR'd frame, no nonce, no backend byte)
```
```

- [ ] **Step 3: Update the Cryptographic Constants table**

Add the new constants:

```markdown
| `ChaCha20 key info` | `b"chacha20-key"` | core.py, babel_oracle.py | HKDF info for ChaCha20 key derivation |
| `ChaCha20 nonce info` | `b"chacha20-nonce"` | core.py, babel_oracle.py | HKDF info for ChaCha20 nonce derivation |
| `SESSION_TTL` | 86400 (default) | babel_oracle.py | Configurable session lifetime in seconds |
| `CONFIG_PATH` | `~/.babel-oracle/config.json` | babel_oracle.py | User configuration file |
| `SESSIONS_PATH` | `~/.babel-oracle/sessions.json` | babel_oracle.py | Session creation timestamps |
| Backend byte SHA-256 | `0x00` | babel_oracle.py | Backend indicator in packet |
| Backend byte ChaCha20 | `0x01` | babel_oracle.py | Backend indicator in packet |
```

- [ ] **Step 4: Update the Remaining TODOs table**

```markdown
### Remaining TODOs

| Priority | Item | Description |
|----------|------|-------------|
| LOW | **Babel B=4** | Requires rainbow chain compression (~500MB). Deferred to separate design. |
| LOW | **Lorenz-SHA backend** | Chaotic system OTP source. Requires fixed-point 128-bit arithmetic. |
```

- [ ] **Step 5: Update the Security Properties table**

Add a row for per-message nonce:

```markdown
| **Multi-message safety** | STRONG | Per-message 16-byte random nonce | Each message in the same time slot uses a unique OTP stream. Nonce mixed via HMAC-SHA256(slot_seed, nonce). |
```

- [ ] **Step 6: Update the Quick Reference table**

Add new entries:

```markdown
| Change OTP backend | `babel_oracle.py` → Configure settings menu, or `config.json` → `"otp_backend"` |
| Change session TTL | `babel_oracle.py` → Configure settings menu, or `config.json` → `"session_ttl"` |
| Use Babel B=3 | `demo.py` → set `BABEL_B3=1` env var, or `BabelConfig(block_size=3)` |
```

- [ ] **Step 7: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md with all implemented enhancements"
```

---

## Final Verification

### Task 11: End-to-end verification

- [ ] **Step 1: Run the full demo**

Run: `python demo.py`
Expected: All phases pass, no assertion errors.

- [ ] **Step 2: Run the CLI app manually**

Run: `python babel_oracle.py`
Test the full flow:
1. Generate identity (with passphrase)
2. Import peer key
3. Encrypt a message → verify clean output and clipboard copy
4. Decrypt the message → verify success
5. Configure settings (change TTL, change backend)
6. Encrypt/decrypt with ChaCha20 backend

- [ ] **Step 3: Run statistical tests**

Run: `python babel_oracle.py` → option 6 (Statistical quality tests)
Expected: All NIST tests PASS.
