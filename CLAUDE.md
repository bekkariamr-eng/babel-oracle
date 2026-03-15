# Babel Oracle Protocol — Complete System Documentation

> This document is designed for an AI assistant (Claude) to fully understand the codebase,
> architecture, design decisions, cryptographic rationale, and extension points.
> Read this BEFORE modifying any file.

---

## 1. Project Identity

| Field | Value |
|-------|-------|
| **Name** | Babel Oracle Protocol |
| **Author** | Amr Bekkari |
| **Affiliation** | ENSA Tanger, Cybersecurity Engineering (GCYS2) |
| **Purpose** | Research PoC for a covert communication channel using deterministic oracles |
| **Status** | Functional prototype — offline SHA-256 CTR mode operational |
| **License** | Academic research — not for production deployment |

---

## 2. One-Paragraph Summary

Two parties (Alice and Bob) exchange ECDH public keys once via any channel. From that shared secret, both independently derive identical OTP keystreams using SHA-256 in counter mode — zero network traffic required. Messages are XOR'd with the OTP (Vernam cipher / One-Time Pad), producing ciphertext indistinguishable from random noise. An optional Babel Index compresses the ciphertext by mapping byte blocks to deterministic function parameters, enabling polymorphic encoding (same message → different parameters each time). The only thing transmitted between parties is the ciphertext blob — pure noise that can travel via any steganographic micro-channel.

---

## 3. File Map

```
babel-oracle/
├── babel_oracle.py    # Standalone interactive CLI app (single-file, all-in-one)
├── core.py            # Crypto primitives: ECDH, HKDF, SHA-256 CTR, XOR, Party
├── babel.py           # Babel Index: reverse lookup table, polymorphic codec
├── tests.py           # NIST SP 800-22 statistical quality tests
├── demo.py            # Full E2E demo script (non-interactive, prints results)
├── build_windows.bat  # PyInstaller build script for Windows .exe
├── run.bat            # Quick-run script (requires Python)
├── requirements.txt   # Python dependencies
└── README.md          # User-facing documentation
```

### File Dependency Graph

```
babel_oracle.py  ← standalone, imports nothing from the project (self-contained)

demo.py
  ├── core.py     (Party, KeyPair, SHA256_CTR_OTP, xor_bytes, derive_*)
  ├── babel.py    (BabelConfig, BabelIndex, BabelCodec)
  └── tests.py    (run_all_tests, entropy_per_byte)

tests.py
  └── core.py     (SHA256_CTR_OTP)

babel.py
  └── (no internal imports — uses only stdlib: hashlib, struct, time, random)

core.py
  └── cryptography.hazmat  (X25519PrivateKey, X25519PublicKey, serialization)
```

**Critical**: `babel_oracle.py` is a COMPLETE COPY of all logic — it duplicates `core.py` functions inline so it can be packaged as a single-file executable. If you modify crypto logic, you MUST update BOTH `core.py` AND the corresponding section in `babel_oracle.py`.

---

## 4. Protocol Phases — Detailed

### Phase 0: Key Exchange (one-time setup)

```
Alice                          Bob
  |                              |
  | generate X25519 keypair      | generate X25519 keypair
  | (x_A, Y_A = x_A * G)        | (x_B, Y_B = x_B * G)
  |                              |
  |--- Y_A --> [any channel] --> |  (public key is not secret)
  |<-- Y_B -- [any channel] --- |
  |                              |
  | K = x_A * Y_B               | K = x_B * Y_A
  | (identical via ECDH)         | (identical via ECDH)
```

**Implementation**: `core.py` → `KeyPair.generate()`, `KeyPair.derive_shared_secret()`

**Key storage** (in `babel_oracle.py`):
- Identity: `~/.babel-oracle/{name}.identity.json` — contains base64(private + public)
- Peer: `~/.babel-oracle/{name}.peer.json` — contains base64(public only)

**Security note**: X25519 (Curve25519) is used instead of P-256 because:
- Constant-time implementation (no timing side channels)
- 128-bit security level
- Simpler API (no point validation needed)
- Used by Signal, WireGuard, TLS 1.3

### Phase 1: Key Derivation Hierarchy

```
shared_secret (32 bytes, from ECDH)
    │
    ├── HKDF-Extract(salt="babel-oracle-v1-salt", ikm=shared_secret)
    │       → PRK (32 bytes)
    │
    ├── HKDF-Expand(PRK, info="babel-oracle-master-key", len=32)
    │       → master_key (32 bytes, permanent)
    │
    ├── HKDF-Extract(master_key, info="babel-session-" || session_id_be64)
    │   HKDF-Expand → session_key (32 bytes, changes per session)
    │
    └── HMAC-SHA256(session_key, timestamp_be64)
            → slot_seed (32 bytes, changes per time slot)
```

**Implementation**: `core.py` → `derive_master_key()`, `derive_session_key()`, `derive_slot_seed()`

**Session ID convention**: Currently uses `int(YYYYMMDD)` as session_id (e.g., 20260315). This means a new session key is derived daily. Can be changed to hourly, weekly, or any granularity.

**Time slot**: Currently 60-second slots (`timestamp // 60 * 60`). The slot timestamp is prepended to the ciphertext (8 bytes, big-endian) so the receiver knows which slot to use for decryption.

**Perfect Forward Secrecy**: Compromising `slot_seed_T` reveals nothing about `slot_seed_{T-1}` because HMAC-SHA256 is a PRF — you cannot reverse it to get the session_key.

### Phase 2: OTP Generation (SHA-256 Counter Mode)

```
slot_seed (32 bytes)
    │
    ├── SHA-256(slot_seed || 0x0000000000000000) → block_0 (32 bytes)
    ├── SHA-256(slot_seed || 0x0000000000000001) → block_1 (32 bytes)
    ├── SHA-256(slot_seed || 0x0000000000000002) → block_2 (32 bytes)
    │   ...
    └── SHA-256(slot_seed || counter_N)          → block_N (32 bytes)
    
    OTP = block_0 || block_1 || ... || block_N (truncated to message length)
```

**Implementation**: `core.py` → `SHA256_CTR_OTP` class

**Why SHA-256 CTR and not ChaCha20 directly?**
- SHA-256 is available in Python's `hashlib` without external dependencies
- For the PoC, this simplifies packaging (no need for `cryptography` lib for the OTP part)
- Security is equivalent: SHA-256 in CTR mode is a standard CSPRNG construction
- In production, ChaCha20 would be faster (SIMD-accelerated)

**Counter format**: 8-byte big-endian unsigned integer, appended to the seed. This gives 2^64 blocks × 32 bytes = 590 exabytes before counter wraps — effectively infinite.

**Determinism guarantee**: Both parties use the same `slot_seed` (derived from the same `session_key` and `timestamp`), so they produce bit-identical OTP streams. This is the core property that eliminates the need for communication.

### Phase 3: Encryption

```
plaintext (N bytes)
    │
    ├── pad_plaintext(plaintext)
    │       → plaintext || os.urandom(P - N)   where P = smallest bucket ≥ N
    │       Buckets: [256, 512, 1024, 2048, 4096], or next 4096 multiple
    │
    ├── frame_message(padded, session_key)
    │       → MAGIC(7) || LENGTH(4) || padded(P) || HMAC-SHA256(32)
    │       LENGTH stores N (original size), NOT P (padded size)
    │       = framed (P + 43 bytes)
    │
    ├── OTP = SHA256_CTR(slot_seed, len=P+43)
    │
    └── ciphertext = framed XOR OTP

    packet = slot_timestamp(8) || ciphertext(P+43)
```

**Implementation**: `core.py` → `Party.encrypt(pad=True)`, `encrypt_data(pad=True)` (in babel_oracle.py)

**Message padding**: Plaintext is padded to fixed bucket sizes before framing. This prevents length-based traffic analysis — the adversary sees only the bucket size. Padding uses `os.urandom` (random bytes, not zeros). The LENGTH field stores the original unpadded size, so `unframe_message` extracts only the original bytes. Padding can be disabled with `pad=False` for backward compatibility.

**MAGIC bytes**: `b"BABEL01"` (7 bytes) — used for format detection during decryption. If magic doesn't match after XOR, the decryption key is wrong.

**HMAC coverage**: The MAC is computed over `MAGIC || LENGTH || padded_plaintext`, NOT over the ciphertext. This is encrypt-then-MAC at the frame level — the MAC is encrypted along with the plaintext, providing both integrity and authentication.

**Important**: The slot timestamp (8 bytes) is prepended IN CLEARTEXT to the packet. This is intentional — it tells the receiver which time slot to use. It does NOT leak information about the message because:
1. The timestamp is the current time slot (public information)
2. It reveals nothing about message content (ciphertext size reveals only the padding bucket, not exact length)

### Phase 4: Decryption

```
packet
    │
    ├── Extract slot_timestamp = packet[0:8]
    │
    ├── REPLAY CHECK: is (peer, slot_timestamp) already seen?
    │       → YES: return None (replay rejected)
    │
    ├── ciphertext = packet[8:]
    │
    ├── slot_seed = derive_slot_seed(session_key, slot_timestamp)
    ├── OTP = SHA256_CTR(slot_seed, len=len(ciphertext))
    │
    ├── framed = ciphertext XOR OTP
    │
    ├── Verify: framed[0:7] == MAGIC?
    ├── Extract length = framed[7:11]       (original unpadded length)
    ├── Extract plaintext = framed[11:11+length]  (strips padding automatically)
    ├── Extract mac_received = framed[-32:]
    │
    ├── mac_computed = HMAC-SHA256(session_key, MAGIC || LENGTH || padded_plaintext)
    └── VERIFY: mac_received == mac_computed? (constant-time comparison)
            → YES: record (peer, slot_timestamp) as seen; return plaintext
            → NO:  return None (tampered or wrong key)
```

**Implementation**: `core.py` → `Party.decrypt(seen_slots=set())`, `decrypt_data(peer_name, replay_log)` (in babel_oracle.py)

**Replay protection**: In `core.py`, `Party.decrypt()` accepts an optional `seen_slots: set` — slot timestamps are checked before decryption and recorded after success. In `babel_oracle.py`, `decrypt_data()` accepts `peer_name` and `replay_log` (dict) — replay state is persisted to `~/.babel-oracle/replay_log.json` with 24-hour auto-pruning via `load_replay_log()` / `save_replay_log()`.

---

## 5. Babel Index — Deep Dive

### Concept

The Babel Index is a pre-computed reverse lookup table. For every possible byte block of size B, it stores one or more "parameter" values that, when passed through a deterministic function, produce that block.

```
Forward:  parameter P → SHA-256(domain || P)[:B] → block value V
Reverse:  block value V → lookup in index → parameter P (or list of P's)
```

### Why It Exists

Without the Babel Index, the protocol already works — Alice encrypts, sends ciphertext, Bob decrypts. The Babel Index adds TWO properties:

1. **Polymorphism**: The same ciphertext block maps to MULTIPLE parameters (~11 on average for B=2). Alice randomly selects one each time. Result: the same message produces completely different parameter sequences on every send. This defeats signature-based detection.

2. **Compression potential** (for API mode): When using astronomical APIs instead of SHA-256 CTR, a single API query returns multiple metrics encoding B bytes. The Babel Index maps which queries to make for each block. For B=4, this means 4:1 compression (4 bytes per query instead of 1).

### Construction

```python
domain = SHA-256("babel-index-domain-" || shared_key)

for param in range(0, search_space):
    value = SHA-256(domain || param_as_be64)[:B]   # first B bytes
    index[value].append(param)                      # store reverse mapping
```

**Domain separator**: The index is bound to the shared key via `domain = SHA-256("babel-index-domain-" || master_key)`. This means:
- Alice and Bob build identical indexes (same master_key → same domain)
- An adversary without master_key builds a DIFFERENT index (useless)

**Coverage**: For B=2 (65,536 targets) with 8× oversampling (524,288 searches), coverage reaches ~99.97%. Gap-filling searches additional parameters for any remaining uncovered blocks.

**Collision count** (polymorphism): With 8× oversampling and B=2, average collisions are ~11 per block. For B=3 (16M targets), collisions would be ~8× with proportional oversampling.

### Encode/Decode Flow

```
ENCODE (Alice):
    ciphertext bytes → split into B-byte blocks → for each block:
        → lookup in index → get list of candidate params → pick random one
    → output: list of parameter integers

DECODE (Bob):
    list of parameter integers → for each param:
        → SHA-256(domain || param)[:B] → recover original block
    → concatenate blocks → original ciphertext bytes
```

**Implementation**: `babel.py` → `BabelCodec.encode()`, `BabelCodec.decode()`

**Serialization**: `encode_to_bytes()` produces: `LENGTH(4 bytes) || param_0(8 bytes) || param_1(8 bytes) || ...`

---

## 6. Security Properties — What Holds and What Doesn't

| Property | Status | Mechanism | Notes |
|----------|--------|-----------|-------|
| **Confidentiality** | STRONG | OTP via SHA-256 CTR XOR | Information-theoretic security (Shannon) IF the OTP is truly one-time. In practice, SHA-256 CTR is computationally secure (not information-theoretic) because the seed is only 32 bytes. Still, breaking it requires inverting SHA-256. |
| **Integrity** | STRONG | HMAC-SHA256 on framed message | Constant-time comparison via `hmac.compare_digest()`. Tampered ciphertext is rejected. |
| **Authentication** | IMPLICIT | Only someone with master_key can produce valid HMAC | No explicit sender authentication — anyone with the shared key can encrypt. For two-party use this is fine. |
| **Forward secrecy** | STRONG | HKDF hierarchy: master → session → slot | Compromising one slot_seed doesn't reveal others. Compromising session_key reveals all slots in that session but not other sessions. Compromising master_key reveals everything — this is the root of trust. |
| **Replay protection** | STRONG | Seen-slot tracking per peer | `core.py`: `Party.decrypt(seen_slots=set())` rejects duplicate slot timestamps. `babel_oracle.py`: `decrypt_data(peer_name, replay_log)` persists seen (peer, slot_ts) tuples to `~/.babel-oracle/replay_log.json` with 24-hour auto-pruning. |
| **Non-attribution** | STRONG (offline) | Zero network traffic for OTP generation | In offline mode, there is no observable network behavior linked to the protocol. The only signal is the ciphertext transmission itself. |
| **Polymorphism** | STRONG (with Babel) | Multiple params per block, random selection | Same message → different Babel params every time. Without Babel Index, the ciphertext itself changes per slot (different OTP), but the XOR structure is fixed. |

### What an Adversary CANNOT Do

- **Read the message**: Requires master_key (ECDH inversion = break Curve25519)
- **Detect the protocol** (offline mode): Zero distinguishing network traffic
- **Forge a message**: Requires session_key for valid HMAC
- **Replay a message**: Seen-slot tracking rejects duplicate packets per peer (persisted to disk with 24h auto-pruning)

### What an Adversary CAN Do

- **Observe ciphertext size**: Mitigated — messages are now padded to fixed bucket sizes (256, 512, 1024, 2048, 4096 bytes) before encryption via `pad_plaintext()`. Messages larger than 4096 bytes pad to the next 4096 multiple. The adversary sees only the bucket size, not the exact message length.
- **Correlate timing**: If Alice always sends at the same time, the pattern is detectable. Mitigation: randomize send times.
- **Compromise the endpoint**: Mitigated — identity files can now be encrypted with a passphrase (PBKDF2 + AES-256-GCM, 600K iterations). Old unencrypted files remain readable for backward compatibility. Users are prompted to set a passphrase on identity creation.

---

## 7. Known Limitations and TODOs

### Implemented Enhancements

| Priority | Item | Status | Description |
|----------|------|--------|-------------|
| HIGH | **Replay protection** | DONE | Tracks seen (peer, slot_ts) tuples. `core.py`: `Party.decrypt(seen_slots=set())`. `babel_oracle.py`: persists to `~/.babel-oracle/replay_log.json` with 24-hour auto-pruning via `load_replay_log()` / `save_replay_log()`. |
| HIGH | **Key file encryption** | DONE | PBKDF2HMAC (SHA-256, 600K iterations) + AES-256-GCM. `encrypt_private_key()` / `decrypt_private_key()` in `babel_oracle.py`. Encrypted identity files use `{"version": 2, "encrypted": true, "private_enc": {salt, nonce, ciphertext}}`. Old plaintext files auto-detected and loaded without passphrase. |
| HIGH | **Message padding** | DONE | `pad_plaintext()` pads to bucket sizes `[256, 512, 1024, 2048, 4096]` with `os.urandom` fill. Messages >4096 pad to next 4096 multiple. `frame_message(pad=True)` enabled by default. LENGTH field stores original size so `unframe_message` strips padding automatically. |

### Remaining TODOs

| Priority | Item | Description |
|----------|------|-------------|
| MEDIUM | **Session expiry** | Sessions currently last forever. Add configurable TTL and re-keying mechanism. |
| MEDIUM | **Multi-message per slot** | Currently one OTP stream per slot. If Alice sends two messages in the same 60-second slot, they use the same OTP base (different offsets due to framing). Consider adding a per-message nonce. |
| LOW | **Babel B=3/B=4** | Current demo uses B=2. B=3 requires ~16M entries (~30s build). B=4 requires rainbow chain compression (~500MB, separate implementation). |
| LOW | **ChaCha20 backend** | Replace SHA-256 CTR with ChaCha20 for 10× speed improvement. Requires `cryptography` lib. |

### Architecture Decisions That Should NOT Change

1. **ECDH for key exchange**: Curve25519 is the correct choice. Do not downgrade to RSA or DH over integers.
2. **HKDF for derivation**: Do not replace with raw SHA-256 chaining. HKDF has formal security proofs.
3. **XOR for encryption**: This is the Vernam cipher. Do not add AES on top — it would not improve security and would add complexity.
4. **HMAC-SHA256 for integrity**: Do not replace with CRC or plain SHA-256. HMAC provides authentication, not just integrity.
5. **Slot timestamp in cleartext**: This is intentional. Encrypting it would require a separate key or nonce, adding complexity without security benefit.

---

## 8. Extension Points

### Adding a New OTP Backend

To add a new keystream generator (e.g., ChaCha20, Lorenz-SHA):

1. Create a class with the same interface as `SHA256_CTR_OTP`:
   ```python
   class NewOTP:
       def __init__(self, seed: bytes): ...
       def generate(self, length: int) -> bytes: ...
       def reset(self): ...
   ```

2. The class MUST be deterministic: same seed → same output, always.

3. Plug it into `Party.get_otp()` in `core.py`:
   ```python
   def get_otp(self, slot_timestamp, length):
       seed = derive_slot_seed(self.session_key, slot_timestamp)
       gen = NewOTP(seed)  # swap here
       return gen.generate(length)
   ```

4. Update `babel_oracle.py` accordingly (it has its own inline copy).

### Adding API Mode (Astronomical Oracle)

To re-enable the API-based oracle from earlier protocol versions:

1. Create an `api_oracle.py` module that queries JPL Horizons, Open-Meteo, etc.
2. The oracle function signature should be:
   ```python
   def query_oracle(params: Tuple[str, float, float, str]) -> bytes:
       """(date, lat, lon, metric) → deterministic bytes"""
   ```
3. Combine with local OTP: `OTP_final = OTP_local XOR H(API_response)`
4. Both parties must query the same APIs with the same params — derive params from slot_seed.

### Adding Steganographic Transmission

The protocol currently produces a base64 blob that must be manually transmitted. To add a steganographic channel:

1. Create a `stego.py` module implementing:
   ```python
   class StegoChannel:
       def send(self, data: bytes) -> None: ...
       def receive(self) -> bytes: ...
   ```

2. Candidate channels:
   - **DNS**: Encode data in subdomain queries (`HMAC(K,slot).example.com`)
   - **Image LSB**: Hide bits in the least significant bits of a JPEG/PNG
   - **Timing**: Encode bits in inter-request delays on normal web browsing
   - **Blockchain**: Micro-transactions to derived addresses

3. The `data` parameter is already pure noise (ciphertext). The stego channel does NOT need to provide confidentiality — only covert transmission.

### Adding Lorenz-SHA Backend

The research paper describes a Lorenz chaotic system as an additional entropy source:

```python
class LorenzSHA:
    def __init__(self, seed: bytes):
        # Parse seed into initial conditions (x0, y0, z0) and params (sigma, rho, beta)
        # Use fixed-point 128-bit arithmetic for cross-platform determinism
        ...
    
    def generate(self, length: int) -> bytes:
        # For each iteration:
        #   1. RK4 step in fixed-point arithmetic
        #   2. Extract raw bytes from (x, y, z)
        #   3. SHA-256(raw || counter) → 32 bytes output
        ...
```

**Critical requirements for Lorenz implementation**:
- MUST use fixed-point integer arithmetic (NOT float64) — floating point diverges across platforms
- MUST hash the output through SHA-256 — raw Lorenz output is NOT uniformly distributed
- MUST include counter in hash input — prevents output repetition on near-recurrence
- Parameters MUST be in chaotic regime: ρ > 24.74 for classical Lorenz

---

## 9. Cryptographic Constants and Magic Values

| Constant | Value | Location | Purpose |
|----------|-------|----------|---------|
| `MAGIC` | `b"BABEL01"` | core.py, babel_oracle.py | Message frame identifier |
| HKDF salt | `b"babel-oracle-v1-salt"` | core.py | Domain separation for master key derivation |
| Master key info | `b"babel-oracle-master-key"` | core.py | HKDF-Expand info string |
| Session key prefix | `b"babel-session-"` | core.py | Prepended to session_id for derivation |
| Session key info | `b"session-key"` | core.py | HKDF-Expand info string |
| Babel domain prefix | `b"babel-index-domain-"` | babel.py | Domain separator for Babel Index |
| Slot duration | 60 seconds | babel_oracle.py | Time quantization for slot_seed |
| Session ID | `YYYYMMDD` as int | babel_oracle.py | Daily session rotation |
| Counter format | 8-byte big-endian uint64 | core.py | SHA-256 CTR counter |
| `PAD_BUCKETS` | `[256, 512, 1024, 2048, 4096]` | core.py, babel_oracle.py | Message padding bucket sizes |
| PBKDF2 iterations | 600,000 | babel_oracle.py | Key file encryption key derivation |
| `REPLAY_MAX_AGE` | 86400 (24 hours) | babel_oracle.py | Replay log auto-pruning threshold |
| Replay log path | `~/.babel-oracle/replay_log.json` | babel_oracle.py | Persistent replay protection state |

**Changing any of these breaks compatibility** between existing encrypted messages and new versions. If you change them, bump the MAGIC version (e.g., `BABEL02`).

---

## 10. Data Formats

### Identity File (`{name}.identity.json`)

**Unencrypted (legacy / no passphrase):**
```json
{
  "name": "alice",
  "private": "<base64-encoded 32-byte X25519 private key>",
  "public": "<base64-encoded 32-byte X25519 public key>"
}
```

**Encrypted (version 2, with passphrase):**
```json
{
  "name": "alice",
  "version": 2,
  "encrypted": true,
  "private_enc": {
    "salt": "<base64-encoded 16-byte PBKDF2 salt>",
    "nonce": "<base64-encoded 12-byte AES-GCM nonce>",
    "ciphertext": "<base64-encoded AES-256-GCM encrypted private key>"
  },
  "public": "<base64-encoded 32-byte X25519 public key>"
}
```

### Peer File (`{name}.peer.json`)
```json
{
  "name": "bob",
  "public": "<base64-encoded 32-byte X25519 public key>"
}
```

### Encrypted Packet (binary)
```
[0:8]     slot_timestamp    uint64 big-endian
[8:15]    encrypted MAGIC   7 bytes (XOR'd with OTP)
[15:19]   encrypted LENGTH  4 bytes (XOR'd with OTP) — stores ORIGINAL unpadded size
[19:19+P] encrypted PAYLOAD P bytes (XOR'd with OTP) — padded to bucket size
[19+P:]   encrypted HMAC    32 bytes (XOR'd with OTP)
```

P = padded size (one of 256, 512, 1024, 2048, 4096, or next 4096 multiple).
LENGTH stores the original message size so `unframe_message` extracts exactly the original bytes.
Total overhead: 8 (timestamp) + 7 (magic) + 4 (length) + padding + 32 (HMAC).

### Babel-Encoded Packet (binary)
```
[0:4]     original_length   uint32 big-endian
[4:12]    param_0            uint64 big-endian
[12:20]   param_1            uint64 big-endian
...
```

Each parameter is 8 bytes. For block size B=2, this gives 8/2 = 4× overhead (each 2-byte block is represented by an 8-byte parameter). The Babel Index is useful NOT for size compression but for:
1. Polymorphism (anti-signature)
2. API mode (maps to real API queries that encode multiple bytes per query)

---

## 11. Testing Checklist

When modifying the code, verify ALL of the following:

```
□ ECDH: alice.master_key == bob.master_key
□ Session: alice.session_key == bob.session_key for same session_id
□ OTP: alice.get_otp(T, N) == bob.get_otp(T, N) for same T and N
□ Encrypt/Decrypt roundtrip: bob.decrypt(alice.encrypt(msg, T), T) == msg
□ Tamper detection: bob.decrypt(tamper(alice.encrypt(msg, T)), T) == None
□ Wrong key: bob2.decrypt(alice.encrypt(msg, T), T) == None (different master_key)
□ Wrong slot: bob.decrypt(alice.encrypt(msg, T), T+60) == None
□ Padding: ciphertext size matches expected bucket (e.g., 56B msg → 256B padded frame)
□ Padding roundtrip: decrypt(encrypt(msg, pad=True)) == msg (original bytes, no padding)
□ Replay: first decrypt succeeds, second decrypt of same packet returns None
□ Key encryption: save_identity(passphrase) → file has "encrypted": true, no plaintext key
□ Key decryption: load_identity with correct passphrase returns valid key
□ Key decryption: load_identity with wrong passphrase raises ValueError
□ Backward compat: load_identity on old unencrypted file works without passphrase
□ Babel roundtrip: codec.decode(codec.encode(data), len(data)) == data
□ Babel polymorphism: codec.encode(data) != codec.encode(data) (usually)
□ Babel domain: BabelIndex(cfg, key_A).domain == BabelIndex(cfg, key_A).domain
□ NIST frequency: p-value >= 0.01 on 50KB+ sample
□ NIST entropy: >= 7.9 bits/byte on 50KB+ sample
```

Run the automated test:
```bash
python3 demo.py   # Full E2E with assertions and NIST tests
```

---

## 12. Performance Characteristics

| Operation | Time | Throughput | Notes |
|-----------|------|------------|-------|
| ECDH key exchange | ~0.5 ms | one-time | Curve25519 |
| HKDF derivation | ~0.01 ms | per-session | SHA-256 based |
| SHA-256 CTR OTP (1 KB) | ~40 µs | ~25 MB/s | Python, no C extensions |
| SHA-256 CTR OTP (100 KB) | ~7 ms | ~14 MB/s | Python, no C extensions |
| XOR encryption | ~10 µs | per-message | Trivial |
| HMAC-SHA256 | ~5 µs | per-message | Integrity tag |
| Babel Index build (B=2) | ~1.7 s | one-time | 524K evaluations |
| Babel encode | ~120 µs | per-message | Index lookup |
| Babel decode | ~40 µs | per-message | Hash evaluation |

**Bottleneck**: SHA-256 in pure Python is slow (~14 MB/s). With `hashlib` C extension (which is already used), this is the speed. To go faster: use ChaCha20 from `cryptography` library (hardware-accelerated, 1+ GB/s) or use `hmac` with `_hashlib` (OpenSSL backend).

---

## 13. Threat Model Reference

The protocol is designed against this adversary:

- **Network**: Full-take capture of all traffic (NSA-level)
- **TLS**: Man-in-the-middle via corporate proxy (can see inside HTTPS)
- **DNS**: Full access to all DNS resolution logs
- **Endpoint**: EDR installed on both machines (can see process activity)
- **Computational**: Cannot break Curve25519 ECDLP or SHA-256 preimage

The protocol does NOT protect against:

- **Endpoint compromise**: If adversary has root/admin on Alice's machine, they can read key files and memory
- **Rubber-hose cryptanalysis**: Physical coercion to reveal keys
- **Quantum computing**: Curve25519 is vulnerable to Shor's algorithm (future threat — migrate to ML-KEM/Kyber when needed)
- **Side channels**: Timing attacks on the Python implementation are not mitigated (use constant-time libraries for production)

---

## 14. Academic Context

This code accompanies a research paper:

> **"Covert Channels via Hybrid Deterministic Oracles: Lorenz-SHA Generator,
> Babel Index Architecture, and Behavioral Detection Framework"**
> Amr Bekkari, ENSA Tanger, 2026.

The paper describes three protocol versions:
- **V1 (API-only)**: OTP from astronomical APIs — detectable via query pattern analysis
- **V2 (Math-only)**: OTP from SHA-256 CTR / ChaCha20 — zero network, zero detection
- **V3 (Hybrid)**: Combines V1 + V2 + Lorenz chaotic system — defense-in-depth

This codebase implements V2 (offline/math-only mode) as the functional PoC.
The detection framework (Phase 4 in the paper) is NOT implemented here — it would
be a separate Zeek/Suricata/XGBoost pipeline analyzing network captures.

---

## 15. Quick Reference — "How Do I..."

| Task | Where to Look |
|------|---------------|
| Change time slot duration | `babel_oracle.py` → `get_slot_timestamp()`, change `// 60 * 60` |
| Change padding buckets | `core.py` + `babel_oracle.py` → modify `PAD_BUCKETS` list |
| Disable padding | Pass `pad=False` to `frame_message()`, `Party.encrypt()`, or `encrypt_data()` |
| Change replay log TTL | `babel_oracle.py` → modify `REPLAY_MAX_AGE` (default 86400 = 24h) |
| Change PBKDF2 iterations | `babel_oracle.py` → modify `iterations=600_000` in `encrypt_private_key()` / `decrypt_private_key()` |
| Switch to ChaCha20 | `core.py` → replace `SHA256_CTR_OTP` with ChaCha20 from `cryptography.hazmat` |
| Add Lorenz backend | Create `lorenz.py`, implement fixed-point RK4 + SHA-256 whitening |
| Add API oracle mode | Create `api_oracle.py`, combine with local OTP via XOR |
| Change Babel block size | `demo.py` → `BabelConfig(block_size=3)`, increase search_space proportionally |
| Add GUI | Use `tkinter` or `PyQt5`, import functions from `babel_oracle.py` |
| Add network transport | Implement `StegoChannel` interface (see Extension Points above) |
