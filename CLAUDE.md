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
  └── cryptography.hazmat  (X25519PrivateKey, X25519PublicKey, serialization, ChaCha20, Cipher)
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

### Phase 2: OTP Generation (SHA-256 Counter Mode / ChaCha20)

Two backends are available, selectable per-party via `Party(backend="sha256-ctr")` or `Party(backend="chacha20")`:

**Backend 1: SHA-256 CTR (default)**
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

**Backend 2: ChaCha20 (~100× faster)**
```
slot_seed (32 bytes)
    │
    ├── key   = HKDF-Expand(slot_seed, info="chacha20-key",   len=32)
    ├── nonce = HKDF-Expand(slot_seed, info="chacha20-nonce", len=16)
    │
    └── OTP = ChaCha20(key, nonce).encrypt(zeros(length))
```

**Implementation**: `core.py` → `SHA256_CTR_OTP`, `ChaCha20_OTP`, `get_otp_generator(seed, backend)` factory

**ChaCha20 key/nonce derivation**: Uses HKDF-Expand with distinct info strings (`b"chacha20-key"` and `b"chacha20-nonce"`) to derive separate key and nonce from the seed. This is cryptographically sound — distinct info strings guarantee independent outputs.

**ChaCha20 statefulness**: The `ChaCha20_OTP` class creates the encryptor once in `__init__` and reuses it across `generate()` calls. This maintains correct counter state — creating a new encryptor each call would reset the counter and return identical bytes.

**Counter format** (SHA-256 CTR): 8-byte big-endian unsigned integer, appended to the seed. This gives 2^64 blocks × 32 bytes = 590 exabytes before counter wraps — effectively infinite.

**Determinism guarantee**: Both parties use the same `slot_seed` (derived from the same `session_key` and `timestamp`), so they produce bit-identical OTP streams regardless of backend. This is the core property that eliminates the need for communication.

**Cross-backend compatibility**: The backend byte in the wire format (see Phase 3) allows a receiver to auto-detect which backend was used, so a SHA-256 CTR party can decrypt ChaCha20 ciphertext and vice versa.

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
    ├── nonce = os.urandom(16)    ← per-message random nonce
    ├── effective_seed = HMAC-SHA256(slot_seed, nonce)
    ├── OTP = backend(effective_seed, len=P+43)
    │
    └── ciphertext = framed XOR OTP

    packet = nonce(16) || backend_byte(1) || ciphertext(P+43)
```

**Implementation**: `core.py` → `Party.encrypt(pad=True)`, `encrypt_data(pad=True, backend="sha256-ctr")` (in babel_oracle.py)

**Per-message nonce**: Each encryption generates a fresh 16-byte random nonce. The nonce is mixed with the slot seed via `HMAC-SHA256(slot_seed, nonce)` to derive a unique `effective_seed` per message. This prevents OTP reuse when multiple messages are sent in the same 60-second time slot. The nonce is prepended to the packet in cleartext — it does not need to be secret, only unique.

**Backend byte**: A single byte (0x00 = SHA-256 CTR, 0x01 = ChaCha20) is included in the wire format so the receiver can auto-detect which OTP backend was used. This enables cross-backend compatibility.

**Message padding**: Plaintext is padded to fixed bucket sizes before framing. This prevents length-based traffic analysis — the adversary sees only the bucket size. Padding uses `os.urandom` (random bytes, not zeros). The LENGTH field stores the original unpadded size, so `unframe_message` extracts only the original bytes. Padding can be disabled with `pad=False` for backward compatibility.

**MAGIC bytes**: `b"BABEL01"` (7 bytes) — used for format detection during decryption. If magic doesn't match after XOR, the decryption key is wrong.

**HMAC coverage**: The MAC is computed over `MAGIC || LENGTH || padded_plaintext`, NOT over the ciphertext. This is encrypt-then-MAC at the frame level — the MAC is encrypted along with the plaintext, providing both integrity and authentication.

### Phase 4: Decryption

```
packet (new format: nonce + backend + ciphertext)
    │
    ├── Extract nonce = packet[0:16]
    ├── Extract backend_byte = packet[16]     (0x00=sha256-ctr, 0x01=chacha20)
    ├── ciphertext = packet[17:]
    │
    ├── REPLAY CHECK: is "slot_ts:nonce_hex" already seen?
    │       → YES: return None (replay rejected)
    │
    ├── slot_seed = derive_slot_seed(session_key, slot_timestamp)
    ├── effective_seed = HMAC-SHA256(slot_seed, nonce)
    ├── OTP = backend(effective_seed, len=len(ciphertext))
    │
    ├── framed = ciphertext XOR OTP
    │
    ├── unframe_message(framed, session_key):
    │       Verify MAGIC, extract LENGTH, extract plaintext, verify HMAC
    │
    └── VERIFY: HMAC valid?
            → YES: record "slot_ts:nonce_hex" as seen; return plaintext
            → NO:  try legacy format fallback, then return None
```

**Implementation**: `core.py` → `Party.decrypt(seen_slots=set())`, `decrypt_data(peer_name, replay_log)` (in babel_oracle.py)

**Dual-path decryption**: The decrypt function first tries the new format (nonce + backend byte + ciphertext). If `unframe_message()` returns None (MAGIC or HMAC mismatch), it falls back to legacy format (no nonce, no backend byte, raw SHA-256 CTR). This ensures backward compatibility with messages encrypted before the nonce update.

**Replay protection**: In `core.py`, `Party.decrypt()` accepts an optional `seen_slots: set`. For new-format messages, the replay key is `"slot_ts:nonce_hex"` (a string), allowing multiple messages per slot (each with a unique nonce). For legacy messages, the replay key is `int(slot_ts)`. In `babel_oracle.py`, `decrypt_data()` persists seen entries to `~/.babel-oracle/replay_log.json` with 24-hour auto-pruning via `load_replay_log()` / `save_replay_log()`. The replay log handles both legacy int entries and new string entries.

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
| HIGH | **Replay protection** | DONE | Tracks seen `"slot_ts:nonce_hex"` tuples (new format) or `int(slot_ts)` (legacy). `core.py`: `Party.decrypt(seen_slots=set())`. `babel_oracle.py`: persists to `~/.babel-oracle/replay_log.json` with 24-hour auto-pruning via `load_replay_log()` / `save_replay_log()`. |
| HIGH | **Key file encryption** | DONE | PBKDF2HMAC (SHA-256, 600K iterations) + AES-256-GCM. `encrypt_private_key()` / `decrypt_private_key()` in `babel_oracle.py`. Encrypted identity files use `{"version": 2, "encrypted": true, "private_enc": {salt, nonce, ciphertext}}`. Old plaintext files auto-detected and loaded without passphrase. |
| HIGH | **Message padding** | DONE | `pad_plaintext()` pads to bucket sizes `[256, 512, 1024, 2048, 4096]` with `os.urandom` fill. Messages >4096 pad to next 4096 multiple. `frame_message(pad=True)` enabled by default. LENGTH field stores original size so `unframe_message` strips padding automatically. |
| MEDIUM | **Per-message nonce** | DONE | Each `encrypt()` generates a 16-byte random nonce, mixed with slot seed via `HMAC-SHA256(slot_seed, nonce)` to derive a unique effective seed. Eliminates OTP reuse when multiple messages are sent in the same 60-second slot. Wire format: `nonce(16) \|\| backend_byte(1) \|\| ciphertext`. Backward-compatible: decrypt falls back to legacy (no-nonce) format. |
| MEDIUM | **Session expiry** | DONE | Configurable TTL via `~/.babel-oracle/config.json` (default: 86400s = 24h). `get_session_id(ttl)` derives session ID from `time() // ttl`. `check_session_expiry()` warns when session is about to rotate. Settings menu (option 8) allows changing TTL and OTP backend. `load_sessions()` / `save_sessions()` persist session state. |
| LOW | **ChaCha20 backend** | DONE | `ChaCha20_OTP` class in `core.py` uses `cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20`. Key and nonce derived via HKDF-Expand with distinct info strings (`b"chacha20-key"`, `b"chacha20-nonce"`). ~100× faster than SHA-256 CTR (~450 MB/s vs ~3 MB/s). Stateful encryptor maintained across `generate()` calls. Backend selectable via `Party(backend="chacha20")` or settings menu. Cross-backend decrypt auto-detects from wire format byte. |
| LOW | **Babel B=3 support** | DONE | `BabelConfig` now accepts `block_size=3` (16M targets, ~30s build, ~400MB memory). `BabelIndex.build()` accepts optional `progress_callback` for GUI/CLI progress reporting. |

### Remaining TODOs

| Priority | Item | Description |
|----------|------|-------------|
| LOW | **Babel B=4** | B=4 requires rainbow chain compression (~500MB on disk, separate implementation). |
| LOW | **Lorenz-SHA backend** | Chaotic system OTP generator — requires fixed-point 128-bit arithmetic for cross-platform determinism. See Extension Points. |

### Architecture Decisions That Should NOT Change

1. **ECDH for key exchange**: Curve25519 is the correct choice. Do not downgrade to RSA or DH over integers.
2. **HKDF for derivation**: Do not replace with raw SHA-256 chaining. HKDF has formal security proofs.
3. **XOR for encryption**: This is the Vernam cipher. Do not add AES on top — it would not improve security and would add complexity.
4. **HMAC-SHA256 for integrity**: Do not replace with CRC or plain SHA-256. HMAC provides authentication, not just integrity.
5. **Slot timestamp in cleartext**: This is intentional. Encrypting it would require a separate key or nonce, adding complexity without security benefit.

---

## 8. Extension Points

### Adding a New OTP Backend

Two backends are already implemented: `SHA256_CTR_OTP` (default) and `ChaCha20_OTP`. To add another (e.g., Lorenz-SHA):

1. Create a class with the same interface as `SHA256_CTR_OTP`:
   ```python
   class NewOTP:
       def __init__(self, seed: bytes): ...
       def generate(self, length: int) -> bytes: ...
       def reset(self): ...
   ```

2. The class MUST be deterministic: same seed → same output, always.

3. Register it in `get_otp_generator()` factory in `core.py`:
   ```python
   def get_otp_generator(seed: bytes, backend: str = "sha256-ctr"):
       if backend == "chacha20":
           return ChaCha20_OTP(seed)
       if backend == "new-backend":
           return NewOTP(seed)
       return SHA256_CTR_OTP(seed)
   ```

4. Add a new backend byte value (e.g., `0x02`) in `Party.encrypt()` and `Party.decrypt()`.

5. Update `babel_oracle.py` accordingly (it has its own inline copy).

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
| ChaCha20 key info | `b"chacha20-key"` | core.py | HKDF-Expand info for ChaCha20 key derivation |
| ChaCha20 nonce info | `b"chacha20-nonce"` | core.py | HKDF-Expand info for ChaCha20 nonce derivation |
| Backend byte (SHA-256) | `0x00` | core.py, babel_oracle.py | Wire format backend identifier |
| Backend byte (ChaCha20) | `0x01` | core.py, babel_oracle.py | Wire format backend identifier |
| Babel domain prefix | `b"babel-index-domain-"` | babel.py | Domain separator for Babel Index |
| Slot duration | 60 seconds (configurable) | babel_oracle.py | Time quantization for slot_seed |
| Session TTL | 86400s default (configurable) | babel_oracle.py | Session rotation interval |
| Counter format | 8-byte big-endian uint64 | core.py | SHA-256 CTR counter |
| `PAD_BUCKETS` | `[256, 512, 1024, 2048, 4096]` | core.py, babel_oracle.py | Message padding bucket sizes |
| PBKDF2 iterations | 600,000 | babel_oracle.py | Key file encryption key derivation |
| `REPLAY_MAX_AGE` | 86400 (24 hours) | babel_oracle.py | Replay log auto-pruning threshold |
| Replay log path | `~/.babel-oracle/replay_log.json` | babel_oracle.py | Persistent replay protection state |
| Config path | `~/.babel-oracle/config.json` | babel_oracle.py | User settings (TTL, backend) |
| Sessions path | `~/.babel-oracle/sessions.json` | babel_oracle.py | Active session state |

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

### Encrypted Packet — New Format (binary)
```
[0:16]    nonce             16 bytes random per-message nonce (cleartext)
[16]      backend_byte      1 byte (0x00=SHA-256 CTR, 0x01=ChaCha20)
[17:24]   encrypted MAGIC   7 bytes (XOR'd with OTP)
[24:28]   encrypted LENGTH  4 bytes (XOR'd with OTP) — stores ORIGINAL unpadded size
[28:28+P] encrypted PAYLOAD P bytes (XOR'd with OTP) — padded to bucket size
[28+P:]   encrypted HMAC    32 bytes (XOR'd with OTP)
```

P = padded size (one of 256, 512, 1024, 2048, 4096, or next 4096 multiple).
LENGTH stores the original message size so `unframe_message` extracts exactly the original bytes.
Total overhead: 16 (nonce) + 1 (backend) + 7 (magic) + 4 (length) + padding + 32 (HMAC).

### Encrypted Packet — Legacy Format (backward compat)
```
[0:8]     slot_timestamp    uint64 big-endian
[8:15]    encrypted MAGIC   7 bytes (XOR'd with OTP)
[15:19]   encrypted LENGTH  4 bytes
[19:19+P] encrypted PAYLOAD P bytes
[19+P:]   encrypted HMAC    32 bytes
```

The decrypt function auto-detects format: tries new format first (nonce+backend), falls back to legacy if HMAC verification fails.

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
□ Multi-message same slot: two encrypts in same slot produce different ciphertext (nonce)
□ Multi-message same slot: both messages decrypt correctly
□ ChaCha20 roundtrip: bob.decrypt(alice_chacha.encrypt(msg, T), T) == msg
□ ChaCha20 backend byte: ciphertext[16] == 0x01 for ChaCha20
□ Cross-backend: SHA-256 party decrypts ChaCha20 ciphertext (auto-detect)
□ ChaCha20 tamper: tampered ChaCha20 ciphertext rejected
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
| SHA-256 CTR OTP (1 KB) | ~40 µs | ~25 MB/s | Python hashlib C extension |
| SHA-256 CTR OTP (100 KB) | ~32 ms | ~3 MB/s | Python hashlib C extension |
| ChaCha20 OTP (100 KB) | ~0.2 ms | ~450 MB/s | OpenSSL-accelerated via `cryptography` |
| XOR encryption | ~10 µs | per-message | Trivial |
| HMAC-SHA256 | ~5 µs | per-message | Integrity tag |
| Babel Index build (B=2) | ~6 s | one-time | 524K evaluations + gap-fill |
| Babel Index build (B=3) | ~30 s | one-time | ~134M evaluations |
| Babel encode | ~120 µs | per-message | Index lookup |
| Babel decode | ~40 µs | per-message | Hash evaluation |

**ChaCha20 advantage**: The ChaCha20 backend is ~100× faster than SHA-256 CTR because it uses OpenSSL's SIMD-accelerated implementation via the `cryptography` library. For bulk encryption or large files, ChaCha20 is strongly recommended.

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
| Change session TTL | `babel_oracle.py` → settings menu (option 8), or edit `~/.babel-oracle/config.json` |
| Switch OTP backend | `babel_oracle.py` → settings menu (option 8), or `Party(backend="chacha20")` in `core.py` |
| Change padding buckets | `core.py` + `babel_oracle.py` → modify `PAD_BUCKETS` list |
| Disable padding | Pass `pad=False` to `frame_message()`, `Party.encrypt()`, or `encrypt_data()` |
| Change replay log TTL | `babel_oracle.py` → modify `REPLAY_MAX_AGE` (default 86400 = 24h) |
| Change PBKDF2 iterations | `babel_oracle.py` → modify `iterations=600_000` in `encrypt_private_key()` / `decrypt_private_key()` |
| Add Lorenz backend | Create `lorenz.py`, implement fixed-point RK4 + SHA-256 whitening, register in `get_otp_generator()` |
| Add API oracle mode | Create `api_oracle.py`, combine with local OTP via XOR |
| Change Babel block size | `demo.py` → `BabelConfig(block_size=3)`, increase search_space proportionally |
| Add GUI | Use `tkinter` or `PyQt5`, import functions from `babel_oracle.py` |
| Add network transport | Implement `StegoChannel` interface (see Extension Points above) |
