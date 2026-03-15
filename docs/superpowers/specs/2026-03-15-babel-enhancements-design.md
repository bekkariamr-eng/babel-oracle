# Babel Oracle — Enhancement Design Spec

**Date**: 2026-03-15
**Author**: Claude (on behalf of Amr Bekkari)
**Status**: Reviewed & Approved

---

## Overview

Five enhancements to the Babel Oracle Protocol:

1. **Fix ciphertext output format** — clean single-line output with reliable auto-copy
2. **Per-message nonce** — prevent OTP reuse when multiple messages sent in same time slot
3. **Session expiry with TTL** — configurable sub-day session lifetime
4. **ChaCha20 OTP backend** — hardware-accelerated alternative to SHA-256 CTR
5. **Babel B=3/B=4 support** — larger block sizes for the Babel Index

---

## 1. Fix Ciphertext Output Format

### Problem
The current ciphertext output uses box-drawing characters that interfere with copy-paste. Users must manually strip formatting.

### Design
- Remove box drawing around ciphertext
- Print base64 as a single unbroken line with no indentation or prefix
- Add clear separator lines before/after for visual clarity
- Improve clipboard auto-copy platform detection:
  - Windows (`os.name == "nt"`): use `clip`
  - macOS (`sys.platform == "darwin"`): use `pbcopy`
  - Linux (fallback): use `xclip -selection clipboard`
- Print clipboard success/failure prominently

### Changes
- **`babel_oracle.py`** → `cmd_encrypt_message()`: Replace ciphertext display section with:
  ```
  ─── CIPHERTEXT (auto-copied to clipboard) ───
  <base64 string on single line, no indentation>
  ────────────────────────────────────────────────
  ```

---

## 2. Per-Message Nonce

### Problem
Two messages sent in the same 60-second time slot use the same `slot_seed`, producing identical OTP streams. XOR of two ciphertexts leaks the XOR of the two plaintexts — a critical vulnerability.

### Design
- Generate a random 16-byte nonce per message
- Mix nonce into slot_seed: `effective_seed = HMAC-SHA256(slot_seed, nonce)`
- Prepend the nonce to the packet after the timestamp:
  ```
  [0:8]   slot_timestamp   (existing)
  [8:24]  message_nonce    (NEW — 16 bytes, os.urandom)
  [24:]   ciphertext       (existing)
  ```
- On decryption, extract the nonce and derive the same effective_seed

### Backward Compatibility — Dual-Path Decryption
Try the new format (with nonce) first. If both MAGIC check AND HMAC verification pass, accept. Otherwise fall back to old format (no nonce).

**False positive analysis**: The probability of old-format ciphertext accidentally producing valid MAGIC (7 bytes) through the nonce path is 1/2^56 — negligible. Additionally, the HMAC must also verify, making false positives effectively impossible.

```python
def decrypt_data(packet, session_key, ...):
    slot_ts = struct.unpack(">Q", packet[0:8])[0]
    slot_seed = derive_slot_seed(session_key, slot_ts)

    # Try new format (with nonce) — requires BOTH magic AND HMAC
    if len(packet) > 24:
        nonce = packet[8:24]
        ciphertext = packet[24:]
        effective_seed = hmac.new(slot_seed, nonce, hashlib.sha256).digest()
        otp = sha256_ctr_generate(effective_seed, len(ciphertext))
        frame = xor_bytes(ciphertext, otp)
        result = unframe_message(frame, session_key)  # checks MAGIC + HMAC
        if result is not None:
            return result  # New format verified

    # Fallback: old format (no nonce)
    ciphertext = packet[8:]
    otp = sha256_ctr_generate(slot_seed, len(ciphertext))
    frame = xor_bytes(ciphertext, otp)
    return unframe_message(frame, session_key)  # checks MAGIC + HMAC
```

### Replay Protection Update
With per-message nonces, multiple messages can share the same slot_timestamp. The replay key must change from `(peer, slot_timestamp)` to `(peer, slot_timestamp, nonce_hex)`. The nonce is 16 random bytes, so collision probability is negligible (2^-128).

```python
# New replay key format
replay_key = f"{slot_ts}:{nonce.hex()}"
replay_log[peer_name].append(replay_key)

# Old format compat: slot_ts as int stays in the list for old messages
```

### Changes
- **`babel_oracle.py`**: Modify `encrypt_data()` to generate and prepend nonce. Modify `decrypt_data()` with dual-path + full verification. Update replay log format.
- **`core.py`**: Modify `Party.encrypt()` to accept/generate nonce. Modify `Party.decrypt()` with dual-path.

---

## 3. Session Expiry with TTL

### Problem
Sessions derived from `session_id = YYYYMMDD` rotate daily, but there is no mechanism for sub-day rotation or configurable TTL. If a user wants hourly re-keying, they cannot configure it.

### Design
- Add `SESSION_TTL` constant (default: 86400 seconds = 24 hours)
- Support sub-day session IDs by deriving `session_id` from `timestamp // ttl` instead of `YYYYMMDD`
- When TTL < 86400: `session_id = int(time.time()) // ttl` (epoch-based, not date-based)
- When TTL >= 86400: keep `session_id = YYYYMMDD` format for compatibility
- On encrypt: check if current session is within TTL, refuse if expired
- On decrypt: allow decryption with warning (don't lose messages from slightly expired sessions)
- Configurable via `~/.babel-oracle/config.json`

### Data Format — `config.json`
```json
{
  "session_ttl": 86400,
  "otp_backend": "sha256-ctr"
}
```

### Session ID derivation
```python
def get_session_id(ttl: int = 86400) -> int:
    if ttl >= 86400:
        return int(time.strftime("%Y%m%d"))
    return int(time.time()) // ttl
```

**Important**: Both parties MUST use the same TTL. This is a manual coordination requirement, same as agreeing on the protocol version. Mismatched TTL = different session_id = decryption failure (detectable via MAGIC/HMAC).

### Changes
- **`babel_oracle.py`**: Add `load_config()`, `get_session_id(ttl)`. Modify `cmd_encrypt_message()` and `cmd_decrypt_message()`.
- **`core.py`**: No changes (TTL is policy, not crypto).

---

## 4. ChaCha20 OTP Backend

### Problem
SHA-256 CTR in Python gives ~14 MB/s. ChaCha20 via OpenSSL backend gives 1+ GB/s.

### Design
- Add `ChaCha20_OTP` class with the same interface as `SHA256_CTR_OTP`
- Use `cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20`
- Key derivation from seed using HKDF (already in codebase):
  ```python
  key = hkdf_expand(seed, b"chacha20-key", 32)     # 32-byte key
  nonce = hkdf_expand(seed, b"chacha20-nonce", 16)  # 16-byte nonce (4-byte counter + 12-byte nonce per RFC 8439)
  ```
  Using HKDF with distinct info strings is standard and avoids ad-hoc derivation.
- Generate keystream by encrypting zeros: `keystream = ChaCha20.encrypt(key, nonce, b"\x00" * length)`
- Add `OTP_BACKEND` config in `~/.babel-oracle/config.json`: `"sha256-ctr"` (default) or `"chacha20"`

### Wire Format — Backend Indicator
Add a 1-byte backend indicator to the packet, after the nonce:
```
[0:8]   slot_timestamp
[8:24]  message_nonce
[24]    backend_id      (NEW — 0x00 = sha256-ctr, 0x01 = chacha20)
[25:]   ciphertext
```

This allows the receiver to auto-detect which backend was used, eliminating the "both parties must manually match config" problem.

**Backward compatibility**: Old packets (no nonce, no backend byte) are handled by the dual-path detection in Section 2. New packets always include both nonce and backend byte.

### Interface
```python
class ChaCha20_OTP:
    def __init__(self, seed: bytes):
        key = hkdf_expand(seed, b"chacha20-key", 32)
        nonce = hkdf_expand(seed, b"chacha20-nonce", 16)
        self.cipher = ChaCha20(key, nonce)
        self.offset = 0

    def generate(self, length: int) -> bytes:
        return encrypt_zeros(self.cipher, length)

    def reset(self):
        self.offset = 0
```

### Changes
- **`core.py`**: Add `ChaCha20_OTP` class. Add `get_otp_generator(seed, backend)` factory.
- **`babel_oracle.py`**: Add inline `ChaCha20_OTP`. Add config option. Add backend byte to packet format.

---

## 5. Babel B=3/B=4 Support

### Problem
Current Babel Index only supports B=2 (65,536 possible block values). Larger block sizes reduce the number of parameters needed per message.

### Design

**B=3 (16,777,216 targets)**:
- search_space = 8 × 16,777,216 = 134,217,728 (8× oversampling)
- Build time: ~30 seconds
- Memory: ~400MB for the index
- Direct table lookup (same algorithm as B=2, just larger)
- Add progress callback for build feedback

**B=4 — Deferred**:
B=4 requires 4,294,967,296 targets and cannot use a direct table (would need ~100GB). A rainbow chain compression approach is needed, which is a significant separate design effort. Defer to a dedicated spec document.

### Implementation
- Make `BabelConfig` accept `block_size` of 2 or 3
- Scale `search_space` proportionally: `search_space = oversampling * (256 ** block_size)`
- Add `progress_callback` parameter to `BabelIndex.__init__()` for build progress
- Validate block_size in [2, 3] at construction

### Changes
- **`babel.py`**: Accept B=3 in `BabelConfig`. Scale search_space. Add progress callback.
- **`demo.py`**: Add B=3 demo option (behind a flag, since build takes ~30s).

---

## Compatibility & Migration

| Enhancement | Backward Compatible? | Notes |
|---|---|---|
| Output format | N/A (display only) | No protocol change |
| Per-message nonce | Yes (dual-path decrypt) | Old packets: no nonce → MAGIC/HMAC verified via old path |
| Session expiry | Conditional | Both parties must use same TTL (same as protocol version) |
| ChaCha20 | Yes (backend byte) | Backend auto-detected from packet; old packets use SHA-256 CTR |
| Babel B=3 | Yes | New block size, existing B=2 unchanged |

---

## Implementation Order

1. **Ciphertext output fix** — standalone, no dependencies
2. **Per-message nonce** — highest security priority (eliminates OTP reuse vulnerability), modifies seed derivation path
3. **Session expiry** — after nonce (replay protection needs nonce-aware format)
4. **ChaCha20 backend** — builds on finalized seed derivation from step 2
5. **Babel B=3** — independent, can go anywhere

This order ensures each step builds on a stable foundation from the previous one.

---

## Testing

All existing tests from CLAUDE.md section 11 must still pass, plus:

**Per-message nonce:**
- Two messages in same slot produce different ciphertext
- Both decrypt correctly
- Old-format packets (no nonce) still decrypt via fallback path
- Replay protection rejects duplicate `(slot_ts, nonce)` pairs
- Replay protection allows same slot_ts with different nonce

**Session expiry:**
- Expired session blocks encryption with clear error
- Expired session allows decryption with warning
- Sub-day TTL produces correct session_id
- Mismatched TTL between parties = decryption failure (detected, not silent)

**ChaCha20:**
- Roundtrip encrypt/decrypt with ChaCha20 backend
- Cross-backend: SHA-256 encrypt → detect backend byte → SHA-256 decrypt (not ChaCha20)
- NIST frequency test: p >= 0.01 on 50KB sample
- NIST entropy: >= 7.9 bits/byte

**Babel B=3:**
- Roundtrip encode/decode
- Coverage >= 99% of 16M target space
- Progress callback fires during build
