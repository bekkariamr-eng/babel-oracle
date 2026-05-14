# Babel Oracle Protocol --- Full Technical Explanation

> Author: Amr Bekkari | ENSA Tanger | Cybersecurity Engineering (GCYS2)
>
> This document explains every layer of the Babel Oracle Protocol:
> what it does, how every byte is derived, why each design choice was made,
> and where the system is strong or vulnerable.

---

## Table of Contents

1. [What Problem Does This Solve](#1-what-problem-does-this-solve)
2. [System Architecture Overview](#2-system-architecture-overview)
3. [Phase 0 --- Key Exchange (ECDH Curve25519)](#3-phase-0--key-exchange)
4. [Phase 1 --- Key Derivation Hierarchy (HKDF)](#4-phase-1--key-derivation-hierarchy)
5. [Phase 2 --- OTP Generation (SHA-256 CTR / ChaCha20)](#5-phase-2--otp-generation)
6. [Phase 3 --- Message Framing, Padding, and Encryption](#6-phase-3--message-framing-padding-and-encryption)
7. [Phase 4 --- Decryption and Verification](#7-phase-4--decryption-and-verification)
8. [Phase 5 --- Babel Index (Polymorphic Encoding)](#8-phase-5--babel-index)
9. [Transport Layer](#9-transport-layer)
10. [Steganographic Layer](#10-steganographic-layer)
11. [Key Storage and Protection](#11-key-storage-and-protection)
12. [Replay Protection](#12-replay-protection)
13. [Wire Formats (Byte-Level)](#13-wire-formats)
14. [Cryptographic Primitives Summary](#14-cryptographic-primitives-summary)
15. [Strengths](#15-strengths)
16. [Weaknesses and Limitations](#16-weaknesses-and-limitations)
17. [Comparison with Existing Systems](#17-comparison-with-existing-systems)
18. [Threat Model](#18-threat-model)

---

## 1. What Problem Does This Solve

Most encryption systems (Signal, TLS, PGP) solve **confidentiality**: an adversary can see that communication is happening but cannot read the content.

The Babel Oracle Protocol solves a different problem: **undetectability**. The adversary should not be able to determine that communication is happening at all.

After a one-time key exchange, Alice and Bob never need to contact each other again. Both independently derive identical encryption keys from their shared secret and the current time. Messages are encrypted into pure noise and can be transmitted through any channel --- a USB stick, a shared folder, an image file, copy-paste. There are no servers, no protocols to fingerprint, no network traffic to analyze.

---

## 2. System Architecture Overview

The protocol operates in layered phases. Each phase feeds into the next:

```
PHASE 0: Key Exchange
    Alice and Bob exchange X25519 public keys once (any channel)
    Result: 32-byte shared secret (identical on both sides)
          |
          v
PHASE 1: Key Derivation
    shared_secret --> HKDF --> master_key (permanent)
    master_key    --> HKDF --> session_key (rotates per TTL period)
    session_key   --> HMAC --> slot_seed (rotates every 60 seconds)
    slot_seed     --> HMAC(nonce) --> effective_seed (unique per message)
          |
          v
PHASE 2: OTP Generation
    effective_seed --> SHA-256 CTR or ChaCha20 --> OTP keystream
          |
          v
PHASE 3: Encryption
    plaintext --> pad --> frame (add MAGIC + LENGTH + HMAC) --> XOR with OTP --> ciphertext
          |
          v
PHASE 4 (optional): Babel Index
    ciphertext --> split into 2-byte blocks --> lookup polymorphic parameters
          |
          v
TRANSMISSION
    ciphertext (or Babel params) sent via any channel:
    shared folder, TCP socket, steganographic image, USB, copy-paste
```

---

## 3. Phase 0 --- Key Exchange

### What Happens

Alice and Bob each generate an X25519 (Curve25519) key pair. They exchange public keys through any channel --- in person, via QR code, over email, on paper. The public key is not secret; it reveals nothing about the private key.

### The Math

```
Alice generates:
    private key  x_A  (random 32 bytes, clamped per Curve25519 spec)
    public key   Y_A = x_A * G   (G is the Curve25519 base point)

Bob generates:
    private key  x_B
    public key   Y_B = x_B * G

Alice computes:  shared_secret = x_A * Y_B = x_A * x_B * G
Bob computes:    shared_secret = x_B * Y_A = x_B * x_A * G

These are identical: x_A * x_B * G == x_B * x_A * G
```

The shared secret is 32 bytes. An adversary who knows both public keys cannot compute it without solving the Elliptic Curve Discrete Logarithm Problem (ECDLP), which is computationally infeasible for Curve25519 (128-bit security level).

### Why X25519

| Property | X25519 | ECDH P-256 | RSA-2048 |
|---|---|---|---|
| Security level | 128-bit | 128-bit | 112-bit |
| Key size | 32 bytes | 32 bytes | 256 bytes |
| Constant-time | Yes (by design) | Implementation-dependent | No |
| Point validation needed | No | Yes | N/A |
| Used by | Signal, WireGuard, TLS 1.3 | TLS, various | Legacy |

X25519 was chosen because it is constant-time by construction (no timing side channels), requires no point validation (no invalid-curve attacks), and is the modern standard for key agreement.

### Implementation

```
core.py         -->  KeyPair.generate(), KeyPair.derive_shared_secret()
babel_oracle.py -->  generate_keypair(), compute_shared_secret()
```

---

## 4. Phase 1 --- Key Derivation Hierarchy

A single shared secret must produce many independent keys over time. The protocol uses HKDF (RFC 5869) built from HMAC-SHA256 to create a three-level key hierarchy.

### Level 1: Master Key (permanent)

```
PRK = HMAC-SHA256(salt="babel-oracle-v1-salt", ikm=shared_secret)
master_key = HKDF-Expand(PRK, info="babel-oracle-master-key", length=32)
```

The master key is derived once and never changes. It is the root of all subsequent keys. Compromising it compromises everything.

### Level 2: Session Key (rotates per TTL)

```
session_id = floor(unix_time / TTL)          // e.g., floor(time / 86400) for daily
info = "babel-session-" || session_id_as_uint64_big_endian
PRK = HMAC-SHA256(master_key, info)
session_key = HKDF-Expand(PRK, info="session-key", length=32)
```

The session key changes when the TTL period rolls over (default: every 24 hours). Both parties compute the same `session_id` because they use the same TTL and UTC epoch. The session key is used for HMAC integrity tags on messages.

### Level 3: Slot Seed (rotates every 60 seconds)

```
slot_timestamp = floor(unix_time / 60) * 60
slot_seed = HMAC-SHA256(session_key, slot_timestamp_as_uint64_big_endian)
```

The slot seed changes every 60 seconds. It is the base from which OTP keystreams are derived.

### Level 4: Effective Seed (unique per message)

```
nonce = 16 random bytes (generated fresh per message)
effective_seed = HMAC-SHA256(slot_seed, nonce)
```

Even if two messages are sent in the same 60-second slot, each gets a unique effective seed because each has a unique random nonce. This prevents OTP reuse.

### Forward Secrecy Analysis

```
Compromise effective_seed  -->  reveals ONE message only
Compromise slot_seed       -->  reveals all messages in that 60-second window
Compromise session_key     -->  reveals all messages in that TTL period
Compromise master_key      -->  reveals everything (root of trust)
```

Each level is derived from the one above via HMAC-SHA256, which is a PRF (pseudorandom function). You cannot reverse it: knowing `slot_seed` at time T tells you nothing about `slot_seed` at time T-60, because that would require inverting HMAC-SHA256 to recover `session_key`.

### Implementation

```
core.py         -->  derive_master_key(), derive_session_key(), derive_slot_seed()
babel_oracle.py -->  derive_master_key(), derive_session_key(), derive_slot_seed(),
                     derive_session() (combines all three steps)
```

---

## 5. Phase 2 --- OTP Generation

The effective seed is used to generate a deterministic, pseudo-random byte stream called the One-Time Pad (OTP). Two backends are available.

### Backend 1: SHA-256 Counter Mode (default)

```
OTP = SHA-256(effective_seed || 0x0000000000000000)       // bytes 0-31
   || SHA-256(effective_seed || 0x0000000000000001)       // bytes 32-63
   || SHA-256(effective_seed || 0x0000000000000002)       // bytes 64-95
   || ...
   truncated to the exact length needed
```

Each SHA-256 call produces 32 bytes. The counter is an 8-byte big-endian unsigned integer. This gives 2^64 blocks * 32 bytes = 590 exabytes before the counter wraps.

**Speed**: ~3 MB/s in Python (hashlib uses C extension).

### Backend 2: ChaCha20 (fast)

```
key   = HKDF-Expand(effective_seed, info="chacha20-key",   length=32)
nonce = HKDF-Expand(effective_seed, info="chacha20-nonce", length=16)
OTP   = ChaCha20(key, nonce).encrypt(zeros(length_needed))
```

ChaCha20 is a stream cipher. Encrypting zeros produces the raw keystream. The key and nonce are derived from the effective seed using HKDF-Expand with distinct info strings, guaranteeing independent outputs.

**Speed**: ~450 MB/s in Python (OpenSSL SIMD-accelerated via `cryptography` library). Approximately 100x faster than SHA-256 CTR.

### Determinism Guarantee

Both parties use the same effective seed (derived from the same session key, slot timestamp, and nonce). Therefore, they produce bit-identical OTP streams regardless of which backend is used. This is the core property that eliminates the need for real-time communication.

### Cross-Backend Compatibility

A backend byte in the wire format (0x00 for SHA-256 CTR, 0x01 for ChaCha20) tells the receiver which backend to use for decryption. A party using SHA-256 CTR can decrypt a ChaCha20 message and vice versa.

### Implementation

```
core.py         -->  SHA256_CTR_OTP, ChaCha20_OTP, get_otp_generator()
babel_oracle.py -->  sha256_ctr_generate(), chacha20_generate(), generate_otp()
```

---

## 6. Phase 3 --- Message Framing, Padding, and Encryption

### Step 1: Padding

Before encryption, the plaintext is padded to a fixed bucket size to prevent length-based traffic analysis.

```
Bucket sizes: [256, 512, 1024, 2048, 4096] bytes
Messages > 4096: padded to next multiple of 4096

Example: 50-byte message --> padded to 256 bytes
         300-byte message --> padded to 512 bytes
         5000-byte message --> padded to 8192 bytes

Padding bytes are random (os.urandom), not zeros.
```

An adversary sees only the bucket size, never the exact message length. The original length is stored inside the encrypted frame so the receiver strips the padding.

### Step 2: Framing

The padded plaintext is wrapped in a frame with a magic marker, length field, and HMAC integrity tag:

```
frame = MAGIC(7) || LENGTH(4) || PADDED_PLAINTEXT(P) || HMAC(32)

Where:
    MAGIC  = "BABEL01" (7 bytes) --- format identifier
    LENGTH = original unpadded plaintext length as uint32 big-endian
    PADDED_PLAINTEXT = plaintext + random padding (P bytes total)
    HMAC   = HMAC-SHA256(session_key, MAGIC || LENGTH || PADDED_PLAINTEXT)
```

The HMAC is computed over the entire frame content (magic + length + padded plaintext). It provides:
- **Integrity**: any bit flip in the ciphertext will cause HMAC verification to fail
- **Authentication**: only someone with the session key can produce a valid HMAC

The HMAC uses constant-time comparison (`hmac.compare_digest`) to prevent timing attacks.

### Step 3: XOR Encryption

```
nonce           = os.urandom(16)                              // 16 random bytes
slot_seed       = HMAC-SHA256(session_key, slot_timestamp)
effective_seed  = HMAC-SHA256(slot_seed, nonce)
OTP             = backend(effective_seed, length=len(frame))
ciphertext      = frame XOR OTP
```

The XOR operation is the Vernam cipher. When the OTP is truly random and used only once, this provides information-theoretic security (Shannon's theorem). In practice, the OTP is pseudo-random (derived from SHA-256 or ChaCha20), so the security is computational --- breaking it requires inverting SHA-256 or ChaCha20.

### Step 4: Packet Assembly

The final packet sent over the wire:

```
CLI format (babel_oracle.py):
    packet = TIMESTAMP(8) || NONCE(16) || BACKEND(1) || CIPHERTEXT(N)

Library format (core.py):
    packet = NONCE(16) || BACKEND(1) || CIPHERTEXT(N)
```

The timestamp allows the receiver to know which time slot was used. The nonce allows the receiver to derive the same effective seed. The backend byte tells the receiver which OTP generator to use.

### Implementation

```
core.py         -->  pad_plaintext(), frame_message(), Party.encrypt()
babel_oracle.py -->  pad_plaintext(), frame_message(), encrypt_data()
```

---

## 7. Phase 4 --- Decryption and Verification

Decryption reverses the encryption process:

### Step 1: Parse the packet

```
Extract timestamp (8 bytes) --> determines which slot seed to use
Extract nonce (16 bytes)     --> determines the effective seed
Extract backend byte (1 byte) --> determines SHA-256 CTR or ChaCha20
Remaining bytes              --> ciphertext
```

### Step 2: Replay check

```
replay_key = "{slot_timestamp}:{nonce_hex}"
If replay_key is in the seen set --> reject (replay attack detected)
```

### Step 3: Regenerate the OTP

```
slot_seed      = HMAC-SHA256(session_key, timestamp)
effective_seed = HMAC-SHA256(slot_seed, nonce)
OTP            = backend(effective_seed, length=len(ciphertext))
```

Because both parties share the same session key, the receiver generates the exact same OTP that the sender used.

### Step 4: XOR to recover the frame

```
frame = ciphertext XOR OTP
```

### Step 5: Verify integrity

```
Check frame[0:7] == "BABEL01"             // magic bytes
Extract length = frame[7:11]              // original plaintext size
Extract padded_plaintext = frame[11:-32]
Extract mac_received = frame[-32:]

mac_computed = HMAC-SHA256(session_key, frame[:-32])

If mac_received != mac_computed --> reject (tampering detected)
If magic != "BABEL01"           --> reject (wrong key or corrupted)
```

### Step 6: Strip padding

```
plaintext = padded_plaintext[0:length]
```

### Step 7: Record replay key

```
Add replay_key to seen set (persisted to disk with 24-hour auto-pruning)
```

### Backward Compatibility

If the new format (nonce + backend byte) fails HMAC verification, the decryptor falls back to the legacy format (no nonce, direct slot seed as OTP seed). This ensures old messages encrypted before the nonce update can still be decrypted.

### Implementation

```
core.py         -->  unframe_message(), Party.decrypt()
babel_oracle.py -->  unframe_message(), decrypt_data()
```

---

## 8. Phase 5 --- Babel Index

The Babel Index is an optional layer that adds **polymorphism** to the ciphertext. Without it, the protocol already works. With it, the same message produces completely different output every time it is encoded.

### Concept

The Babel Index is a pre-computed reverse lookup table. For every possible 2-byte (or 3-byte) block value, it stores one or more integer parameters that, when hashed, produce that block:

```
Forward direction (fast):
    parameter P --> SHA-256(domain || P)[0:B] --> block value V

Reverse direction (pre-computed):
    block value V --> lookup in index --> [P1, P2, P3, ...] (multiple matches)
```

### Construction

```
domain = SHA-256("babel-index-domain-" || master_key)    // binds to shared key

For param = 0 to search_space:
    value = SHA-256(domain || param_as_uint64)[0:B]
    index[value].append(param)
```

For B=2 (65,536 possible targets) with 8x oversampling (524,288 searches):
- Coverage reaches 99.97%
- Average of ~10 collisions per block (polymorphism)
- Gap-filling searches additional parameters for any remaining uncovered blocks
- Build time: ~4 seconds

Both parties build identical indexes because they use the same master key, producing the same domain separator.

### Encoding (Sender)

```
ciphertext bytes --> split into B-byte blocks
For each block:
    candidates = index[block_value]     // multiple parameters produce this block
    selected = secrets.choice(candidates)  // cryptographically random selection
Output: list of parameter integers
```

Because each block has ~10 candidate parameters and the selection is random, the same ciphertext produces a completely different parameter sequence on every encode. This is the polymorphism property --- it defeats signature-based detection.

### Decoding (Receiver)

```
For each parameter:
    block = SHA-256(domain || parameter)[0:B]
Concatenate all blocks --> original ciphertext
```

Decoding is deterministic --- each parameter maps to exactly one block value.

### Serialization

```
encoded_bytes = LENGTH(4) || PARAM_0(8) || PARAM_1(8) || PARAM_2(8) || ...

Each parameter is 8 bytes (uint64 big-endian).
For B=2: each 2-byte block becomes 8 bytes --> 4x size expansion.
```

The Babel Index is NOT for compression in the current mode. Its value is:
1. **Polymorphism**: same message, different encoding every time
2. **API mode** (future): parameters map to real API queries, encoding multiple bytes per query

### Implementation

```
babel.py -->  BabelConfig, BabelIndex, BabelCodec
```

---

## 9. Transport Layer

The protocol is transport-agnostic. Ciphertext is pure noise that can travel over any channel. Two automated transports are implemented.

### Shared Folder Transport

Uses a directory (Dropbox, OneDrive, USB, network share) as a dead drop:

```
send(): writes a random-hex-named .bin file containing the packet
poll(): scans for new .bin files, reads them, optionally deletes after reading
```

To an observer, the folder contains cache-like temporary files with random names and random contents --- normal cloud sync behavior.

### TCP Socket Transport

Direct peer-to-peer TCP connection:

```
Wire format: 4-byte big-endian length prefix + payload
```

To a network observer, the traffic is random bytes over TCP --- no protocol fingerprint, no TLS handshake, no HTTP headers. Indistinguishable from VPN or obfuscated tunnel traffic.

### Packet Multiplexing

Both transports use a type-tagged packet format with XOR obfuscation:

```
raw = type_byte || payload
mask = SHA-256("babel-pkt-mask-" || length_as_uint32)
packet = raw XOR mask
```

Packet types: 0x01 = key announce, 0x02 = message, 0x04 = file.

The XOR mask prevents trivial type fingerprinting but is NOT a security mechanism --- it is deterministic from the packet length and reversible by anyone who knows the protocol. Security comes from the OTP encryption layer, not from transport obfuscation.

### Automatic Key Exchange

The `Node` class wraps `Party` + `Transport` to provide automatic key exchange:

1. Node starts, announces its public key via the transport
2. When a peer's key announce arrives, performs ECDH automatically
3. Opens a session (time-based session ID)
4. All subsequent messages are encrypted/decrypted transparently

**Warning**: Key announces are unauthenticated. An active man-in-the-middle on the transport can replace public keys. The initial key exchange must occur over a trusted channel, or keys must be verified out-of-band (e.g., comparing fingerprints).

### Implementation

```
transport.py -->  SharedFolderTransport, SocketTransport, Node
```

---

## 10. Steganographic Layer

An optional layer that hides encrypted packets inside images.

### LSB Steganography with Key-Seeded Scatter

Instead of embedding data sequentially in pixels (easy to detect), the system uses a pseudo-random pixel order derived from the session key:

```
stego_key = HMAC-SHA256(session_key, "babel-stego-scatter")

Pixel order: Fisher-Yates shuffle of [0, 1, ..., W*H-1]
    using HMAC-SHA256(stego_key, index) as the PRNG for each swap

Data is embedded 1 or 2 bits per color channel (R, G, B) in shuffled order.
```

Both parties generate the same scatter pattern from the same session key, so the receiver extracts bits from the same pixel positions.

### Payload Format (Inside Image)

```
MAGIC("BSTG", 4 bytes) || LENGTH(4 bytes) || DATA(N bytes) || HMAC_TAG(4 bytes)

The HMAC_TAG is HMAC-SHA256(stego_key, data) truncated to 4 bytes.
```

### Cover Image Generator

Synthetic cover images (gradient, noise, plasma textures) are generated when no user-provided cover images are available. These look like typical wallpapers or background images, avoiding the suspicion that completely random-pixel images would raise.

### Capacity

For a 640x480 image with 2 bits per channel, 50% pixel usage:
~57,600 bytes of payload capacity per image.

### Implementation

```
babel_stego.py -->  QRKeyExchange, LSBSteganography, StegoTransport, CoverImageGenerator
```

---

## 11. Key Storage and Protection

### Identity Files

Private keys can be stored encrypted or unencrypted:

**Unencrypted** (legacy):
```json
{
    "name": "alice",
    "private": "<base64 of 32-byte X25519 private key>",
    "public": "<base64 of 32-byte X25519 public key>"
}
```

**Encrypted** (version 2):
```json
{
    "name": "alice",
    "version": 2,
    "encrypted": true,
    "private_enc": {
        "salt": "<base64 of 16-byte random salt>",
        "nonce": "<base64 of 12-byte random nonce>",
        "ciphertext": "<base64 of AES-256-GCM encrypted private key>"
    },
    "public": "<base64 of 32-byte public key>"
}
```

### Encryption Scheme

```
salt       = os.urandom(16)
derived_key = PBKDF2-HMAC-SHA256(passphrase, salt, iterations=600,000, length=32)
nonce      = os.urandom(12)
ciphertext = AES-256-GCM(derived_key, nonce, private_key_bytes)
```

PBKDF2 with 600,000 iterations provides strong resistance to brute-force passphrase attacks. AES-256-GCM provides authenticated encryption --- any modification to the ciphertext is detected.

### Storage Location

All files are stored in `~/.babel-oracle/`:
```
~/.babel-oracle/
    alice.identity.json      // private + public key
    bob.peer.json            // peer's public key only
    config.json              // settings (TTL, backend)
    sessions.json            // active session state
    replay_log.json          // seen message tracking
    msg_*.babel              // encrypted message files
```

---

## 12. Replay Protection

### Mechanism

Each successfully decrypted message is recorded by its unique identifier:

```
New format:  "{slot_timestamp}:{nonce_hex}"   // e.g., "1778718240:a7f3...b2c1"
Legacy format:  slot_timestamp (integer)       // e.g., 1778718240
```

If the same identifier is seen again, decryption is rejected.

### Persistence

In `core.py`, the seen set is in-memory (`set`). In `babel_oracle.py`, the replay log is persisted to `~/.babel-oracle/replay_log.json` and auto-pruned every 24 hours (entries older than `REPLAY_MAX_AGE = 86400` seconds are removed).

### Limitations

- In-memory replay protection (core.py) is lost on process restart
- The replay log file is plaintext JSON, which leaks message timing metadata
- A 24-hour pruning window means messages older than 24 hours can be replayed (but they would also need to be in the correct session, which rotates with TTL)

---

## 13. Wire Formats

### CLI Packet (babel_oracle.py)

```
Offset  Size  Field            Description
------  ----  -----            -----------
0       8     timestamp        uint64 BE, slot timestamp (cleartext)
8       16    nonce            random per-message nonce (cleartext)
24      1     backend_byte     0x00 = SHA-256 CTR, 0x01 = ChaCha20
25      7     enc_magic        "BABEL01" XOR'd with OTP
32      4     enc_length       original plaintext length XOR'd with OTP
36      P     enc_payload      padded plaintext XOR'd with OTP
36+P    32    enc_hmac         HMAC-SHA256 tag XOR'd with OTP

P = padded size (256, 512, 1024, 2048, 4096, or next 4096 multiple)
Total = 8 + 16 + 1 + 7 + 4 + P + 32 = P + 68 bytes
```

### Library Packet (core.py)

```
Offset  Size  Field            Description
------  ----  -----            -----------
0       16    nonce            random per-message nonce
16      1     backend_byte     0x00 or 0x01
17      7     enc_magic        "BABEL01" XOR'd with OTP
24      4     enc_length       original plaintext length XOR'd with OTP
28      P     enc_payload      padded plaintext XOR'd with OTP
28+P    32    enc_hmac         HMAC-SHA256 tag XOR'd with OTP

Total = 16 + 1 + 7 + 4 + P + 32 = P + 60 bytes
```

The two formats differ: the CLI format includes an 8-byte timestamp prefix. They are not interchangeable.

### Babel-Encoded Packet

```
Offset  Size  Field            Description
------  ----  -----            -----------
0       4     original_length  uint32 BE, original data length
4       8     param_0          uint64 BE, first Babel parameter
12      8     param_1          uint64 BE, second Babel parameter
...
```

---

## 14. Cryptographic Primitives Summary

| Primitive | Standard | Purpose | Security Level |
|---|---|---|---|
| X25519 | RFC 7748 | Key agreement (ECDH) | 128-bit |
| HKDF | RFC 5869 | Key derivation hierarchy | 256-bit (SHA-256) |
| HMAC-SHA256 | RFC 2104 | Integrity, key derivation, PRF | 256-bit |
| SHA-256 | FIPS 180-4 | OTP generation (CTR mode) | 128-bit (collision), 256-bit (preimage) |
| ChaCha20 | RFC 8439 | OTP generation (stream cipher) | 256-bit |
| AES-256-GCM | NIST SP 800-38D | Key file encryption | 256-bit |
| PBKDF2 | RFC 2898 | Passphrase key derivation | Configurable (600K iterations) |
| XOR | Vernam cipher | Encryption | Information-theoretic (if OTP is truly random) |

Every primitive is individually well-studied and widely deployed. The novel contribution is their composition into a zero-traffic covert channel.

---

## 15. Strengths

### S1. Zero Network Footprint

After the initial key exchange, the protocol generates no network traffic. Both parties derive identical keystreams independently from their shared secret and the current time. There are no servers to contact, no DNS queries to make, no TLS handshakes to perform. A network observer sees nothing.

### S2. Ciphertext Is Indistinguishable from Random Noise

The OTP output passes NIST SP 800-22 statistical tests (frequency, runs, block frequency, serial correlation, byte distribution, Shannon entropy >= 7.99 bits/byte). The ciphertext has no headers, no magic bytes, no structure. It is computationally indistinguishable from random data.

### S3. Strong Forward Secrecy

The four-level key hierarchy (master -> session -> slot -> effective) means compromising one level does not automatically compromise the others below it:
- Compromising an effective seed reveals one message
- Compromising a slot seed reveals at most ~60 seconds of messages
- Compromising a session key reveals one TTL period
- Only the master key is a full compromise

Each level is derived via HMAC-SHA256, which is a one-way function --- you cannot go backwards.

### S4. Per-Message Nonce Prevents OTP Reuse

Every encryption generates a fresh 16-byte random nonce. Even if 100 messages are sent in the same 60-second time slot, each gets a unique effective seed and therefore a unique OTP. The classic two-time-pad attack is impossible.

### S5. Integrity and Authentication (HMAC-SHA256)

Every message includes an HMAC-SHA256 tag computed over the framed plaintext. Any modification to the ciphertext --- even a single bit flip --- causes HMAC verification to fail. The HMAC also provides implicit authentication: only someone with the session key can produce a valid tag.

### S6. Message Padding Defeats Length Analysis

Messages are padded to fixed bucket sizes (256, 512, 1024, 2048, 4096 bytes) with random bytes. An adversary cannot determine whether a 256-byte packet contains a 1-byte message or a 200-byte message. Padding uses `os.urandom` (not zeros), so it is indistinguishable from the plaintext.

### S7. Replay Protection

The protocol tracks seen messages by their `(slot_timestamp, nonce)` pair. Duplicate packets are silently rejected. The replay log is persisted to disk and auto-pruned.

### S8. Key File Encryption

Private keys can be encrypted at rest with PBKDF2 (600,000 iterations) + AES-256-GCM. Even if the key file is stolen, the adversary must brute-force the passphrase.

### S9. Babel Index Polymorphism

With the Babel Index enabled, the same message produces a completely different parameter sequence every time it is encoded (~10 candidate parameters per block, selected via CSPRNG). This defeats any attempt to detect repeated message patterns.

### S10. Dual OTP Backend with Auto-Detection

SHA-256 CTR (universal, ~3 MB/s) and ChaCha20 (~450 MB/s, SIMD-accelerated) are interchangeable. The backend byte in the wire format allows the receiver to auto-detect. Parties using different backends can communicate seamlessly.

### S11. Well-Chosen Primitives

X25519, HKDF, HMAC-SHA256, ChaCha20, AES-256-GCM are all modern, audited, widely deployed standards. No custom cryptography is invented --- only the composition is novel.

---

## 16. Weaknesses and Limitations

### W1. Clock Synchronization Required

Both parties must agree on the current time within ~30 seconds (half of the 60-second slot window). The transport layer tries neighboring slots (current, +60s, -60s) as a tolerance mechanism, but the CLI does not.

**Impact**: If Alice and Bob's clocks drift (especially on air-gapped systems without NTP), decryption will silently fail.

**Mitigation**: The timestamp is embedded in the CLI packet, so the receiver knows which slot was used. But the transport layer relies on local clock.

### W2. Initial Key Exchange Bootstrap Problem

The public keys must be exchanged through some channel. The keys themselves are not secret, but an adversary who observes the exchange learns that Alice and Bob know each other. This is a metadata leak.

**Impact**: The protocol hides the existence of messages, not the existence of the relationship. If the adversary observed the key exchange, they know to look for covert communication between these parties.

### W3. Unaudited Composition

Each individual primitive (X25519, HKDF, HMAC, SHA-256) has formal security proofs. However, the composition --- the specific way they are chained together --- has not been formally analyzed or independently audited. Novel protocol compositions can introduce subtle vulnerabilities that are not present in the individual components.

### W4. No Sender Authentication

The HMAC proves that the message came from someone with the session key. In a two-party protocol, this means it came from the other party. But the protocol cannot distinguish between Alice and Bob as senders --- anyone with the shared key can produce valid messages. This is acceptable for two-party use but would be a problem in a group setting.

### W5. Master Key Is a Single Point of Failure

Compromising the master key compromises all past, present, and future communications. The master key is permanent and never rotates. In contrast, protocols like Signal use a ratchet mechanism that provides post-compromise security --- even if the current key is compromised, future keys will eventually become secure again.

**The Babel Oracle has no ratchet.** If the master key is compromised, the entire channel is permanently compromised.

### W6. No Post-Quantum Resistance

X25519 (Curve25519) is vulnerable to Shor's algorithm on a sufficiently powerful quantum computer. A quantum adversary could recover the private key from the public key and decrypt all past and future communications.

**Mitigation**: Migrate to ML-KEM (Kyber) when quantum computers become a realistic threat. The key derivation and encryption layers (HKDF, SHA-256, ChaCha20) are believed to be quantum-resistant (Grover's algorithm halves their security level, which is still sufficient at 256-bit).

### W7. Python Implementation --- Side Channels

The Python implementation is not constant-time in several operations:
- XOR encryption uses a generator expression (timing varies with length)
- The Babel Index lookup uses standard dictionary operations
- Python's garbage collector may leave key material in memory

**Impact**: A local adversary with precise timing measurements could potentially extract information. This is a concern only in the endpoint-compromise threat model.

### W8. Replay Log Leaks Metadata

The replay log (`replay_log.json`) stores message timestamps and nonces in plaintext. An adversary with filesystem access can determine:
- When messages were received
- How many messages were received per peer
- Activity patterns over time

This partially undermines the undetectability goal.

### W9. Low Bandwidth for Steganographic Channel

In steganographic mode (hiding data in images), the effective bandwidth is very low:
- 640x480 image at 2 bits/channel, 50% pixel usage: ~57 KB capacity
- In practice, after encryption overhead: ~56 KB per image
- Sending images too frequently would be suspicious

**Impact**: The protocol is a signaling channel, not a bulk data channel. It is suitable for short messages, coordinates, instructions --- not for files, video, or voice.

### W10. MAC-then-Encrypt Construction

The HMAC is computed on the plaintext, then the HMAC and plaintext are encrypted together (MAC-then-encrypt). The standard recommendation is encrypt-then-MAC, where the MAC covers the ciphertext. For XOR-based encryption, this distinction is less critical than for block cipher modes (no error propagation, no padding oracle attacks possible). But it deviates from best practice.

### W11. Transport Key Exchange Is Unauthenticated

The automatic transport layer (`Node` in `transport.py`) accepts any public key announcement without verification. An active man-in-the-middle can replace public keys during the automatic exchange, performing a classic MITM attack.

**Mitigation**: Use the QR code exchange or manual key import for the initial setup. Verify key fingerprints out-of-band.

### W12. Session ID / Slot Timestamp in Cleartext

The timestamp portion of the CLI packet is unencrypted. An adversary who intercepts the packet can determine when it was created (to the nearest 60 seconds). This is by design --- encrypting it would require a separate key or nonce --- but it is a minor metadata leak.

---

## 17. Comparison with Existing Systems

| Criterion | Signal | Tor | Babel Oracle |
|---|---|---|---|
| **Goal** | Confidentiality | Anonymity | Undetectability |
| **Content encrypted** | Yes | Yes | Yes |
| **Metadata hidden** | No (server sees who talks) | Partial (exit node sees destination) | Yes (no traffic exists) |
| **Existence hidden** | No (Signal traffic is visible) | No (Tor traffic is detectable) | Yes (no network signature) |
| **Requires servers** | Yes (Signal servers) | Yes (relays) | No |
| **Requires internet** | Yes | Yes | No (works offline) |
| **Blockable by state** | Yes (IP blocking) | Partially (bridges) | No (nothing to block) |
| **Post-compromise recovery** | Yes (Double Ratchet) | N/A | No (master key = everything) |
| **Bandwidth** | High (100+ Mbps) | Low (~2 Mbps) | Very low (~1 Kbps stego) |
| **Security audit** | Extensive, peer-reviewed | Extensive, peer-reviewed | None (research prototype) |
| **Usability** | Excellent (app) | Medium (browser) | Prototype (CLI) |

**The Babel Oracle does not replace Signal.** It solves a problem Signal does not address: hiding the existence of communication itself. Signal protects content; Babel Oracle protects the fact that content exists.

---

## 18. Threat Model

### What the adversary CAN do

| Capability | Description |
|---|---|
| Full network capture | Records all traffic (ISP, corporate proxy, state-level) |
| TLS interception | Man-in-the-middle via corporate CA (can see inside HTTPS) |
| DNS logging | Full access to all DNS resolution logs |
| Endpoint monitoring | EDR/antivirus installed, can see process names and file activity |
| Filesystem access | Can read files in `~/.babel-oracle/` if not encrypted |

### What the adversary CANNOT do

| Limitation | Why |
|---|---|
| Break Curve25519 ECDLP | 128-bit security, no known polynomial-time algorithm |
| Invert SHA-256 | 256-bit preimage resistance |
| Forge HMAC-SHA256 | Requires the session key |
| Distinguish OTP from random | Passes NIST SP 800-22 statistical tests |
| Detect the protocol via network | Zero network traffic in offline mode |
| Brute-force key file passphrase | PBKDF2 with 600K iterations |

### What the adversary CAN detect

| Signal | How |
|---|---|
| Key exchange happened | If they observed the initial public key exchange |
| Ciphertext size (bucket) | Padding limits but does not eliminate this |
| Timing patterns | If Alice always sends at the same time, the pattern is visible |
| Protocol binary on disk | The Python script itself is not hidden |
| Stego images in shared folder | Statistical analysis of images (chi-squared test on LSBs) |

### Not protected against

| Threat | Reason |
|---|---|
| Endpoint root compromise | Adversary reads keys and plaintext from process memory |
| Physical coercion | Passphrase can be extracted under duress |
| Quantum computing (future) | Curve25519 is vulnerable to Shor's algorithm |
| Timing side channels | Python implementation is not constant-time |
| Compromised master key | No ratchet mechanism --- everything is lost |

---

*Babel Oracle Protocol v2 --- Offline Mode (SHA-256 CTR / ChaCha20)*
*Research prototype --- not for production deployment*
