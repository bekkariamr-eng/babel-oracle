# Babel Oracle Protocol — Proof of Concept

**Covert Channels via Hybrid Deterministic Oracles**
*Amr Bekkari — ENSA Tanger, Cybersecurity Engineering*

## Overview

This PoC demonstrates a covert communication channel where two parties
(Alice and Bob) can exchange encrypted messages with **zero network
infrastructure** and **zero direct communication** after an initial key exchange.

The protocol generates identical One-Time Pads on both sides using
SHA-256 in counter mode, seeded by a shared ECDH secret. The "Babel Index"
compresses transmissions by mapping ciphertext blocks to deterministic
function parameters (inspired by Borges' Library of Babel).

## Architecture

```
Alice                                    Bob
  |                                       |
  |--- ECDH pub key --> [keyserver] <--- ECDH pub key ---|
  |                                       |
  |  K = ECDH(my_priv, peer_pub)         K = ECDH(my_priv, peer_pub)
  |  session_key = HKDF(K, session)      session_key = HKDF(K, session)
  |  slot_seed = HMAC(session_key, T)    slot_seed = HMAC(session_key, T)
  |  OTP = SHA256_CTR(slot_seed)         OTP = SHA256_CTR(slot_seed)
  |                                       |
  |  ciphertext = message XOR OTP         |
  |  params = babel_encode(ciphertext)    |
  |                                       |
  |  --- params via steganography --->    |
  |                                       |
  |           ciphertext = babel_decode(params)
  |           message = ciphertext XOR OTP
```

## Files

| File | Description |
|------|-------------|
| `core.py` | ECDH, HKDF, SHA-256 CTR OTP, XOR encryption, Party abstraction |
| `babel.py` | Babel Index construction, reverse lookup, polymorphic encoding |
| `tests.py` | NIST SP 800-22 statistical tests (frequency, runs, entropy, chi²) |
| `demo.py` | Full E2E demonstration with all 7 phases |

## Quick Start

```bash
pip install cryptography
python3 demo.py
```

## Security Properties

| Property | Mechanism |
|----------|-----------|
| Confidentiality | OTP (Shannon information-theoretic security) |
| Integrity | HMAC-SHA256 on framed messages |
| Key exchange | ECDH Curve25519 via keyserver (no direct contact) |
| Forward secrecy | HKDF hierarchical derivation (master → session → slot) |
| Polymorphism | Babel Index multi-collision (~11 variants per block) |
| Network traffic | **ZERO** in offline mode |

## Research Context

This is a research prototype for a cybersecurity engineering project.
The primary contribution is the **detection framework** (not included
in this PoC) that identifies oracle channel traffic through behavioral
analysis of API query patterns.

## References

- Stallings, W. (2023). *Cryptography and Network Security*, 8th Ed.
- Shannon, C.E. (1949). Communication Theory of Secrecy Systems.
- Borges, J.L. (1941). The Library of Babel.
- RFC 5869: HKDF. RFC 7748: Curve25519.
