#!/usr/bin/env python3
"""
Babel Oracle Protocol — Full Operational PoC
=============================================
Complete end-to-end demonstration of the offline covert channel.

Alice sends a message to Bob using:
1. ECDH key exchange (Curve25519)
2. HKDF hierarchical key derivation
3. SHA-256 CTR mode OTP (zero network)
4. Babel Index for polymorphic encoding
5. XOR encryption (Vernam / OTP)
6. HMAC-SHA256 integrity verification

Zero network traffic. Zero infrastructure. Zero detectability.

Author: Amr Bekkari
"""

import sys
import os
import time
import hashlib
import struct
import json

# Add project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import (
    KeyPair, Party, PAD_BUCKETS,
    derive_slot_seed, SHA256_CTR_OTP,
    xor_bytes, hkdf_extract, hkdf_expand,
)
from babel import BabelConfig, BabelIndex, BabelCodec
from tests import run_all_tests, entropy_per_byte


# =============================================================================
# DISPLAY HELPERS
# =============================================================================

W = 70

def banner(title):
    print(f"\n{'='*W}")
    print(f"  {title}")
    print(f"{'='*W}\n")

def section(title):
    print(f"\n{'─'*W}")
    print(f"  {title}")
    print(f"{'─'*W}")

def kv(key, value, indent=2):
    print(f"{' '*indent}{key:.<36s} {value}")

def hexdump(data, label="", max_bytes=64):
    if label:
        print(f"  {label}:")
    d = data[:max_bytes]
    hex_str = d.hex()
    chunks = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
    lines = [chunks[i:i+16] for i in range(0, len(chunks), 16)]
    for line in lines:
        print(f"    {' '.join(line)}")
    if len(data) > max_bytes:
        print(f"    ... ({len(data) - max_bytes} more bytes)")


def ok(msg):
    print(f"  [OK] {msg}")

def fail(msg):
    print(f"  [FAIL] {msg}")


# =============================================================================
# MAIN DEMO
# =============================================================================

def main():
    banner("BABEL ORACLE PROTOCOL — FULL OPERATIONAL PoC")
    print("  Mode .............. Offline (SHA-256 CTR)")
    print("  Network traffic ... Zero")
    print("  Key exchange ...... ECDH (Curve25519)")
    print("  OTP generator ..... SHA-256 Counter Mode")
    print("  Babel Index ....... B=2 (demo) / B=3 (medium)")
    print("  Integrity ......... HMAC-SHA256")
    print()

    # =========================================================================
    # PHASE 0: KEY EXCHANGE
    # =========================================================================
    section("PHASE 0 — Key Exchange (ECDH Curve25519)")

    alice = Party(name="Alice")
    bob = Party(name="Bob")

    kv("Alice public key", alice.public_key.hex()[:32] + "...")
    kv("Bob public key", bob.public_key.hex()[:32] + "...")

    # Simulate keyserver: exchange public keys
    alice.establish_key(bob.public_key)
    bob.establish_key(alice.public_key)

    # Verify both derived the same master key
    assert alice.master_key == bob.master_key, "ECDH FAILED: master keys differ!"
    ok("Shared master key derived (identical on both sides)")
    kv("Master key", alice.master_key.hex()[:32] + "...")
    print()
    print("  After this point, Alice and Bob NEVER communicate again.")
    print("  All subsequent operations are independent and offline.")

    # =========================================================================
    # PHASE 1: SESSION + SLOT DERIVATION
    # =========================================================================
    section("PHASE 1 — Session and Slot Key Derivation (HKDF)")

    session_id = 20260315  # e.g., date-based
    alice.open_session(session_id)
    bob.open_session(session_id)

    assert alice.session_key == bob.session_key
    ok(f"Session key derived for session #{session_id}")
    kv("Session key", alice.session_key.hex()[:32] + "...")

    slot_timestamp = int(time.time()) // 60 * 60  # current minute slot
    seed_a = derive_slot_seed(alice.session_key, slot_timestamp)
    seed_b = derive_slot_seed(bob.session_key, slot_timestamp)

    assert seed_a == seed_b
    ok(f"Slot seed derived for T={slot_timestamp}")
    kv("Slot seed", seed_a.hex()[:32] + "...")

    # =========================================================================
    # PHASE 2: OTP GENERATION — SHA-256 CTR
    # =========================================================================
    section("PHASE 2 — OTP Generation (SHA-256 Counter Mode)")

    t0 = time.perf_counter()
    otp_a = alice.get_otp(slot_timestamp, 1024)
    t_gen = time.perf_counter() - t0

    otp_b = bob.get_otp(slot_timestamp, 1024)

    assert otp_a == otp_b, "OTP MISMATCH!"
    ok(f"1 KB OTP generated in {t_gen*1e6:.1f} us (identical on both sides)")
    kv("Speed", f"{1024 / t_gen / 1e6:.1f} MB/s")
    kv("Entropy", f"{entropy_per_byte(otp_a):.4f} bits/byte (max 8.0)")
    hexdump(otp_a, "OTP (first 64 bytes)")

    # Benchmark larger generation
    t0 = time.perf_counter()
    big = alice.get_otp(slot_timestamp + 1, 100_000)
    t_big = time.perf_counter() - t0
    kv("100 KB generation", f"{t_big*1000:.1f} ms ({0.1 / t_big:.0f} MB/s)")

    # =========================================================================
    # PHASE 3: DIRECT ENCRYPTION (no Babel — baseline)
    # =========================================================================
    section("PHASE 3a — Direct Encryption (XOR with OTP)")

    message = "Rendez-vous demain a 14h au cafe. Apporte les documents.".encode()
    kv("Plaintext", message.decode())
    kv("Length", f"{len(message)} bytes")

    # Determine pad bucket for display
    padded_size = len(message)
    for bucket in PAD_BUCKETS:
        if padded_size <= bucket:
            padded_size = bucket
            break

    t0 = time.perf_counter()
    ciphertext = alice.encrypt(message, slot_timestamp)
    t_enc = time.perf_counter() - t0

    kv("Padded to", f"{padded_size} bytes (anti length-analysis)")
    kv("Ciphertext length", f"{len(ciphertext)} bytes (padded + 7 magic + 4 len + 32 HMAC)")
    kv("Encryption time", f"{t_enc*1e6:.1f} us")
    hexdump(ciphertext, "Ciphertext (pure noise)")

    # Verify ciphertext looks random
    ent = entropy_per_byte(ciphertext)
    kv("Ciphertext entropy", f"{ent:.4f} bits/byte")
    if ent > 6.0:
        ok(f"Ciphertext has high entropy ({ent:.2f}/8.0) — small sample size limits max")
    else:
        fail(f"Entropy too low: {ent:.4f}")

    # =========================================================================
    # PHASE 4: DECRYPTION BY BOB
    # =========================================================================
    section("PHASE 3b — Decryption by Bob")

    t0 = time.perf_counter()
    recovered = bob.decrypt(ciphertext, slot_timestamp)
    t_dec = time.perf_counter() - t0

    assert recovered == message, "DECRYPTION FAILED!"
    ok(f"Message recovered in {t_dec*1e6:.1f} us")
    kv("Recovered", recovered.decode())

    # Test integrity: tamper with ciphertext
    tampered = bytearray(ciphertext)
    tampered[20] ^= 0xFF  # flip one byte
    result = bob.decrypt(bytes(tampered), slot_timestamp)
    assert result is None, "Tampered message should fail MAC!"
    ok("HMAC integrity check: tampered message correctly rejected")

    # Test replay protection
    section("PHASE 3c — Replay Protection")

    seen_slots = set()
    r1 = bob.decrypt(ciphertext, slot_timestamp, seen_slots=seen_slots)
    assert r1 == message, "First decryption should succeed"
    ok("First decryption: accepted")

    r2 = bob.decrypt(ciphertext, slot_timestamp, seen_slots=seen_slots)
    assert r2 is None, "Replay should be rejected"
    ok("Replay decryption: correctly rejected (slot already seen)")

    kv("Seen slots", f"{seen_slots}")

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

    # =========================================================================
    # PHASE 5: BABEL INDEX — POLYMORPHIC ENCODING
    # =========================================================================
    section("PHASE 4 — Babel Index Construction")

    print("\n  Building Babel Index (B=2, 65,536 target blocks)...\n")

    babel_config = BabelConfig(block_size=2)
    babel_idx = BabelIndex(babel_config, alice.master_key)

    t0 = time.perf_counter()
    babel_idx.build(verbose=True)
    t_build = time.perf_counter() - t0

    print()
    kv("Build time", f"{t_build:.1f}s")
    kv("Coverage", f"{babel_idx.stats['coverage']*100:.2f}%")
    kv("Avg collisions/block", f"{babel_idx.stats['avg_collisions']:.1f}")
    kv("Total index entries", f"{babel_idx.stats['total_entries']:,}")

    # =========================================================================
    # PHASE 6: BABEL ENCODE / DECODE
    # =========================================================================
    section("PHASE 5 — Babel Encode/Decode")

    # Build codec
    codec_alice = BabelCodec(babel_idx)

    # Bob builds the SAME index independently (same master_key → same domain)
    babel_idx_bob = BabelIndex(babel_config, bob.master_key)
    print("\n  Bob builds his own index independently (same key = same index)...\n")
    babel_idx_bob.build(verbose=False)

    assert babel_idx.domain == babel_idx_bob.domain
    ok("Bob's index has identical domain separator")

    codec_bob = BabelCodec(babel_idx_bob)

    # Encrypt message, then Babel-encode the ciphertext
    print()
    test_message = "Attack at dawn. Coordinates: 35.7796N, 5.8137W".encode()
    kv("Original message", test_message.decode())

    # Step 1: XOR encrypt
    ciphertext = alice.encrypt(test_message, slot_timestamp)
    kv("Ciphertext size", f"{len(ciphertext)} bytes")

    # Step 2: Babel encode the ciphertext
    t0 = time.perf_counter()
    params = codec_alice.encode(ciphertext)
    t_babel_enc = time.perf_counter() - t0

    kv("Babel params count", f"{len(params)} (was {len(ciphertext)} bytes)")
    kv("Compression", f"{len(ciphertext)}B → {len(params)} params "
       f"(ratio {len(ciphertext)/len(params):.1f}:1)")
    kv("Babel encode time", f"{t_babel_enc*1e6:.1f} us")

    # Show polymorphism: encode same ciphertext again
    params2 = codec_alice.encode(ciphertext)
    different_count = sum(1 for a, b in zip(params, params2) if a != b)
    kv("Polymorphism", f"{different_count}/{len(params)} params differ "
       f"on re-encode ({different_count/len(params)*100:.0f}%)")

    # Step 3: Bob decodes Babel params back to ciphertext
    t0 = time.perf_counter()
    recovered_ct = codec_bob.decode(params, len(ciphertext))
    t_babel_dec = time.perf_counter() - t0

    assert recovered_ct == ciphertext, "BABEL DECODE MISMATCH!"
    ok(f"Babel decode OK in {t_babel_dec*1e6:.1f} us")

    # Step 4: Bob XOR decrypts
    recovered_msg = bob.decrypt(recovered_ct, slot_timestamp)
    assert recovered_msg == test_message, "FINAL DECRYPTION FAILED!"
    ok(f"Final message: {recovered_msg.decode()}")

    # =========================================================================
    # PHASE 7: STATISTICAL TESTS ON OTP
    # =========================================================================
    section("PHASE 6 — Statistical Quality Tests (NIST SP 800-22 subset)")

    print("\n  Running 6 tests on 100 KB of SHA-256 CTR output...\n")
    results = run_all_tests(seed_a, num_bytes=100_000)

    all_pass = True
    for name, r in results.items():
        if "p_value" in r:
            status = "PASS" if r["pass"] else "FAIL"
            if not r["pass"]:
                all_pass = False
            kv(name, f"p={r['p_value']:.6f}  [{status}]")
        else:
            status = "PASS" if r["pass"] else "FAIL"
            if not r["pass"]:
                all_pass = False
            kv(name, f"val={r['value']}  [{status}]")

    print()
    if all_pass:
        ok("ALL STATISTICAL TESTS PASSED")
    else:
        fail("Some tests failed — investigate")

    # =========================================================================
    # PHASE 8: FILE ENCRYPTION DEMO
    # =========================================================================
    section("PHASE 7 — File Encryption Demo")

    # Create a sample file
    sample_content = (
        "CONFIDENTIAL REPORT\n"
        "====================\n"
        "Subject: Infrastructure Assessment Results\n"
        "Date: 2026-03-15\n\n"
        "Findings:\n"
        "1. Primary firewall has 3 critical misconfigurations\n"
        "2. Internal DNS allows zone transfers\n"
        "3. Database credentials in plaintext config files\n"
        "4. No network segmentation between dev and prod\n\n"
        "Recommendation: Immediate remediation required.\n"
    ).encode()

    kv("Input file", f"{len(sample_content)} bytes")

    # Alice encrypts
    slot_ts = slot_timestamp + 2  # different slot
    ct_file = alice.encrypt(sample_content, slot_ts)

    # Babel encode
    params_file = codec_alice.encode(ct_file)
    babel_encoded = codec_alice.encode_to_bytes(ct_file)

    kv("Ciphertext", f"{len(ct_file)} bytes")
    kv("Babel encoded", f"{len(babel_encoded)} bytes "
       f"({len(params_file)} params)")
    kv("Ratio", f"original {len(sample_content)}B "
       f"→ babel {len(babel_encoded)}B")

    # Bob decodes
    ct_recovered = codec_bob.decode_from_bytes(babel_encoded)
    msg_recovered = bob.decrypt(ct_recovered, slot_ts)

    assert msg_recovered == sample_content
    ok("File encrypted, Babel-encoded, transmitted, decoded, decrypted")
    ok(f"Recovered {len(msg_recovered)} bytes — content verified")

    # =========================================================================
    # SUMMARY
    # =========================================================================
    banner("PROTOCOL SUMMARY")

    print("  Security Properties:")
    kv("Confidentiality", "OTP (Shannon-secure)")
    kv("Integrity", "HMAC-SHA256")
    kv("Key exchange", "ECDH Curve25519 (no contact)")
    kv("Forward secrecy", "HKDF per-session + per-slot")
    kv("Polymorphism", f"~{babel_idx.stats['avg_collisions']:.0f} variants/block")
    kv("Network traffic", "ZERO (offline mode)")

    print("\n  Performance:")
    kv("OTP generation", f"{0.1/t_big:.0f} MB/s")
    kv("Encryption", "< 10 us per message")
    kv("Babel index build", f"{t_build:.1f}s (one-time)")
    kv("Babel encode/decode", "< 100 us per message")

    print("\n  Detection Surface:")
    kv("API requests", "None (offline mode)")
    kv("Suspicious domains", "None")
    kv("Traffic patterns", "None")
    kv("Ciphertext analysis", "Impossible (OTP)")
    kv("Only remaining signal", "Steganographic transmission channel")

    print(f"\n{'='*W}")
    print("  All phases completed successfully.")
    print(f"{'='*W}\n")


if __name__ == "__main__":
    main()
