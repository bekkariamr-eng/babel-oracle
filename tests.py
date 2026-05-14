"""
Statistical Quality Tests for the OTP Generator
=================================================
Subset of NIST SP 800-22 tests to verify the SHA-256 CTR
output is indistinguishable from true randomness.

Author: Amr Bekkari
"""

import math
import hashlib
import struct
from typing import Dict, Tuple
from core import SHA256_CTR_OTP, ChaCha20_OTP


def frequency_test(data: bytes) -> Tuple[float, bool]:
    """
    NIST SP 800-22 Test 1: Frequency (monobit) test.
    Checks if the number of 0s and 1s is approximately equal.
    """
    n = len(data) * 8
    s = sum(bin(byte).count("1") for byte in data)
    s_obs = abs(2 * s - n) / math.sqrt(n)
    p_value = math.erfc(s_obs / math.sqrt(2))
    return p_value, p_value >= 0.01


def runs_test(data: bytes) -> Tuple[float, bool]:
    """
    NIST SP 800-22 Test 2: Runs test.
    Checks if the oscillation between 0s and 1s is as expected.
    """
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    n = len(bits)
    pi = sum(bits) / n

    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return 0.0, False

    v_obs = 1
    for i in range(n - 1):
        if bits[i] != bits[i + 1]:
            v_obs += 1

    p_value = math.erfc(
        abs(v_obs - 2 * n * pi * (1 - pi))
        / (2 * math.sqrt(2 * n) * pi * (1 - pi))
    )
    return p_value, p_value >= 0.01


def block_frequency_test(data: bytes, block_size: int = 128) -> Tuple[float, bool]:
    """
    NIST SP 800-22 Test 2: Block frequency test.
    Divides the sequence into blocks and checks frequency within each.
    """
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    n = len(bits)
    num_blocks = n // block_size
    if num_blocks == 0:
        return 0.0, False

    chi_sq = 0.0
    for i in range(num_blocks):
        block = bits[i * block_size : (i + 1) * block_size]
        pi_i = sum(block) / block_size
        chi_sq += (pi_i - 0.5) ** 2

    chi_sq *= 4 * block_size
    # Incomplete gamma function approximation for chi-squared test
    # Using simple approximation for small degrees of freedom
    p_value = _chi2_pvalue(chi_sq, num_blocks)
    return p_value, p_value >= 0.01


def entropy_per_byte(data: bytes) -> float:
    """Calculate Shannon entropy per byte (max = 8.0 bits)."""
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / n
            entropy -= p * math.log2(p)
    return entropy


def serial_correlation(data: bytes) -> float:
    """
    Compute lag-1 serial correlation coefficient.
    Should be close to 0.0 for random data.
    """
    n = len(data)
    if n < 2:
        return 0.0
    mean = sum(data) / n
    var = sum((b - mean) ** 2 for b in data) / n
    if var == 0:
        return 0.0
    cov = sum((data[i] - mean) * (data[i + 1] - mean) for i in range(n - 1)) / (n - 1)
    return cov / var


def byte_distribution_chi2(data: bytes) -> Tuple[float, bool]:
    """
    Chi-squared test for uniform byte distribution.
    Each byte value (0-255) should appear with equal frequency.
    """
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    expected = n / 256
    chi_sq = sum((f - expected) ** 2 / expected for f in freq)
    p_value = _chi2_pvalue(chi_sq, 255)
    return p_value, p_value >= 0.01


def _chi2_pvalue(chi_sq: float, df: int) -> float:
    """Approximate p-value for chi-squared distribution."""
    if df <= 0:
        return 0.0
    # Wilson-Hilferty approximation
    z = (((chi_sq / df) ** (1 / 3)) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
    p = 0.5 * math.erfc(z / math.sqrt(2))
    return max(0.0, min(1.0, p))


def _run_suite(data: bytes) -> Dict:
    """Run the statistical test suite on a byte sample."""
    results = {}

    p, passed = frequency_test(data)
    results["frequency_monobit"] = {"p_value": round(p, 6), "pass": passed}

    p, passed = runs_test(data)
    results["runs"] = {"p_value": round(p, 6), "pass": passed}

    p, passed = block_frequency_test(data)
    results["block_frequency"] = {"p_value": round(p, 6), "pass": passed}

    ent = entropy_per_byte(data)
    results["entropy_per_byte"] = {"value": round(ent, 4), "pass": ent >= 7.9}

    corr = serial_correlation(data)
    results["serial_correlation"] = {
        "value": round(corr, 6),
        "pass": abs(corr) < 0.01,
    }

    p, passed = byte_distribution_chi2(data)
    results["byte_distribution_chi2"] = {"p_value": round(p, 6), "pass": passed}

    return results


def run_all_tests(seed: bytes, num_bytes: int = 100_000) -> Dict:
    """
    Run all statistical tests on SHA-256 CTR output.
    Returns a dict with test names, p-values, and pass/fail status.
    """
    gen = SHA256_CTR_OTP(seed)
    data = gen.generate(num_bytes)
    return _run_suite(data)


def run_all_tests_chacha20(seed: bytes, num_bytes: int = 100_000) -> Dict:
    """
    Run all statistical tests on ChaCha20 output.
    Returns a dict with test names, p-values, and pass/fail status.
    """
    gen = ChaCha20_OTP(seed)
    data = gen.generate(num_bytes)
    return _run_suite(data)
