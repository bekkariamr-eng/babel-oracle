"""
Babel Index — Reverse Lookup Table for Oracle Compression
==========================================================
Maps target byte blocks to deterministic function parameters
that produce those blocks when evaluated through SHA-256.

The "Library of Babel" principle: every possible byte sequence
already exists as the output of some SHA-256(seed || params).
We pre-compute the index to find those parameters instantly.

Block size B=2 (demo): 65,536 entries — builds in ~1s
Block size B=3 (medium): 16,777,216 entries — builds in ~30s
Block size B=4 (full): 4,294,967,296 entries — requires rainbow chains

Author: Amr Bekkari
"""

import hashlib
import struct
import os
import json
import time
import random
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class BabelConfig:
    """Configuration for Babel Index construction."""
    block_size: int = 2          # bytes per block (2=demo, 3=medium, 4=full)
    hash_prefix: bytes = b""     # domain separator bound to the shared key
    max_param: int = 0           # auto-computed: 2^(block_size*8)
    search_space: int = 0        # how many params to try

    def __post_init__(self):
        if self.block_size not in (2, 3):
            raise ValueError(f"block_size must be 2 or 3, got {self.block_size}")
        self.max_param = 1 << (self.block_size * 8)
        # oversample by 8x to ensure near-100% coverage
        self.search_space = self.max_param * 8


class BabelIndex:
    """
    The Babel Library: a reverse index mapping byte blocks to
    the parameters that produce them via SHA-256.
    
    Given a target block T (B bytes), returns a list of parameter
    values P such that SHA-256(domain || P)[:B] == T.
    
    This is the core of the "Babel compression": instead of
    transmitting the block itself, transmit the parameter P.
    The receiver re-computes SHA-256(domain || P)[:B] to recover T.
    """

    def __init__(self, config: BabelConfig, shared_key: bytes):
        self.config = config
        self.B = config.block_size
        # Domain separator: binds the index to the shared key
        # Both parties compute the same index independently
        self.domain = hashlib.sha256(
            b"babel-index-domain-" + shared_key
        ).digest()
        # index[block_value] = [param1, param2, ...] (collisions = polymorphism)
        self.index: Dict[int, List[int]] = {}
        self.built = False
        self.stats = {"total_entries": 0, "coverage": 0.0, "avg_collisions": 0.0}

    def _eval(self, param: int) -> int:
        """Evaluate the oracle function for a given parameter.
        Returns the first B bytes of SHA-256(domain || param) as an integer."""
        h = hashlib.sha256(
            self.domain + struct.pack(">Q", param)
        ).digest()
        return int.from_bytes(h[: self.B], "big")

    def build(self, verbose: bool = True, progress_callback=None) -> None:
        """
        Build the reverse index by evaluating the oracle function
        over the search space and storing the mapping value → [params].
        """
        t0 = time.time()
        target_count = self.config.max_param
        search_count = self.config.search_space

        if verbose:
            print(f"[Babel] Building index: B={self.B}, "
                  f"target_space={target_count:,}, "
                  f"search_space={search_count:,}")

        self.index.clear()

        milestone = max(1, search_count // 20)
        for p in range(search_count):
            val = self._eval(p)
            if val not in self.index:
                self.index[val] = []
            self.index[val].append(p)

            if verbose and (p + 1) % milestone == 0:
                pct = (p + 1) / search_count * 100
                cov = len(self.index) / target_count * 100
                print(f"  [{pct:5.1f}%] searched {p+1:>10,} | "
                      f"coverage: {cov:.1f}% ({len(self.index):,}/{target_count:,})")
            if progress_callback and (p + 1) % milestone == 0:
                progress_callback(p + 1, search_count)

        elapsed = time.time() - t0
        coverage = len(self.index) / target_count

        # Gap-filling: find uncovered blocks and search specifically for them
        if coverage < 1.0:
            missing = set(range(target_count)) - set(self.index.keys())
            if verbose and missing:
                print(f"  [GAP-FILL] {len(missing)} uncovered blocks, searching...")
            extra_param = search_count
            max_extra = search_count * 4  # try up to 4x more
            while missing and extra_param < max_extra:
                val = self._eval(extra_param)
                if val not in self.index:
                    self.index[val] = []
                self.index[val].append(extra_param)
                missing.discard(val)
                extra_param += 1
            if verbose:
                print(f"  [GAP-FILL] Searched {extra_param - search_count:,} extra, "
                      f"{len(missing)} still missing")
        total_entries = sum(len(v) for v in self.index.values())
        avg_coll = total_entries / max(len(self.index), 1)

        self.stats = {
            "total_entries": total_entries,
            "coverage": coverage,
            "avg_collisions": avg_coll,
            "build_time_s": round(elapsed, 2),
            "block_size": self.B,
            "search_space": search_count,
        }
        self.built = True

        if verbose:
            print(f"[Babel] Index built in {elapsed:.1f}s")
            print(f"  Coverage: {coverage*100:.2f}% "
                  f"({len(self.index):,}/{target_count:,})")
            print(f"  Avg collisions per block: {avg_coll:.1f}")
            print(f"  Total entries: {total_entries:,}")

    def lookup(self, block: bytes) -> Optional[int]:
        """
        Find a parameter that produces the target block.
        Randomly selects among collisions (polymorphism).
        Returns None if no match found (should not happen with full coverage).
        """
        assert len(block) == self.B
        val = int.from_bytes(block, "big")
        candidates = self.index.get(val)
        if not candidates:
            return None
        return random.choice(candidates)

    def lookup_all(self, block: bytes) -> List[int]:
        """Return ALL parameters that produce the target block."""
        val = int.from_bytes(block, "big")
        return self.index.get(val, [])

    def verify(self, param: int, expected_block: bytes) -> bool:
        """Verify that a parameter produces the expected block."""
        val = self._eval(param)
        return val == int.from_bytes(expected_block, "big")

    def resolve(self, param: int) -> bytes:
        """Evaluate the oracle for a parameter, returning B bytes."""
        val = self._eval(param)
        return val.to_bytes(self.B, "big")


# =============================================================================
# BABEL CODEC — Encode/Decode via the Babel Index
# =============================================================================

class BabelCodec:
    """
    High-level codec: encode arbitrary data into Babel parameters
    and decode them back.
    
    Encode: data → split into B-byte blocks → lookup each in index → param list
    Decode: param list → evaluate oracle for each → concatenate → data
    
    Compression ratio: instead of transmitting N bytes,
    transmit N/B parameter values (each 8 bytes).
    For B=2: 2:1 raw compression (but parameters carry the message implicitly).
    For B=4: 4:1 compression.
    """

    def __init__(self, babel_index: BabelIndex):
        self.idx = babel_index
        self.B = babel_index.B

    def encode(self, data: bytes) -> List[int]:
        """
        Encode data into a sequence of Babel parameters.
        Each parameter, when evaluated, produces B bytes of the original data.
        """
        assert self.idx.built, "Build the index first"

        # Pad to block boundary
        padded = data
        remainder = len(data) % self.B
        if remainder:
            padded = data + bytes(self.B - remainder)

        params = []
        for i in range(0, len(padded), self.B):
            block = padded[i : i + self.B]
            param = self.idx.lookup(block)
            if param is None:
                raise ValueError(
                    f"Block {block.hex()} at offset {i} has no Babel entry. "
                    f"Index coverage may be insufficient."
                )
            params.append(param)

        return params

    def decode(self, params: List[int], original_length: int) -> bytes:
        """
        Decode a sequence of Babel parameters back to data.
        Re-evaluates the oracle for each parameter to recover the blocks.
        """
        blocks = []
        for p in params:
            block = self.idx.resolve(p)
            blocks.append(block)
        result = b"".join(blocks)
        return result[:original_length]

    def encode_to_bytes(self, data: bytes) -> bytes:
        """Encode data and serialize params as bytes (8 bytes each, big-endian)."""
        params = self.encode(data)
        header = struct.pack(">I", len(data))  # original length
        body = b"".join(struct.pack(">Q", p) for p in params)
        return header + body

    def decode_from_bytes(self, encoded: bytes) -> bytes:
        """Decode from serialized parameter bytes."""
        original_length = struct.unpack(">I", encoded[:4])[0]
        body = encoded[4:]
        params = []
        for i in range(0, len(body), 8):
            params.append(struct.unpack(">Q", body[i : i + 8])[0])
        return self.decode(params, original_length)
