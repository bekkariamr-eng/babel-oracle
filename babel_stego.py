#!/usr/bin/env python3
"""
Babel Oracle Protocol — Steganographic Transport Layer
========================================================
Provides covert communication channels via:
  - QR Code Key Exchange (ECDH public keys as QR codes)
  - Image Steganography (LSB embedding with key-seeded pixel scatter)
  - StegoTransport (Transport backend using stego images)
  - Cover Image Generator (synthetic gradient/noise textures)

Dependencies: qrcode[pil], Pillow, pyzbar

Author: Amr Bekkari
"""

import base64
import hashlib
import hmac
import io
import json
import os
import struct
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

# Add project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import KeyPair, Party

try:
    import qrcode
    from qrcode.constants import ERROR_CORRECT_M
    HAS_QR = True
except ImportError:
    HAS_QR = False

try:
    from pyzbar.pyzbar import decode as qr_decode
    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False

try:
    from PIL import Image, ImageDraw, ImageFilter
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# Import Transport ABC from transport module
from transport import Transport, make_packet, parse_packet, PKT_KEY_ANNOUNCE, PKT_MESSAGE


# =============================================================================
# 1. QR CODE KEY EXCHANGE
# =============================================================================

class QRKeyExchange:
    """
    Exchange ECDH public keys via QR codes.

    Payload format (JSON):
        {"babel": 1, "name": "<identity>", "pub": "<base64-raw-public-key>"}

    The QR code is version-1 protocol identifier, identity name, and
    the 32-byte X25519 public key encoded as base64.
    """

    PROTOCOL_VERSION = 1

    @staticmethod
    def generate_qr(name: str, public_key: bytes, save_path: Optional[str] = None) -> "Image.Image":
        """
        Generate a QR code containing the ECDH public key.

        Args:
            name: Identity name (e.g., "alice")
            public_key: 32-byte X25519 public key
            save_path: Optional path to save the QR image

        Returns:
            PIL Image of the QR code
        """
        if not HAS_QR:
            raise ImportError("qrcode package required: pip install qrcode[pil]")
        if not HAS_PIL:
            raise ImportError("Pillow package required: pip install Pillow")

        assert len(public_key) == 32, "Public key must be 32 bytes"

        payload = json.dumps({
            "babel": QRKeyExchange.PROTOCOL_VERSION,
            "name": name,
            "pub": base64.b64encode(public_key).decode("ascii"),
        }, separators=(",", ":"))  # compact JSON

        qr = qrcode.QRCode(
            version=None,  # auto-size
            error_correction=ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(payload)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

        if save_path:
            img.save(save_path)

        return img

    @staticmethod
    def read_qr(image_path: str) -> Tuple[str, bytes]:
        """
        Read a QR code and extract the peer's identity and public key.

        Args:
            image_path: Path to the QR code image

        Returns:
            (name, public_key_bytes) tuple

        Raises:
            ValueError: If QR code is invalid or not a Babel key
        """
        if not HAS_PYZBAR:
            raise ImportError("pyzbar package required: pip install pyzbar")
        if not HAS_PIL:
            raise ImportError("Pillow package required: pip install Pillow")

        img = Image.open(image_path)
        decoded = qr_decode(img)

        if not decoded:
            raise ValueError("No QR code found in image")

        data = decoded[0].data.decode("utf-8")
        payload = json.loads(data)

        if payload.get("babel") != QRKeyExchange.PROTOCOL_VERSION:
            raise ValueError(f"Unknown protocol version: {payload.get('babel')}")

        name = payload["name"]
        pub_bytes = base64.b64decode(payload["pub"])

        if len(pub_bytes) != 32:
            raise ValueError(f"Invalid public key length: {len(pub_bytes)}")

        return name, pub_bytes

    @staticmethod
    def read_qr_from_image(img: "Image.Image") -> Tuple[str, bytes]:
        """
        Read a QR code from an in-memory PIL Image.

        Args:
            img: PIL Image containing a QR code

        Returns:
            (name, public_key_bytes) tuple
        """
        if not HAS_PYZBAR:
            raise ImportError("pyzbar package required: pip install pyzbar")

        decoded = qr_decode(img)

        if not decoded:
            raise ValueError("No QR code found in image")

        data = decoded[0].data.decode("utf-8")
        payload = json.loads(data)

        if payload.get("babel") != QRKeyExchange.PROTOCOL_VERSION:
            raise ValueError(f"Unknown protocol version: {payload.get('babel')}")

        name = payload["name"]
        pub_bytes = base64.b64decode(payload["pub"])

        if len(pub_bytes) != 32:
            raise ValueError(f"Invalid public key length: {len(pub_bytes)}")

        return name, pub_bytes


# =============================================================================
# 2. LSB IMAGE STEGANOGRAPHY — Key-seeded pixel scatter
# =============================================================================

@dataclass
class StegoConfig:
    """Configuration for LSB steganography."""
    bits_per_channel: int = 1       # 1 or 2 LSBs per color channel
    channels: str = "RGB"           # Which channels to use
    magic: bytes = b"BSTG"         # 4-byte magic for detection
    max_payload_ratio: float = 0.5  # Max fraction of pixels to use


class LSBSteganography:
    """
    Least Significant Bit steganography with key-seeded pixel scatter.

    Instead of writing data sequentially (easy to detect), pixels are
    selected in a pseudo-random order derived from a shared key. Both
    parties generate the same scatter pattern from the same key.

    Scatter algorithm:
        1. Generate pixel indices [0, 1, ..., W*H-1]
        2. Fisher-Yates shuffle using HMAC-SHA256 PRNG seeded from stego_key
        3. Embed/extract bits in shuffled order

    Payload format (embedded in image):
        MAGIC(4) || LENGTH(4) || DATA(N) || CRC32(4)
    """

    def __init__(self, config: Optional[StegoConfig] = None):
        self.config = config or StegoConfig()
        assert self.config.bits_per_channel in (1, 2), "bits_per_channel must be 1 or 2"

    def _derive_stego_key(self, session_key: bytes) -> bytes:
        """Derive the stego scatter key from session key."""
        return hmac.new(
            session_key, b"babel-stego-scatter", hashlib.sha256
        ).digest()

    def _hmac_prng(self, key: bytes, index: int) -> int:
        """Deterministic PRNG: HMAC-SHA256(key, index) → 32-bit int."""
        h = hmac.new(key, struct.pack(">Q", index), hashlib.sha256).digest()
        return struct.unpack(">I", h[:4])[0]

    def _generate_scatter(self, stego_key: bytes, num_pixels: int, needed: int) -> List[int]:
        """
        Generate a pseudo-random pixel order using Fisher-Yates shuffle.

        Args:
            stego_key: 32-byte key for the PRNG
            num_pixels: Total pixels in the image
            needed: How many pixels we need (partial shuffle optimization)

        Returns:
            List of pixel indices in scatter order
        """
        # For efficiency, only do a partial Fisher-Yates shuffle
        # We only need `needed` indices, not the full array
        indices = list(range(num_pixels))
        n = min(needed, num_pixels)

        for i in range(n):
            j = i + (self._hmac_prng(stego_key, i) % (num_pixels - i))
            indices[i], indices[j] = indices[j], indices[i]

        return indices[:n]

    def _crc32(self, data: bytes) -> bytes:
        """Compute CRC32 checksum as 4 bytes."""
        import zlib
        return struct.pack(">I", zlib.crc32(data) & 0xFFFFFFFF)

    def capacity(self, image: "Image.Image") -> int:
        """
        Calculate the maximum payload capacity in bytes.

        Args:
            image: PIL Image (must be RGB)

        Returns:
            Maximum number of data bytes that can be embedded
        """
        if not HAS_PIL:
            raise ImportError("Pillow required: pip install Pillow")

        w, h = image.size
        num_pixels = w * h
        usable_pixels = int(num_pixels * self.config.max_payload_ratio)
        channels = len(self.config.channels)
        bits_per_pixel = channels * self.config.bits_per_channel
        total_bits = usable_pixels * bits_per_pixel
        total_bytes = total_bits // 8

        # Subtract header overhead: MAGIC(4) + LENGTH(4) + CRC32(4) = 12 bytes
        return max(0, total_bytes - 12)

    def embed(self, image: "Image.Image", data: bytes,
              session_key: bytes) -> "Image.Image":
        """
        Embed data into an image using LSB steganography with key-seeded scatter.

        Args:
            image: Cover image (RGB, will be copied)
            data: Data to embed
            session_key: Session key for deriving scatter pattern

        Returns:
            New PIL Image with embedded data

        Raises:
            ValueError: If data is too large for the image
        """
        if not HAS_PIL:
            raise ImportError("Pillow required: pip install Pillow")

        img = image.copy().convert("RGB")
        w, h = img.size
        num_pixels = w * h
        pixels = list(img.getdata())

        # Build payload: MAGIC || LENGTH || DATA || CRC32
        payload = (
            self.config.magic
            + struct.pack(">I", len(data))
            + data
            + self._crc32(data)
        )

        # Convert payload to bit stream
        bpc = self.config.bits_per_channel
        channels = self.config.channels
        num_channels = len(channels)
        bits_per_pixel = num_channels * bpc
        bits_needed = len(payload) * 8
        pixels_needed = (bits_needed + bits_per_pixel - 1) // bits_per_pixel

        usable_pixels = int(num_pixels * self.config.max_payload_ratio)
        if pixels_needed > usable_pixels:
            raise ValueError(
                f"Data too large: need {pixels_needed} pixels, "
                f"have {usable_pixels} usable ({num_pixels} total)"
            )

        # Generate scatter pattern
        stego_key = self._derive_stego_key(session_key)
        scatter = self._generate_scatter(stego_key, num_pixels, pixels_needed)

        # Embed bits
        bit_mask = (1 << bpc) - 1  # 0x01 for bpc=1, 0x03 for bpc=2
        clear_mask = 0xFF ^ bit_mask  # 0xFE for bpc=1, 0xFC for bpc=2

        bit_index = 0
        total_bits = len(payload) * 8
        channel_map = {"R": 0, "G": 1, "B": 2}

        for pixel_order in range(pixels_needed):
            px_idx = scatter[pixel_order]
            r, g, b = pixels[px_idx]
            color = [r, g, b]

            for ch_name in channels:
                if bit_index >= total_bits:
                    break
                ch_idx = channel_map[ch_name]

                # Extract bpc bits from payload
                byte_pos = bit_index // 8
                bit_offset = bit_index % 8

                # Get the bits we need
                if bit_offset + bpc <= 8:
                    bits = (payload[byte_pos] >> (8 - bit_offset - bpc)) & bit_mask
                else:
                    # Bits span two bytes
                    available = 8 - bit_offset
                    high = (payload[byte_pos] & ((1 << available) - 1)) << (bpc - available)
                    low = (payload[byte_pos + 1] >> (8 - (bpc - available))) & ((1 << (bpc - available)) - 1)
                    bits = high | low

                # Embed into LSB(s)
                color[ch_idx] = (color[ch_idx] & clear_mask) | bits
                bit_index += bpc

            pixels[px_idx] = tuple(color)

        # Write modified pixels back
        img.putdata(pixels)
        return img

    def extract(self, image: "Image.Image", session_key: bytes) -> Optional[bytes]:
        """
        Extract hidden data from a stego image.

        Args:
            image: Stego image (RGB)
            session_key: Session key for deriving scatter pattern

        Returns:
            Extracted data bytes, or None if no valid data found
        """
        if not HAS_PIL:
            raise ImportError("Pillow required: pip install Pillow")

        img = image.convert("RGB")
        w, h = img.size
        num_pixels = w * h
        pixels = list(img.getdata())

        bpc = self.config.bits_per_channel
        channels = self.config.channels
        num_channels = len(channels)
        bits_per_pixel = num_channels * bpc
        channel_map = {"R": 0, "G": 1, "B": 2}
        bit_mask = (1 << bpc) - 1

        # We need at least the header: MAGIC(4) + LENGTH(4) = 8 bytes = 64 bits
        header_pixels = (64 + bits_per_pixel - 1) // bits_per_pixel
        usable_pixels = int(num_pixels * self.config.max_payload_ratio)

        if header_pixels > usable_pixels:
            return None

        stego_key = self._derive_stego_key(session_key)

        # First pass: extract header to get length
        # We'll extract enough for MAGIC + LENGTH + reasonable max
        # Start with header extraction
        header_scatter = self._generate_scatter(stego_key, num_pixels, usable_pixels)

        def extract_bits(n_bytes: int) -> bytes:
            """Extract n_bytes from the scatter pattern."""
            result = bytearray(n_bytes)
            bit_index = 0
            total_bits = n_bytes * 8
            pixel_order = 0

            while bit_index < total_bits:
                if pixel_order >= len(header_scatter):
                    return None
                px_idx = header_scatter[pixel_order]
                r, g, b = pixels[px_idx]
                color = [r, g, b]

                for ch_name in channels:
                    if bit_index >= total_bits:
                        break
                    ch_idx = channel_map[ch_name]
                    bits = color[ch_idx] & bit_mask

                    byte_pos = bit_index // 8
                    bit_offset = bit_index % 8

                    if bit_offset + bpc <= 8:
                        result[byte_pos] |= bits << (8 - bit_offset - bpc)
                    else:
                        available = 8 - bit_offset
                        result[byte_pos] |= (bits >> (bpc - available))
                        if byte_pos + 1 < n_bytes:
                            result[byte_pos + 1] |= (bits & ((1 << (bpc - available)) - 1)) << (8 - (bpc - available))

                    bit_index += bpc

                pixel_order += 1

            return bytes(result)

        # Extract header: MAGIC(4) + LENGTH(4) = 8 bytes
        header = extract_bits(8)
        if header is None:
            return None

        # Check magic
        if header[:4] != self.config.magic:
            return None

        # Get data length
        data_length = struct.unpack(">I", header[4:8])[0]

        # Sanity check
        if data_length > self.capacity(image):
            return None

        # Extract full payload: header(8) + data(N) + CRC32(4)
        total_length = 8 + data_length + 4
        full_payload = extract_bits(total_length)
        if full_payload is None:
            return None

        data = full_payload[8:8 + data_length]
        crc_stored = full_payload[8 + data_length:8 + data_length + 4]
        crc_computed = self._crc32(data)

        if crc_stored != crc_computed:
            return None

        return data


# =============================================================================
# 3. STEGO TRANSPORT — Transport backend using steganography
# =============================================================================

class StegoTransport(Transport):
    """
    Transport backend that hides packets inside images in a shared folder.

    send(): Embeds packet into a cover image, saves to shared folder
    poll(): Scans folder for new images, attempts extraction from each

    Uses CoverImageGenerator for synthetic covers if no cover images provided.
    """

    def __init__(self, folder: str, session_key: bytes,
                 cover_images: Optional[List[str]] = None,
                 config: Optional[StegoConfig] = None,
                 delete_after_read: bool = True):
        """
        Args:
            folder: Shared folder path
            session_key: Session key for stego scatter derivation
            cover_images: Optional list of cover image paths
            config: Stego configuration
            delete_after_read: Remove images after successful extraction
        """
        self.folder = folder
        self.session_key = session_key
        self.stego = LSBSteganography(config)
        self.cover_images = cover_images or []
        self.delete_after_read = delete_after_read
        self._seen_files: set = set()
        self._own_files: set = set()
        self._cover_gen = None
        self._started = False

    def start(self) -> None:
        """Initialize the transport folder."""
        os.makedirs(self.folder, exist_ok=True)
        self._cover_gen = CoverImageGenerator()
        self._started = True

    def stop(self) -> None:
        """Shut down the transport."""
        self._started = False

    def _get_cover_image(self) -> "Image.Image":
        """Get a cover image — from provided list or generate synthetic."""
        if self.cover_images:
            import random
            path = random.choice(self.cover_images)
            return Image.open(path).convert("RGB")
        else:
            # Generate a synthetic cover image
            return self._cover_gen.generate()

    def send(self, data: bytes) -> bool:
        """
        Embed data into a cover image and save to the shared folder.

        Args:
            data: Raw packet bytes to send

        Returns:
            True on success, False on failure
        """
        if not self._started:
            return False

        try:
            cover = self._get_cover_image()

            # Check capacity — if insufficient, try a larger cover
            if self.stego.capacity(cover) < len(data):
                # Generate a larger cover
                needed_pixels = (len(data) + 12) * 8  # rough estimate
                side = int((needed_pixels / 3 / self.stego.config.max_payload_ratio) ** 0.5) + 1
                side = max(side, 512)
                cover = self._cover_gen.generate(width=side, height=side)

            stego_img = self.stego.embed(cover, data, self.session_key)

            # Save with random filename
            filename = os.urandom(8).hex() + ".png"
            filepath = os.path.join(self.folder, filename)
            stego_img.save(filepath, "PNG")
            self._own_files.add(filename)

            return True
        except Exception as e:
            print(f"[StegoTransport] send error: {e}")
            return False

    def poll(self) -> List[bytes]:
        """
        Scan the shared folder for new images and extract hidden data.

        Returns:
            List of extracted data blobs
        """
        if not self._started:
            return []

        results = []
        try:
            for filename in os.listdir(self.folder):
                if not filename.endswith(".png"):
                    continue
                if filename in self._own_files:
                    continue
                if filename in self._seen_files:
                    continue

                filepath = os.path.join(self.folder, filename)
                self._seen_files.add(filename)

                try:
                    img = Image.open(filepath).convert("RGB")
                    data = self.stego.extract(img, self.session_key)
                    if data is not None:
                        results.append(data)
                        if self.delete_after_read:
                            try:
                                os.remove(filepath)
                            except OSError:
                                pass
                except Exception:
                    continue  # Not a stego image or corrupted

        except OSError:
            pass

        return results


# =============================================================================
# 4. COVER IMAGE GENERATOR — Synthetic gradient/noise textures
# =============================================================================

class CoverImageGenerator:
    """
    Generate synthetic cover images for steganography.

    Produces natural-looking gradient and noise textures that look like
    typical background images, wallpapers, or camera captures. These are
    harder to flag than solid-color or completely random images.

    Styles:
        - gradient: Smooth color gradient with noise overlay
        - noise: Colored noise texture (like camera sensor noise)
        - plasma: Plasma-like fractal pattern
    """

    STYLES = ["gradient", "noise", "plasma"]

    def __init__(self, seed: Optional[bytes] = None):
        """
        Args:
            seed: Optional deterministic seed. If None, uses os.urandom.
        """
        self._seed = seed
        self._counter = 0

    def _get_random_bytes(self, n: int) -> bytes:
        """Get n random or pseudo-random bytes."""
        if self._seed:
            h = hashlib.sha256(self._seed + struct.pack(">Q", self._counter)).digest()
            self._counter += 1
            result = h
            while len(result) < n:
                h = hashlib.sha256(self._seed + struct.pack(">Q", self._counter)).digest()
                self._counter += 1
                result += h
            return result[:n]
        else:
            return os.urandom(n)

    def generate(self, width: int = 640, height: int = 480,
                 style: Optional[str] = None) -> "Image.Image":
        """
        Generate a synthetic cover image.

        Args:
            width: Image width in pixels
            height: Image height in pixels
            style: "gradient", "noise", or "plasma". Random if None.

        Returns:
            PIL Image (RGB)
        """
        if not HAS_PIL:
            raise ImportError("Pillow required: pip install Pillow")

        if style is None:
            rand = self._get_random_bytes(1)
            style = self.STYLES[rand[0] % len(self.STYLES)]

        if style == "gradient":
            return self._gen_gradient(width, height)
        elif style == "noise":
            return self._gen_noise(width, height)
        elif style == "plasma":
            return self._gen_plasma(width, height)
        else:
            raise ValueError(f"Unknown style: {style}")

    def _gen_gradient(self, w: int, h: int) -> "Image.Image":
        """Generate a gradient image with subtle noise overlay."""
        rand = self._get_random_bytes(12)

        # Random start and end colors
        r1, g1, b1 = rand[0], rand[1], rand[2]
        r2, g2, b2 = rand[3], rand[4], rand[5]
        # Noise intensity (0-15)
        noise_amp = rand[6] % 16

        img = Image.new("RGB", (w, h))
        pixels = []

        for y in range(h):
            t = y / max(h - 1, 1)
            for x in range(w):
                s = x / max(w - 1, 1)
                # Diagonal gradient mixing
                mix = (t + s) / 2.0
                r = int(r1 + (r2 - r1) * mix) & 0xFF
                g = int(g1 + (g2 - g1) * mix) & 0xFF
                b = int(b1 + (b2 - b1) * mix) & 0xFF
                pixels.append((r, g, b))

        img.putdata(pixels)

        # Add subtle noise
        if noise_amp > 0:
            noise_data = self._get_random_bytes(w * h * 3)
            noise_pixels = []
            for i in range(w * h):
                nr = (noise_data[i * 3] % (noise_amp * 2 + 1)) - noise_amp
                ng = (noise_data[i * 3 + 1] % (noise_amp * 2 + 1)) - noise_amp
                nb = (noise_data[i * 3 + 2] % (noise_amp * 2 + 1)) - noise_amp
                pr, pg, pb = pixels[i]
                noise_pixels.append((
                    max(0, min(255, pr + nr)),
                    max(0, min(255, pg + ng)),
                    max(0, min(255, pb + nb)),
                ))
            img.putdata(noise_pixels)

        return img

    def _gen_noise(self, w: int, h: int) -> "Image.Image":
        """Generate a colored noise texture."""
        rand = self._get_random_bytes(6)
        base_r, base_g, base_b = rand[0], rand[1], rand[2]
        variance = 30 + (rand[3] % 50)  # 30-79 range

        img = Image.new("RGB", (w, h))
        noise_data = self._get_random_bytes(w * h * 3)
        pixels = []

        for i in range(w * h):
            r = max(0, min(255, base_r + (noise_data[i * 3] % (variance * 2 + 1)) - variance))
            g = max(0, min(255, base_g + (noise_data[i * 3 + 1] % (variance * 2 + 1)) - variance))
            b = max(0, min(255, base_b + (noise_data[i * 3 + 2] % (variance * 2 + 1)) - variance))
            pixels.append((r, g, b))

        img.putdata(pixels)

        # Apply slight blur for natural look
        img = img.filter(ImageFilter.GaussianBlur(radius=0.5))

        return img

    def _gen_plasma(self, w: int, h: int) -> "Image.Image":
        """Generate a plasma-like fractal pattern."""
        import math

        rand = self._get_random_bytes(24)
        # Random phase offsets and frequencies
        freqs = [1.0 + (rand[i] % 30) / 10.0 for i in range(6)]  # 1.0-3.9
        phases = [rand[i + 6] / 255.0 * 2 * math.pi for i in range(6)]
        colors = [(rand[12 + i], rand[15 + i], rand[18 + i]) for i in range(3)]

        img = Image.new("RGB", (w, h))
        pixels = []

        for y in range(h):
            for x in range(w):
                nx = x / w * math.pi * 2
                ny = y / h * math.pi * 2

                v1 = math.sin(nx * freqs[0] + phases[0]) * math.cos(ny * freqs[1] + phases[1])
                v2 = math.sin(nx * freqs[2] + ny * freqs[3] + phases[2])
                v3 = math.cos(nx * freqs[4] + phases[3]) * math.sin(ny * freqs[5] + phases[4])

                # Combine and normalize to 0-1
                v = (v1 + v2 + v3) / 3.0
                v = (v + 1.0) / 2.0  # shift from [-1,1] to [0,1]
                v = max(0.0, min(1.0, v))

                # Color interpolation
                r = int(colors[0][0] * (1 - v) + colors[1][0] * v) & 0xFF
                g = int(colors[0][1] * (1 - v) + colors[1][1] * v) & 0xFF
                b = int(colors[0][2] * (1 - v) + colors[1][2] * v) & 0xFF

                pixels.append((r, g, b))

        img.putdata(pixels)
        return img


# =============================================================================
# 5. DEMO FUNCTIONS
# =============================================================================

def demo_qr_exchange():
    """
    Demo 1: QR Code Key Exchange

    Alice generates a QR code with her public key.
    Bob scans it and completes the key exchange.
    """
    print("=" * 60)
    print("DEMO 1: QR Code Key Exchange")
    print("=" * 60)

    if not HAS_QR:
        print("SKIP: qrcode not installed (pip install qrcode[pil])")
        return False
    if not HAS_PIL:
        print("SKIP: Pillow not installed (pip install Pillow)")
        return False

    # Alice generates keypair and QR code
    alice_kp = KeyPair.generate()
    print(f"Alice public key: {alice_kp.public_bytes.hex()[:16]}...")

    with tempfile.TemporaryDirectory() as tmpdir:
        qr_path = os.path.join(tmpdir, "alice_key.png")
        qr_img = QRKeyExchange.generate_qr("alice", alice_kp.public_bytes, qr_path)
        print(f"QR code saved to: {qr_path}")
        print(f"QR image size: {qr_img.size}")

        # Bob scans the QR code
        if HAS_PYZBAR:
            name, pub_bytes = QRKeyExchange.read_qr(qr_path)
            print(f"Bob reads QR: name={name}, key={pub_bytes.hex()[:16]}...")

            # Verify roundtrip
            assert name == "alice", f"Name mismatch: {name}"
            assert pub_bytes == alice_kp.public_bytes, "Public key mismatch!"
            print("✓ QR roundtrip verified: name and public key match")

            # Also test in-memory read
            name2, pub2 = QRKeyExchange.read_qr_from_image(qr_img)
            assert name2 == "alice" and pub2 == alice_kp.public_bytes
            print("✓ In-memory QR read also works")
        else:
            print("SKIP pyzbar decode (pyzbar not installed)")
            print("✓ QR generation works, decode requires pyzbar")

    # Now do a full ECDH exchange via QR
    bob_kp = KeyPair.generate()
    alice_party = Party("alice", keypair=alice_kp)
    bob_party = Party("bob", keypair=bob_kp)

    # Simulate: Alice scans Bob's QR, Bob scans Alice's QR
    alice_party.establish_key(bob_kp.public_bytes)
    bob_party.establish_key(alice_kp.public_bytes)
    alice_party.open_session(20260316)
    bob_party.open_session(20260316)

    assert alice_party.master_key == bob_party.master_key, "Master key mismatch!"
    print("✓ ECDH key agreement successful via QR-exchanged keys")
    print()
    return True


def demo_stego_transport():
    """
    Demo 2: Steganographic Transport

    Alice and Bob communicate by hiding encrypted packets inside
    synthetic cover images in a shared folder.
    """
    print("=" * 60)
    print("DEMO 2: Steganographic Transport")
    print("=" * 60)

    if not HAS_PIL:
        print("SKIP: Pillow not installed (pip install Pillow)")
        return False

    # Setup parties
    alice_kp = KeyPair.generate()
    bob_kp = KeyPair.generate()

    alice = Party("alice", keypair=alice_kp)
    bob = Party("bob", keypair=bob_kp)

    alice.establish_key(bob_kp.public_bytes)
    bob.establish_key(alice_kp.public_bytes)
    alice.open_session(20260316)
    bob.open_session(20260316)

    assert alice.session_key == bob.session_key

    slot_ts = int(time.time()) // 60 * 60

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create stego transports
        config = StegoConfig(bits_per_channel=2)
        alice_stego = StegoTransport(tmpdir, alice.session_key, config=config)
        bob_stego = StegoTransport(tmpdir, bob.session_key, config=config)

        alice_stego.start()
        bob_stego.start()

        # Alice encrypts and sends a message via stego
        messages = [
            b"Hello Bob, this is hidden in an image!",
            b"Steganography is working!",
            b"Third message via stego transport",
        ]

        for msg in messages:
            ciphertext = alice.encrypt(msg, slot_ts)
            packet = make_packet(PKT_MESSAGE, ciphertext)
            success = alice_stego.send(packet)
            assert success, f"Failed to send: {msg}"
            print(f"Alice sent ({len(msg)}B plaintext → stego image)")

        # Bob polls and decrypts
        time.sleep(0.1)
        received = bob_stego.poll()
        print(f"\nBob received {len(received)} stego images")

        decrypted = []
        for data in received:
            pkt_type, payload = parse_packet(data)
            assert pkt_type == PKT_MESSAGE
            result = bob.decrypt(payload, slot_ts)
            if result is not None:
                decrypted.append(result)
                print(f"  Decrypted: {result.decode()}")

        assert len(decrypted) == len(messages), \
            f"Expected {len(messages)} messages, got {len(decrypted)}"
        for orig, dec in zip(messages, decrypted):
            assert orig == dec, f"Mismatch: {orig} != {dec}"

        print("✓ All messages roundtripped through stego transport")

        # Test cover image generation
        print("\nCover image styles:")
        gen = CoverImageGenerator()
        for style in CoverImageGenerator.STYLES:
            img = gen.generate(320, 240, style=style)
            print(f"  {style}: {img.size} mode={img.mode}")

        # Test capacity
        stego = LSBSteganography(config)
        test_img = gen.generate(640, 480)
        cap = stego.capacity(test_img)
        print(f"\nCapacity of 640x480 image (2bpc): {cap:,} bytes")

        # Test raw LSB embed/extract without transport
        print("\nDirect LSB embed/extract test:")
        test_data = b"Direct stego test payload 12345"
        stego_img = stego.embed(test_img, test_data, alice.session_key)
        extracted = stego.extract(stego_img, alice.session_key)
        assert extracted == test_data, f"LSB mismatch: {extracted} != {test_data}"
        print(f"  ✓ Embedded {len(test_data)}B, extracted successfully")

        # Test wrong key fails
        wrong_key = os.urandom(32)
        extracted_wrong = stego.extract(stego_img, wrong_key)
        assert extracted_wrong is None, "Wrong key should fail extraction!"
        print("  ✓ Wrong key correctly rejected")

        alice_stego.stop()
        bob_stego.stop()

    print()
    return True


def demo_qr_then_stego():
    """
    Demo 3: Full Pipeline — QR Key Exchange → Stego Communication

    1. Alice and Bob exchange keys via QR codes
    2. They communicate via steganographic images in a shared folder
    """
    print("=" * 60)
    print("DEMO 3: Full Pipeline (QR Exchange → Stego Transport)")
    print("=" * 60)

    if not HAS_PIL:
        print("SKIP: Pillow not installed (pip install Pillow)")
        return False
    if not HAS_QR:
        print("SKIP: qrcode not installed")
        return False

    with tempfile.TemporaryDirectory() as tmpdir:
        # Phase 1: Key exchange via QR codes
        print("Phase 1: QR Key Exchange")
        alice_kp = KeyPair.generate()
        bob_kp = KeyPair.generate()

        # Generate QR codes
        alice_qr_path = os.path.join(tmpdir, "alice_qr.png")
        bob_qr_path = os.path.join(tmpdir, "bob_qr.png")
        QRKeyExchange.generate_qr("alice", alice_kp.public_bytes, alice_qr_path)
        QRKeyExchange.generate_qr("bob", bob_kp.public_bytes, bob_qr_path)
        print("  Alice and Bob generated QR codes")

        # Read peer QR codes (simulate scanning)
        if HAS_PYZBAR:
            bob_name, bob_pub = QRKeyExchange.read_qr(alice_qr_path)
            # Note: bob reads alice's QR to get alice's key
            # We swap: alice reads bob's QR
            alice_peer_name, alice_peer_pub = QRKeyExchange.read_qr(bob_qr_path)
            bob_peer_name, bob_peer_pub = QRKeyExchange.read_qr(alice_qr_path)
            print(f"  Alice scanned Bob's QR: {alice_peer_name}")
            print(f"  Bob scanned Alice's QR: {bob_peer_name}")
        else:
            # Simulate without pyzbar
            alice_peer_pub = bob_kp.public_bytes
            bob_peer_pub = alice_kp.public_bytes
            print("  (Simulated QR scan — pyzbar not installed)")

        # Establish keys
        alice = Party("alice", keypair=alice_kp)
        bob = Party("bob", keypair=bob_kp)
        alice.establish_key(alice_peer_pub)
        bob.establish_key(bob_peer_pub)

        session_id = 20260316
        alice.open_session(session_id)
        bob.open_session(session_id)
        assert alice.session_key == bob.session_key
        print("  ✓ ECDH key agreement complete")

        # Phase 2: Stego communication
        print("\nPhase 2: Stego Communication")
        stego_dir = os.path.join(tmpdir, "shared")
        config = StegoConfig(bits_per_channel=2)

        alice_transport = StegoTransport(stego_dir, alice.session_key, config=config)
        bob_transport = StegoTransport(stego_dir, bob.session_key, config=config)
        alice_transport.start()
        bob_transport.start()

        slot_ts = int(time.time()) // 60 * 60

        # Alice sends
        msg = b"This message traveled via QR key exchange and image steganography!"
        ciphertext = alice.encrypt(msg, slot_ts)
        packet = make_packet(PKT_MESSAGE, ciphertext)
        assert alice_transport.send(packet)
        print(f"  Alice sent: {len(msg)}B → encrypted → stego image")

        # Bob receives
        time.sleep(0.1)
        received = bob_transport.poll()
        assert len(received) == 1, f"Expected 1, got {len(received)}"
        pkt_type, payload = parse_packet(received[0])
        plaintext = bob.decrypt(payload, slot_ts)
        assert plaintext == msg, f"Decryption failed: {plaintext}"
        print(f"  Bob received: {plaintext.decode()}")
        print("  ✓ Full QR → Stego pipeline working!")

        # Bob replies
        reply = b"Got it! Steganography is amazing!"
        ct_reply = bob.encrypt(reply, slot_ts)
        pkt_reply = make_packet(PKT_MESSAGE, ct_reply)
        assert bob_transport.send(pkt_reply)
        print(f"\n  Bob replied: {len(reply)}B → encrypted → stego image")

        time.sleep(0.1)
        alice_received = alice_transport.poll()
        assert len(alice_received) == 1
        pkt_type2, payload2 = parse_packet(alice_received[0])
        reply_plain = alice.decrypt(payload2, slot_ts)
        assert reply_plain == reply
        print(f"  Alice received: {reply_plain.decode()}")
        print("  ✓ Bidirectional stego communication verified!")

        # Stats
        stego_obj = LSBSteganography(config)
        cover = CoverImageGenerator().generate(640, 480)
        cap = stego_obj.capacity(cover)
        print(f"\n  Capacity per 640×480 image: {cap:,} bytes")
        print(f"  Encrypted packet size: {len(ciphertext)} bytes")
        print(f"  Overhead: image hides {len(packet)} bytes of packet data")

        alice_transport.stop()
        bob_transport.stop()

    print()
    return True


# =============================================================================
# 6. MAIN — Run all demos
# =============================================================================

if __name__ == "__main__":
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║    Babel Oracle — Steganographic Transport Layer     ║")
    print("╠══════════════════════════════════════════════════════╣")
    print("║  QR Key Exchange + LSB Stego + Cover Image Gen      ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    results = {}

    # Demo 1: QR Key Exchange
    results["qr_exchange"] = demo_qr_exchange()

    # Demo 2: Stego Transport
    results["stego_transport"] = demo_stego_transport()

    # Demo 3: Full Pipeline
    results["full_pipeline"] = demo_qr_then_stego()

    # Summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for name, passed in results.items():
        status = "PASS ✓" if passed else "SKIP/FAIL"
        print(f"  {name}: {status}")

    total = sum(1 for v in results.values() if v)
    print(f"\n  {total}/{len(results)} demos passed")

    if total == len(results):
        print("\n  All steganography demos passed! 🎉")
    else:
        missing = []
        if not HAS_QR:
            missing.append("qrcode[pil]")
        if not HAS_PYZBAR:
            missing.append("pyzbar")
        if not HAS_PIL:
            missing.append("Pillow")
        if missing:
            print(f"\n  Install missing deps: pip install {' '.join(missing)}")
