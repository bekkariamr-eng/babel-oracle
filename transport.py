#!/usr/bin/env python3
"""
Babel Oracle Protocol — Automatic Transport Layer
===================================================
Provides automatic key exchange and message delivery over:
  - Shared folder (Dropbox, OneDrive, USB, network share)
  - Direct TCP socket (P2P)

Wraps core.py Party for crypto. Zero manual intervention after start().

Author: Amr Bekkari
"""

import hashlib
import os
import socket
import struct
import sys
import threading
import time
from abc import ABC, abstractmethod
from typing import Callable, List, Optional, Tuple

# Add project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import KeyPair, Party


# =============================================================================
# 1. PACKET MULTIPLEXING — Type-tagged packets with XOR obfuscation
# =============================================================================

PKT_KEY_ANNOUNCE = 0x01  # public key broadcast
PKT_MESSAGE      = 0x02  # encrypted message
PKT_FILE         = 0x04  # encrypted file


def _pkt_mask(length: int) -> bytes:
    """Generate a repeating mask from SHA-256 of the packet length."""
    base = hashlib.sha256(
        b"babel-pkt-mask-" + struct.pack(">I", length)
    ).digest()
    reps = (length // 32) + 1
    return (base * reps)[:length]


def make_packet(pkt_type: int, payload: bytes) -> bytes:
    """
    Wrap payload with a type byte, then XOR-obfuscate with a
    length-dependent mask so even the type byte looks random.
    This is NOT for security (OTP handles that) — just prevents
    trivial type fingerprinting in packet captures.
    """
    raw = bytes([pkt_type]) + payload
    mask = _pkt_mask(len(raw))
    return bytes(a ^ b for a, b in zip(raw, mask))


def parse_packet(data: bytes) -> Tuple[int, bytes]:
    """Reverse the XOR obfuscation and return (type, payload)."""
    mask = _pkt_mask(len(data))
    raw = bytes(a ^ b for a, b in zip(data, mask))
    return raw[0], raw[1:]


# =============================================================================
# 2. ABSTRACT TRANSPORT INTERFACE
# =============================================================================

class Transport(ABC):
    """
    Abstract transport for sending and receiving raw byte blobs.
    Implementations must be thread-safe for poll() / send().
    """

    @abstractmethod
    def send(self, data: bytes) -> bool:
        """Send data to the peer(s). Returns True on success."""
        ...

    @abstractmethod
    def poll(self) -> List[bytes]:
        """Return list of newly received data blobs (may be empty)."""
        ...

    @abstractmethod
    def start(self) -> None:
        """Initialize the transport (create dirs, bind sockets, etc.)."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Shut down the transport cleanly."""
        ...


# =============================================================================
# 3. SHARED FOLDER TRANSPORT — Dead-drop via any synced directory
# =============================================================================

class SharedFolderTransport(Transport):
    """
    Uses a shared directory as a dead drop.

    send() writes a random-hex-named .bin file containing raw ciphertext.
    poll() scans for new files, reads them, and optionally deletes after reading.

    An observer sees random temp/cache-like files appearing and disappearing
    — normal cloud sync behavior.
    """

    def __init__(self, folder: str, delete_after_read: bool = True):
        self.folder = os.path.abspath(folder)
        self.delete_after_read = delete_after_read
        self._seen_files: set = set()
        self._own_files: set = set()  # files we wrote — skip in poll
        self._lock = threading.Lock()

    def start(self) -> None:
        os.makedirs(self.folder, exist_ok=True)
        # Don't snapshot — we WANT to read pre-existing files
        # (peer's key announce may already be there)

    def stop(self) -> None:
        pass  # nothing to tear down

    def send(self, data: bytes) -> bool:
        fname = os.urandom(12).hex() + ".bin"
        path = os.path.join(self.folder, fname)
        try:
            with open(path, "wb") as f:
                f.write(data)
            with self._lock:
                self._own_files.add(fname)
            return True
        except OSError:
            return False

    def poll(self) -> List[bytes]:
        results = []
        with self._lock:
            try:
                entries = os.listdir(self.folder)
            except OSError:
                return results
            for fname in entries:
                if not fname.endswith(".bin"):
                    continue
                if fname in self._seen_files:
                    continue
                if fname in self._own_files:
                    self._seen_files.add(fname)
                    continue
                self._seen_files.add(fname)
                path = os.path.join(self.folder, fname)
                try:
                    with open(path, "rb") as f:
                        data = f.read()
                    if data:
                        results.append(data)
                    if self.delete_after_read:
                        try:
                            os.remove(path)
                        except OSError:
                            pass
                except OSError:
                    pass
        return results


# =============================================================================
# 4. SOCKET TRANSPORT — Direct P2P TCP connection
# =============================================================================

class SocketTransport(Transport):
    """
    Direct TCP connection between two parties.

    Server mode: listens on a port, accepts one connection.
    Client mode: connects to peer IP:port.

    Wire format: 4-byte big-endian length prefix + payload.
    Background recv thread fills an inbox list.
    From network perspective: looks like random data over TCP.
    """

    def __init__(self, mode: str = "server", host: str = "0.0.0.0",
                 port: int = 0, peer_host: str = "127.0.0.1",
                 peer_port: int = 0):
        """
        mode: "server" or "client"
        Server: listens on host:port (port=0 → OS picks a free port)
        Client: connects to peer_host:peer_port
        """
        self.mode = mode
        self.host = host
        self.port = port
        self.peer_host = peer_host
        self.peer_port = peer_port
        self._conn: Optional[socket.socket] = None
        self._server_sock: Optional[socket.socket] = None
        self._inbox: List[bytes] = []
        self._lock = threading.Lock()
        self._recv_thread: Optional[threading.Thread] = None
        self._running = False
        self.actual_port = 0  # filled after bind

    def start(self) -> None:
        self._running = True
        if self.mode == "server":
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind((self.host, self.port))
            self.actual_port = self._server_sock.getsockname()[1]
            self._server_sock.listen(1)
            self._server_sock.settimeout(30)
            conn, _addr = self._server_sock.accept()
            self._conn = conn
        else:
            self._conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._conn.connect((self.peer_host, self.peer_port))
            self.actual_port = self.peer_port

        self._conn.settimeout(1.0)
        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()

    def stop(self) -> None:
        self._running = False
        if self._conn:
            try:
                self._conn.close()
            except OSError:
                pass
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass

    def send(self, data: bytes) -> bool:
        if self._conn is None:
            return False
        try:
            header = struct.pack(">I", len(data))
            self._conn.sendall(header + data)
            return True
        except OSError:
            return False

    def poll(self) -> List[bytes]:
        with self._lock:
            items = list(self._inbox)
            self._inbox.clear()
        return items

    def _recv_loop(self) -> None:
        """Background thread: read length-prefixed messages into inbox."""
        while self._running and self._conn:
            try:
                header = self._recv_exact(4)
                if header is None:
                    continue
                length = struct.unpack(">I", header)[0]
                if length > 10_000_000:  # 10 MB sanity limit
                    continue
                payload = self._recv_exact(length)
                if payload is None:
                    continue
                with self._lock:
                    self._inbox.append(payload)
            except (OSError, ConnectionError):
                if not self._running:
                    break
                time.sleep(0.1)

    def _recv_exact(self, n: int) -> Optional[bytes]:
        """Read exactly n bytes from the socket."""
        buf = b""
        while len(buf) < n:
            if not self._running:
                return None
            try:
                chunk = self._conn.recv(n - len(buf))
                if not chunk:
                    return None
                buf += chunk
            except socket.timeout:
                if not self._running:
                    return None
                continue
            except OSError:
                return None
        return buf


# =============================================================================
# 5. NODE — Full participant with auto key exchange and message delivery
# =============================================================================

def _encode_key_announce(name: str, public_key: bytes) -> bytes:
    """Encode a key announcement: name_length(1) + name_utf8(N) + public_key(32)."""
    name_bytes = name.encode("utf-8")[:255]
    return bytes([len(name_bytes)]) + name_bytes + public_key


def _decode_key_announce(data: bytes) -> Tuple[str, bytes]:
    """Decode a key announcement. Returns (name, public_key_32bytes)."""
    name_len = data[0]
    name = data[1:1 + name_len].decode("utf-8", errors="replace")
    public_key = data[1 + name_len:1 + name_len + 32]
    return name, public_key


class Node:
    """
    A full protocol participant with automatic transport.

    Wraps Party (from core.py) + Transport to provide:
    - Auto identity generation/loading
    - Auto public key announcement via transport
    - Auto ECDH key exchange when peer's key arrives
    - Auto decryption of incoming messages
    - Callback-based message delivery

    Usage:
        node = Node("alice", transport, on_message=my_callback)
        node.start()
        # ... peer starts, keys exchange automatically ...
        node.send_message(b"hello")
        node.stop()
    """

    def __init__(self, name: str, transport: Transport,
                 on_message: Optional[Callable[[str, bytes], None]] = None,
                 backend: str = "sha256-ctr"):
        self.name = name
        self.transport = transport
        self.on_message = on_message
        self.backend = backend

        # Crypto party
        self.party = Party(name=name, backend=backend)

        # Peer tracking
        self.peer_name: Optional[str] = None
        self.peer_public_key: Optional[bytes] = None
        self.key_established = threading.Event()

        # State
        self._running = False
        self._poll_thread: Optional[threading.Thread] = None
        self._seen_slots: set = set()
        self._received_messages: List[Tuple[str, bytes]] = []
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the node: init transport, announce key, begin polling."""
        self.transport.start()
        self._running = True

        # Announce our public key
        announce_payload = _encode_key_announce(self.name, self.party.public_key)
        pkt = make_packet(PKT_KEY_ANNOUNCE, announce_payload)
        self.transport.send(pkt)

        # Start background polling
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def stop(self) -> None:
        """Stop the node and transport."""
        self._running = False
        self.transport.stop()

    def send_message(self, plaintext: bytes, wait_for_key: bool = True,
                     timeout: float = 15.0) -> bool:
        """
        Send an encrypted message to the peer.
        Blocks until key exchange is complete (up to timeout).
        """
        if wait_for_key:
            if not self.key_established.wait(timeout=timeout):
                return False

        slot_ts = int(time.time()) // 60 * 60
        ciphertext = self.party.encrypt(plaintext, slot_ts)
        pkt = make_packet(PKT_MESSAGE, ciphertext)
        return self.transport.send(pkt)

    def send_file(self, data: bytes, wait_for_key: bool = True,
                  timeout: float = 15.0) -> bool:
        """Send an encrypted file to the peer."""
        if wait_for_key:
            if not self.key_established.wait(timeout=timeout):
                return False

        slot_ts = int(time.time()) // 60 * 60
        ciphertext = self.party.encrypt(data, slot_ts)
        pkt = make_packet(PKT_FILE, ciphertext)
        return self.transport.send(pkt)

    def get_received_messages(self) -> List[Tuple[str, bytes]]:
        """Return all received messages as [(peer_name, plaintext), ...]."""
        with self._lock:
            return list(self._received_messages)

    def _poll_loop(self) -> None:
        """Background thread: poll transport, process incoming packets."""
        while self._running:
            blobs = self.transport.poll()
            for blob in blobs:
                self._handle_blob(blob)
            time.sleep(0.3)

    def _handle_blob(self, data: bytes) -> None:
        """Process a single received blob."""
        try:
            pkt_type, payload = parse_packet(data)
        except (IndexError, ValueError):
            return  # malformed — discard silently

        if pkt_type == PKT_KEY_ANNOUNCE:
            self._handle_key_announce(payload)
        elif pkt_type in (PKT_MESSAGE, PKT_FILE):
            self._handle_encrypted(pkt_type, payload)
        # Unknown types: discard silently (multi-party tolerance)

    def _handle_key_announce(self, payload: bytes) -> None:
        """Process a peer's public key announcement.
        WARNING: unauthenticated — transport channel must be trusted or
        keys verified out-of-band to prevent MITM."""
        try:
            peer_name, peer_pk = _decode_key_announce(payload)
        except (IndexError, ValueError):
            return

        if len(peer_pk) != 32:
            return
        if peer_name == self.name:
            return  # ignore our own announcement (shared folder echo)

        self.peer_name = peer_name
        self.peer_public_key = peer_pk

        # Perform ECDH key exchange
        self.party.establish_key(peer_pk)

        # Open session (time-based)
        session_id = int(time.strftime("%Y%m%d"))
        self.party.open_session(session_id)

        self.key_established.set()

    def _handle_encrypted(self, pkt_type: int, payload: bytes) -> None:
        """Try to decrypt an incoming message/file."""
        if not self.key_established.is_set():
            return  # can't decrypt without key exchange

        slot_ts = int(time.time()) // 60 * 60

        # Try current slot and neighboring slots (±1 minute tolerance)
        plaintext = None
        for offset in (0, -60, 60):
            result = self.party.decrypt(payload, slot_ts + offset,
                                        seen_slots=self._seen_slots)
            if result is not None:
                plaintext = result
                break

        if plaintext is None:
            return  # not for us, or corrupted — discard silently

        peer = self.peer_name or "unknown"
        label = "file" if pkt_type == PKT_FILE else "message"

        with self._lock:
            self._received_messages.append((peer, plaintext))

        if self.on_message:
            self.on_message(peer, plaintext)


# =============================================================================
# 6. DEMOS
# =============================================================================

W = 70

def _banner(title):
    print(f"\n{'='*W}")
    print(f"  {title}")
    print(f"{'='*W}\n")

def _section(title):
    print(f"\n{'─'*W}")
    print(f"  {title}")
    print(f"{'─'*W}")

def _ok(msg):
    print(f"  [OK] {msg}")

def _kv(key, value):
    print(f"  {key:.<40s} {value}")


def demo_shared_folder():
    """
    Demo: Two nodes communicate via a shared temp directory.
    Fully automatic key exchange and message delivery.
    """
    import tempfile

    _banner("TRANSPORT DEMO — Shared Folder (Dead Drop)")

    # Create temp shared folder
    tmpdir = tempfile.mkdtemp(prefix="babel-deaddrop-")
    print(f"  Shared folder: {tmpdir}\n")

    received_by_bob = []
    received_by_alice = []

    def bob_callback(peer, msg):
        received_by_bob.append((peer, msg))
        print(f"    [Bob received] from {peer}: {msg.decode()}")

    def alice_callback(peer, msg):
        received_by_alice.append((peer, msg))
        print(f"    [Alice received] from {peer}: {msg.decode()}")

    # ── Step 1: Create nodes ──
    _section("Step 1 — Create nodes with SharedFolderTransport")

    transport_alice = SharedFolderTransport(tmpdir, delete_after_read=False)
    transport_bob = SharedFolderTransport(tmpdir, delete_after_read=False)

    alice = Node("alice", transport_alice, on_message=alice_callback)
    bob = Node("bob", transport_bob, on_message=bob_callback)

    _kv("Alice backend", alice.backend)
    _kv("Bob backend", bob.backend)

    # ── Step 2: Start nodes (auto key exchange) ──
    _section("Step 2 — Start nodes (auto key exchange)")

    alice.start()
    print("  Alice started — public key announced")

    bob.start()
    print("  Bob started — public key announced")

    # Wait for both to complete key exchange
    alice.key_established.wait(timeout=5)
    bob.key_established.wait(timeout=5)

    assert alice.key_established.is_set(), "Alice key exchange failed"
    assert bob.key_established.is_set(), "Bob key exchange failed"
    _ok("Key exchange completed automatically")
    _kv("Alice peer", alice.peer_name)
    _kv("Bob peer", bob.peer_name)

    # ── Step 3: Alice sends messages ──
    _section("Step 3 — Alice sends 3 encrypted messages")

    messages = [
        b"Message 1: Rendez-vous at noon",
        b"Message 2: Bring the documents",
        b"Message 3: Use the back entrance",
    ]

    for msg in messages:
        ok = alice.send_message(msg)
        assert ok, f"Failed to send: {msg}"
        print(f"  Sent: {msg.decode()}")
        time.sleep(0.2)  # small delay for file system

    # ── Step 4: Wait for Bob to receive ──
    _section("Step 4 — Bob receives messages")

    deadline = time.time() + 10
    while len(received_by_bob) < 3 and time.time() < deadline:
        time.sleep(0.3)

    assert len(received_by_bob) == 3, \
        f"Bob received {len(received_by_bob)}/3 messages"
    _ok(f"Bob received all {len(received_by_bob)} messages")

    # Verify content
    for i, (peer, plaintext) in enumerate(received_by_bob):
        assert plaintext == messages[i], f"Message {i} mismatch"
    _ok("All message contents verified")

    # ── Step 5: Bob replies ──
    _section("Step 5 — Bob replies to Alice")

    reply = b"Acknowledged. See you there."
    bob.send_message(reply)
    print(f"  Bob sent: {reply.decode()}")

    deadline = time.time() + 5
    while len(received_by_alice) < 1 and time.time() < deadline:
        time.sleep(0.3)

    assert len(received_by_alice) == 1
    assert received_by_alice[0][1] == reply
    _ok(f"Alice received reply: {received_by_alice[0][1].decode()}")

    # ── Step 6: What an observer sees ──
    _section("Step 6 — What an observer sees in the shared folder")

    files = [f for f in os.listdir(tmpdir) if f.endswith(".bin")]
    print(f"  Files in folder: {len(files)}")
    for fname in sorted(files)[:6]:
        path = os.path.join(tmpdir, fname)
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            preview = f.read(16).hex()
        print(f"    {fname}  ({size} bytes)  {preview}...")

    print()
    print("  Observer analysis:")
    print("    - Random hex filenames (.bin) — looks like cache/temp artifacts")
    print("    - File contents are pure noise — no headers, no protocol signatures")
    print("    - Files appear/disappear — normal cloud sync behavior")
    print("    - No network traffic generated — purely filesystem-based")

    # ── Cleanup ──
    alice.stop()
    bob.stop()

    _banner("SHARED FOLDER DEMO — PASSED")


def demo_socket():
    """
    Demo: Two nodes communicate via direct TCP connection.
    Fully automatic key exchange and message delivery.
    """
    _banner("TRANSPORT DEMO — TCP Socket (P2P)")

    received_by_bob = []
    received_by_alice = []

    def bob_callback(peer, msg):
        received_by_bob.append((peer, msg))
        print(f"    [Bob received] from {peer}: {msg.decode()}")

    def alice_callback(peer, msg):
        received_by_alice.append((peer, msg))
        print(f"    [Alice received] from {peer}: {msg.decode()}")

    # ── Step 1: Create transports ──
    _section("Step 1 — Create TCP transports")

    transport_alice = SocketTransport(mode="server", host="127.0.0.1", port=0)
    transport_bob_placeholder = None  # need server port first

    # ── Step 2: Start server, then client ──
    _section("Step 2 — Start server (Alice), then client (Bob)")

    # Alice starts server in a thread (start() blocks until accept)
    alice_node = Node("alice", transport_alice, on_message=alice_callback)

    server_ready = threading.Event()
    alice_started = threading.Event()

    def start_alice():
        # Bind and listen first so we can get the port
        transport_alice._running = True
        transport_alice._server_sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM)
        transport_alice._server_sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        transport_alice._server_sock.bind(
            (transport_alice.host, transport_alice.port))
        transport_alice.actual_port = \
            transport_alice._server_sock.getsockname()[1]
        transport_alice._server_sock.listen(1)
        transport_alice._server_sock.settimeout(30)
        server_ready.set()  # signal that port is known

        # Accept (blocks)
        conn, _addr = transport_alice._server_sock.accept()
        transport_alice._conn = conn
        transport_alice._conn.settimeout(1.0)
        transport_alice._recv_thread = threading.Thread(
            target=transport_alice._recv_loop, daemon=True)
        transport_alice._recv_thread.start()

        # Now do the Node-level start (announce key, start polling)
        # Announce key
        announce = _encode_key_announce(
            alice_node.name, alice_node.party.public_key)
        pkt = make_packet(PKT_KEY_ANNOUNCE, announce)
        transport_alice.send(pkt)

        alice_node._running = True
        alice_node._poll_thread = threading.Thread(
            target=alice_node._poll_loop, daemon=True)
        alice_node._poll_thread.start()
        alice_started.set()

    alice_thread = threading.Thread(target=start_alice, daemon=True)
    alice_thread.start()

    # Wait for server to bind
    server_ready.wait(timeout=5)
    port = transport_alice.actual_port
    print(f"  Alice listening on 127.0.0.1:{port}")

    # Bob connects as client
    transport_bob = SocketTransport(
        mode="client", peer_host="127.0.0.1", peer_port=port)
    bob_node = Node("bob", transport_bob, on_message=bob_callback)
    bob_node.start()
    print(f"  Bob connected to 127.0.0.1:{port}")

    # Wait for Alice's node to fully start
    alice_started.wait(timeout=5)

    # Wait for key exchange
    alice_node.key_established.wait(timeout=10)
    bob_node.key_established.wait(timeout=10)

    assert alice_node.key_established.is_set(), "Alice key exchange failed"
    assert bob_node.key_established.is_set(), "Bob key exchange failed"
    _ok("Key exchange completed automatically over TCP")
    _kv("Alice peer", alice_node.peer_name)
    _kv("Bob peer", bob_node.peer_name)

    # ── Step 3: Exchange messages ──
    _section("Step 3 — Exchange encrypted messages over TCP")

    messages = [
        b"TCP message 1: Secure channel established",
        b"TCP message 2: Coordinates received",
        b"TCP message 3: Proceeding to extraction",
    ]

    for msg in messages:
        ok = alice_node.send_message(msg)
        assert ok, f"Failed to send: {msg}"
        print(f"  Alice sent: {msg.decode()}")
        time.sleep(0.1)

    # Wait for Bob to receive
    deadline = time.time() + 10
    while len(received_by_bob) < 3 and time.time() < deadline:
        time.sleep(0.3)

    assert len(received_by_bob) == 3, \
        f"Bob received {len(received_by_bob)}/3 messages"
    _ok(f"Bob received all {len(received_by_bob)} messages")

    for i, (peer, plaintext) in enumerate(received_by_bob):
        assert plaintext == messages[i], f"Message {i} mismatch"
    _ok("All message contents verified")

    # Bob replies
    _section("Step 4 — Bob replies over TCP")

    reply = b"Copy that. Extraction confirmed."
    bob_node.send_message(reply)
    print(f"  Bob sent: {reply.decode()}")

    deadline = time.time() + 5
    while len(received_by_alice) < 1 and time.time() < deadline:
        time.sleep(0.3)

    assert len(received_by_alice) == 1
    assert received_by_alice[0][1] == reply
    _ok(f"Alice received: {received_by_alice[0][1].decode()}")

    # ── Network perspective ──
    _section("Step 5 — What a network observer sees")
    print("  Observer analysis:")
    print("    - TCP connection to localhost (or any IP:port)")
    print("    - All payload bytes are pure noise — no protocol fingerprint")
    print("    - Length-prefixed frames — similar to VPN/obfs4 traffic")
    print("    - No TLS handshake, no HTTP headers, no identifiable protocol")
    print("    - Content is OTP-encrypted — computationally indistinguishable")
    print("      from random")

    # ── Cleanup ──
    alice_node.stop()
    bob_node.stop()

    _banner("TCP SOCKET DEMO — PASSED")


# =============================================================================
# 7. MAIN — Demo selector
# =============================================================================

def main():
    _banner("BABEL ORACLE — AUTOMATIC TRANSPORT LAYER")
    print("  Available demos:")
    print("    1. Shared Folder (dead drop via synced directory)")
    print("    2. TCP Socket (direct P2P connection)")
    print("    3. Both")
    print()

    choice = input("  Select demo [1/2/3]: ").strip()

    if choice == "1":
        demo_shared_folder()
    elif choice == "2":
        demo_socket()
    elif choice == "3":
        demo_shared_folder()
        demo_socket()
    else:
        print("  Invalid choice. Running both demos.\n")
        demo_shared_folder()
        demo_socket()

    print("\n  All transport demos completed successfully.\n")


if __name__ == "__main__":
    main()
