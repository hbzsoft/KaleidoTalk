# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


# padding.py
"""Cover Traffic module

Provides fixed-length packet encapsulation/decapsulation, random jitter intervals, and fragmentation/reassembly.
Used to obfuscate communication metadata (packet size and send frequency) against traffic analysis.

Protocol format (fixed PACKET_SIZE bytes):
  [0:1]   type     - 1 byte: 0x01=real data, 0x02=fragment first, 0x03=fragment mid, 0x04=fragment last, 0x00=padding
    [1:3]   length   - 2-byte big-endian: real data length (excluding padding)
  [3:5]   seq      - 2-byte big-endian: fragment sequence number (valid only for fragmented packets)
  [5:7]   total    - 2-byte big-endian: total fragment count (valid only for fragmented packets)
  [7:N]   payload  - real data
    [N:END] padding  - random padding bytes (total length = PACKET_SIZE)
"""

import os
import struct
import time
import random
import threading

# ----------------------------------------------------------------------
# Protocol constants
PACKET_SIZE = 2048          # Fixed packet size in bytes
HEADER_SIZE = 7             # Header size in bytes (type + length + seq + total)
MAX_PAYLOAD = PACKET_SIZE - HEADER_SIZE  # Maximum payload per packet

# Packet types
TYPE_PADDING = 0x00         # pure padding packet
TYPE_DATA = 0x01            # Complete data packet (no fragmentation)
TYPE_FRAGMENT_FIRST = 0x02   # Fragment: first piece
TYPE_FRAGMENT_MID = 0x03    # Fragment: middle piece
TYPE_FRAGMENT_LAST = 0x04   # Fragment: last piece

# Heartbeat parameters
BASE_INTERVAL = 5.0         # Base heartbeat interval (seconds)
JITTER_RATIO = 1.0 / 3.0   # Jitter range = ±BASE_INTERVAL * JITTER_RATIO


def next_interval():
    """Calculate next heartbeat interval (with random jitter)

    Returns:
        float: Wait time in seconds
    """
    jitter = BASE_INTERVAL * JITTER_RATIO
    return BASE_INTERVAL + random.uniform(-jitter, jitter)


def build_packet(data: bytes, packet_type: int = TYPE_DATA,
                 frag_seq: int = 0, frag_total: int = 0) -> bytes:
    """Build a fixed-length data packet

    Args:
        data: Real payload (not exceeding MAX_PAYLOAD bytes)
        packet_type: Packet types
        frag_seq: Fragment sequence number (valid only for fragmentation)
        frag_total: Total fragment count (valid only for fragmentation)

    Returns:
        bytes: Data packet of exactly PACKET_SIZE length

    Raises:
        ValueError: Data exceeds MAX_PAYLOAD
    """
    if len(data) > MAX_PAYLOAD:
        raise ValueError(f"Data {len(data)} bytes exceeds single packet limit {MAX_PAYLOAD}")

    header = struct.pack('>BHHH', packet_type, len(data), frag_seq, frag_total)
    payload = header + data

    # Pad to fixed length using random bytes.
    padding_len = PACKET_SIZE - len(payload)
    padding = os.urandom(padding_len) if padding_len > 0 else b''

    return payload + padding


def parse_packet(raw: bytes):
    """Parse a fixed-length data packet

    Args:
        raw: Raw data packet (length should be PACKET_SIZE)

    Returns:
        tuple: (packet_type, data, frag_seq, frag_total)
            - packet_type: Packet types（int）
            - data: Real payload (bytes)
            - frag_seq: Fragment sequence number (int)
            - frag_total: Total fragment count (int)

    Raises:
        ValueError: Invalid packet length or header parsing failed
    """
    if len(raw) != PACKET_SIZE:
        raise ValueError(f"Packet length {len(raw)} not equal to expected {PACKET_SIZE}")

    packet_type, length, frag_seq, frag_total = struct.unpack('>BHHH', raw[:HEADER_SIZE])

    if packet_type == TYPE_PADDING:
        return packet_type, b'', frag_seq, frag_total

    if length > MAX_PAYLOAD or length + HEADER_SIZE > PACKET_SIZE:
        raise ValueError(f"Payload length {length} is invalid")

    data = raw[HEADER_SIZE:HEADER_SIZE + length]
    return packet_type, data, frag_seq, frag_total


def fragment_data(data: bytes) -> list:
    """Fragment large data into multiple fixed-length packets

    Args:
        data: Raw data to fragment

    Returns:
        list[bytes]: List of fixed-length packets
    """
    if len(data) <= MAX_PAYLOAD:
        return [build_packet(data, TYPE_DATA)]

    total = (len(data) + MAX_PAYLOAD - 1) // MAX_PAYLOAD
    fragments = []

    for i in range(total):
        start = i * MAX_PAYLOAD
        end = min(start + MAX_PAYLOAD, len(data))
        chunk = data[start:end]

        if i == 0:
            ptype = TYPE_FRAGMENT_FIRST
        elif i == total - 1:
            ptype = TYPE_FRAGMENT_LAST
        else:
            ptype = TYPE_FRAGMENT_MID

        fragments.append(build_packet(chunk, ptype, frag_seq=i, frag_total=total))

    return fragments


class FragmentReassembler:
    """Fragment reassembler

    Used on receiver side to reassemble multiple fragments into complete data.
    Thread-safe.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._buffers = {}  # key -> {'total': int, 'chunks': dict, 'timer': float}

    def feed(self, packet_type: int, data: bytes, frag_seq: int, frag_total: int):
        """Feed a packet and attempt reassembly

        Args:
            packet_type: Packet types
            data: Payload
            frag_seq: fragment sequence number
            frag_total: Total fragment count

        Returns:
            bytes or None: Complete reassembled data, or None (not complete yet)
        """
        # Return non-fragmented packets directly
        if packet_type == TYPE_DATA:
            return data
        if packet_type == TYPE_PADDING:
            return None

        if frag_total <= 0 or frag_total > 1000:
            return None  # Defend against abnormal values

        with self._lock:
            # Use (frag_total, frag_seq range) as key.
            # Simplification: use frag_total from first packet as identifier.
            # A stricter approach needs stream ID, but current protocol allows one reassembly per connection.
            key = frag_total  # Simplified key

            if key not in self._buffers:
                self._buffers[key] = {
                    'total': frag_total,
                    'chunks': {},
                    'timer': time.time(),
                }

            buf = self._buffers[key]
            buf['chunks'][frag_seq] = data

            # Timeout cleanup (30 seconds)
            if time.time() - buf['timer'] > 30:
                del self._buffers[key]
                return None

            # Check whether all fragments have arrived
            if len(buf['chunks']) == buf['total']:
                result = b''
                for i in range(buf['total']):
                    result += buf['chunks'][i]
                del self._buffers[key]
                return result

            return None

    def reset(self):
        """Clear all buffers"""
        with self._lock:
            self._buffers.clear()


def build_padding_packet() -> bytes:
    """Build a pure padding packet (cover traffic)."""
    return build_packet(b'', TYPE_PADDING)


class PaddedSender:
    """Fixed-length packet sender

    Send fixed-length packets on underlying socket.
    """

    @staticmethod
    def send(sock, data: bytes):
        """Send a fixed-length packet

        Args:
            sock: Connected socket
            data: Raw data to send (auto-fragmented)
        """
        packets = fragment_data(data)
        for pkt in packets:
            sock.sendall(pkt)

    @staticmethod
    def send_padding(sock):
        """Send a pure padding packet."""
        sock.sendall(build_padding_packet())


class PaddedReceiver:
    """Fixed-length packet receiver

    Receive fixed-length packets from underlying socket and reassemble them.
    """

    def __init__(self):
        self._reassembler = FragmentReassembler()
        self._recv_buf = b''

    def recv(self, sock) -> bytes:
        """Receive a complete logical message (may span multiple fixed-length packets)

        Args:
            sock: Connected socket

        Returns:
            bytes: Complete message data

        Raises:
            ValueError: Invalid data format
            ConnectionError: Connection closed
        """
        while True:
            # Try extracting a full packet from buffer
            while len(self._recv_buf) >= PACKET_SIZE:
                raw = self._recv_buf[:PACKET_SIZE]
                self._recv_buf = self._recv_buf[PACKET_SIZE:]

                ptype, data, frag_seq, frag_total = parse_packet(raw)

                if ptype == TYPE_PADDING:
                    continue  # Padding packet, skip.

                result = self._reassembler.feed(ptype, data, frag_seq, frag_total)
                if result is not None:
                    return result

            # Need more data
            try:
                chunk = sock.recv(PACKET_SIZE * 4)  # Read multiple packets at once
                if not chunk:
                    raise ConnectionError("Connection closed")
                self._recv_buf += chunk
            except (ConnectionError, OSError):
                raise

    def reset(self):
        """Reset receiver state"""
        self._reassembler.reset()
        self._recv_buf = b''

