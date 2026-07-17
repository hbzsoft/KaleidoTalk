# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


# server.py - server entrypoint (integrated cover traffic)
import socket
import threading
import json
import os
import struct
import hashlib
import time
import logging
import ssl
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from src.common.padding import (
    PaddedSender,
    PaddedReceiver,
    build_padding_packet,
    next_interval,
    PACKET_SIZE,
)
from src.common.crypto_utils import ServerCrypto
from src.server.server_storage import (
    locks as storage_locks,
    USERS_FILE,
    KEYS_FILE,
    INVITES_FILE,
    BANS_FILE,
    load_users,
    save_users,
    load_user_keys,
    save_user_keys,
    load_invites,
    save_invites,
    load_bans_file,
    save_bans_file,
    require_invite_code,
)
from src.server.server_session import (
    locks,
    clients,
    logged_in_users,
    ip_ban_list,
    user_ban_list,
    ip_attempts,
    register_socket,
    unregister_socket,
)
from src.server.server_commands import handle_message
from src.server.config import load_config

# ----------------------------------------------------------------------
# Logging configuration (level set after config is loaded)
_logger = logging.getLogger(__name__)


def _setup_logging(level_name):
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler('server.log', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )


logger = logging.getLogger(__name__)
# ----------------------------------------------------------------------
# TLS context (global)
TLS_CONTEXT = None
TLS_CERT_FILE = 'server_keys/server.crt'
TLS_KEY_FILE = 'server_keys/server.key'


def generate_self_signed_cert(cert_file=TLS_CERT_FILE, key_file=TLS_KEY_FILE):
    """Generate a self-signed certificate and RSA key, then save to files."""
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return

    os.makedirs(os.path.dirname(cert_file), exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KaleidoTalk"),
        x509.NameAttribute(NameOID.COMMON_NAME, "KaleidoTalk Server"),
    ])

    not_before = datetime.now(timezone.utc)
    not_after = not_before + timedelta(days=365 * 10)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    logger.info(f"Generated TLS certificate and key: {cert_file}, {key_file}")


def create_tls_context():
    """Create and return server-side TLS context."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)
    context.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, 'TLSVersion'):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    return context


# ----------------------------------------------------------------------
# Cover traffic: server heartbeat thread
def _heartbeat_sender(sock, stop_event, send_lock):
    """Server heartbeat sender thread; periodically sends padding packets."""
    try:
        while not stop_event.is_set():
            stop_event.wait(next_interval())
            if stop_event.is_set():
                break
            try:
                with send_lock:
                    sock.sendall(build_padding_packet())
            except Exception:
                break
    except Exception:
        pass


# ----------------------------------------------------------------------
# PaddedSocket wrapper (module-level to keep object identity stable)
class PaddedSocket:
    """Wrap socket output from send_msg and forward responses as fixed-size packets.

    Important: each client connection must reuse a single PaddedSocket instance,
    because server_session stores clients/logged_in_users using this object as key.
    If a new wrapper is created per message, unregister_socket cannot find entries,
    leaving users incorrectly marked as online after logout/disconnect.
    """
    def __init__(self, inner_sock, lock):
        self._inner = inner_sock
        self._lock = lock
        self._send_buffer = b''

    def sendall(self, data):
        # send_msg format: [4-byte length][JSON frame bytes]
        # Parse frames, extract `data`, then send using fixed-size packets.
        self._send_buffer += data

        # Try to parse buffered frames.
        while len(self._send_buffer) >= 4:
            length = struct.unpack('>I', self._send_buffer[:4])[0]
            if length > 10 * 1024 * 1024:
                # Abnormal length; clear buffer.
                self._send_buffer = b''
                break
            if len(self._send_buffer) < 4 + length:
                # Incomplete frame; wait for more data.
                break

            # Extract frame bytes.
            frame_data = self._send_buffer[4:4+length]
            self._send_buffer = self._send_buffer[4+length:]

            try:
                frame = json.loads(frame_data.decode('utf-8'))
                # Extract response payload.
                response = frame.get('data', frame)
                # Send response as fixed-size packet.
                response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
                with self._lock:
                    PaddedSender.send(self._inner, response_bytes)
            except Exception:
                # Fallback: send original frame bytes.
                with self._lock:
                    PaddedSender.send(self._inner, frame_data)

    def recv(self, bufsize):
        return self._inner.recv(bufsize)

    def settimeout(self, timeout):
        self._inner.settimeout(timeout)

    def getpeername(self):
        return self._inner.getpeername()

    def close(self):
        self._inner.close()

    def fileno(self):
        return self._inner.fileno()


def handle_message_padded(padded_sock, addr, payload):
    """Handle command and send response via fixed-size packet transport."""
    handle_message(padded_sock, addr, payload)


# ----------------------------------------------------------------------
# Client handler thread (with integrated cover traffic)
def handle_client(raw_sock, addr):
    """Handle a single client connection.

    Flow:
    1. TLS handshake
    2. Send welcome message (fixed-size packet)
    3. Start heartbeat thread (padding packets)
    4. Main loop: receive fixed-size packet -> unwrap -> process -> wrap response
    """
    global TLS_CONTEXT
    sock = None
    stop_event = threading.Event()
    send_lock = threading.Lock()  # Protect concurrent socket writes.

    try:
        sock = TLS_CONTEXT.wrap_socket(raw_sock, server_side=True)
    except Exception as e:
        logger.error(f"TLS handshake failed ({addr}): {e}")
        raw_sock.close()
        return

    logger.info(f"New TLS connection (cover traffic): {addr}")
    sock.settimeout(30.0)

    # Create fixed-size packet receiver.
    receiver = PaddedReceiver()

    # Send welcome message through fixed-size packet transport.
    try:
        welcome = {
            'type': 'welcome',
            'data': {
                'message': 'Welcome to KaleidoTalk V3.0',
                'server_time': datetime.now(timezone.utc).isoformat()
            }
        }
        welcome_bytes = json.dumps(welcome, ensure_ascii=False).encode('utf-8')
        with send_lock:
            PaddedSender.send(sock, welcome_bytes)
    except Exception:
        sock.close()
        return

    # Start heartbeat thread for cover traffic.
    heartbeat = threading.Thread(
        target=_heartbeat_sender,
        args=(sock, stop_event, send_lock),
        daemon=True
    )
    heartbeat.start()

    # Create one PaddedSocket wrapper and reuse for this entire connection.
    # This is essential because server_session uses it as a dictionary key.
    padded_sock = PaddedSocket(sock, send_lock)

    # Main message loop.
    while True:
        try:
            # Receive fixed-size packets and reassemble full message.
            raw = receiver.recv(sock)
            if not raw:
                break

            # Parse JSON payload.
            try:
                payload = json.loads(raw.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue

            # Process command using the same padded_sock instance.
            handle_message_padded(padded_sock, addr, payload)

        except ConnectionError:
            break
        except socket.timeout:
            # No special timeout handling; heartbeat keeps traffic shape.
            continue
        except Exception as e:
            logger.error(f"Error while processing message ({addr}): {e}")
            break

    # Cleanup (same padded_sock ensures unregister works correctly).
    stop_event.set()
    unregister_socket(padded_sock)
    try:
        sock.close()
    except Exception:
        pass
    logger.info(f"Connection closed: {addr}")


# ----------------------------------------------------------------------
# Main function
def start_server():
    global TLS_CONTEXT, PACKET_SIZE

    # Load configuration.
    config = load_config()
    _setup_logging(config.get("log_level", "INFO"))
    logger = logging.getLogger(__name__)

    host = config.get("host", "0.0.0.0")
    port = config.get("port", 5555)
    PACKET_SIZE = config.get("max_packet_size", 2048)
    interactive = config.get("interactive", True)

    # Initialize server keys.
    if interactive:
        try:
            admin_pw = input("Enter server admin password: ")
        except (EOFError, KeyboardInterrupt):
            print("\nStartup canceled")
            return
        try:
            ServerCrypto.initialize(admin_pw)
        except ValueError as e:
            print(f"Initialization failed: {e}")
            return
    else:
        try:
            ServerCrypto.initialize_noninteractive()
        except ValueError as e:
            print(f"Initialization failed: {e}")
            return

    # Generate/load TLS certificate.
    generate_self_signed_cert()
    TLS_CONTEXT = create_tls_context()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)

    logger.info(f"Server started (TLS + cover traffic) {host}:{port}")
    logger.info(f"Fixed packet size: {PACKET_SIZE} bytes")
    logger.info(f"Server ed25519 fingerprint: {hashlib.sha256(ServerCrypto.get_ed25519_pub_pem().encode()).hexdigest()}")
    logger.info(f"Invite-code registration enabled: {require_invite_code()}")

    # Initialize data files.
    if not os.path.exists(USERS_FILE):
        save_users({})
    if not os.path.exists(KEYS_FILE):
        save_user_keys({})
    if not os.path.exists(INVITES_FILE):
        save_invites({'require_invite': False, 'codes': {}})

    # Load ban lists.
    try:
        bans = load_bans_file()
        now_t = time.time()
        for ip, until in bans.get('ip_bans', {}).items():
            try:
                if not until or float(until) > now_t:
                    ip_ban_list[ip] = float(until)
            except Exception:
                continue
        user_ban_list.clear()
        for u in bans.get('user_bans', {}):
            user_ban_list[u] = True
        logger.info('Ban lists loaded')
    except Exception:
        logger.warning('Failed to load ban lists or file does not exist')

    try:
        while True:
            raw_sock, addr = server.accept()
            threading.Thread(target=handle_client, args=(raw_sock, addr), daemon=True).start()
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
    finally:
        server.close()


if __name__ == '__main__':
    print("KaleidoTalk Copyright (C) 2026 Bangze Han")
    print("This program comes with ABSOLUTELY NO WARRANTY.")
    print("This is free software, and you are welcome to redistribute it")
    print("under the terms of the GNU General Public License version 3 or later.")
    print()
    print("Version 3.0")
    start_server()
