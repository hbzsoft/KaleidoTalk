# chat_client.py
# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


# chat_client.py
import socket
import threading
import json
import os
import time
import re
import base64
import hashlib
import hmac
import secrets
import ssl
import ctypes
from datetime import datetime
from src.common.network import set_socket_time_offset, get_socket_time_offset
from src.common.padding import (
    PaddedSender,
    PaddedReceiver,
    build_padding_packet,
    next_interval,
    PACKET_SIZE,
)
from src.common.crypto_utils import (
    IdentityKeyManager,
    ExchangeKeyManager,
    PasswordManager,
    MessageEncryptorV2,
    ServerCrypto,
    FingerprintWords,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519

# ----------------------------------------------------------------------
# Window flashing (Windows)
FLASHW_STOP = 0
FLASHW_CAPTION = 0x00000001
FLASHW_TRAY = 0x00000002
FLASHW_ALL = FLASHW_CAPTION | FLASHW_TRAY
FLASHW_TIMER = 0x00000004
FLASHW_TIMERNOFG = 0x0000000C

class FLASHWINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint),
        ("hwnd", ctypes.c_void_p),
        ("dwFlags", ctypes.c_uint),
        ("uCount", ctypes.c_uint),
        ("dwTimeout", ctypes.c_uint),
    ]
# ----------------------------------------------------------------------

class ChatClient:
    """
    Client core logic: connection, login, registration, message sending, key management, trust database
    """
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.sock = None
        self.running = False
        self.username = None
        self.callback = None
        self.cert_verify_callback = None      # For TLS certificate confirmation popup
        self.session_id = None
        self.session_key = None
        self.token = None
        self._auth_sequence = 0

        # Identity keys (Ed25519)
        self.id_priv = None
        self.id_pub = None
        # Key exchange keys (X25519)
        self.x_priv = None
        self.x_pub = None

        # Server public keys
        self.server_ed25519_pub = None
        self.server_x25519_pub = None
        self.require_invite_for_register = None

        # User public key cache
        self.user_pubkeys = {}  # username -> {'ed25519': ..., 'x25519': ...}

        # Key rotation support
        self.x25519_privates = {}  # key_id -> priv_key_object (my own keys)
        self.x25519_publics = {}   # key_id -> pub_hex (local cache)
        self.current_key_id = None # latest key ID
        self.x25519_keys_info = [] # [{id, pub_hex, created_at}] my own key list
        self.recovery_priv = None  # Ed25519 recovery key for account freeze

        # Trust database
        self._trust_lock = threading.Lock()
        self._hmac_key = self._load_or_create_hmac_key()
        self.trust_db = self._load_trust_db()

        # Pending message cache
        self.pending_messages = {}  # username -> list of encrypted payloads
        self.pending_msg_lock = threading.Lock()
        self.pending_outgoing_messages = {}  # username -> list of plaintext messages waiting for pubkey
        self.pending_outgoing_lock = threading.Lock()
        self.pending_verifications = set()
        self.pending_verifications_lock = threading.Lock()
        self.pending_manual_verifications = set()
        self.pending_manual_verifications_lock = threading.Lock()

        # Temporary state for registration/login
        self.last_password = None
        self.pending_login_user = None
        self.local_key_loaded = False
        self._color_palette = [
            '#1f77b4',
            '#2ca02c',
            '#d62728',
            '#9467bd',
            '#ff7f0e',
            '#17becf',
            '#8c564b',
            '#e377c2',
            '#7f7f7f',
            '#bcbd22',
            '#17a2b8',
            '#5f27cd',
        ]
        self._name_colors = {}

        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread = None
        self._send_lock = threading.Lock()  # Protect socket concurrent writes
        self._last_timestamp = 0  # Last authentication request timestamp; ensure monotonic increase

    # ------------------------------------------------------------------
    # Traffic masking: heartbeat thread
    def _heartbeat_loop(self):
        """Client heartbeat thread: periodically sends padding packets to maintain traffic masking"""
        try:
            while not self._heartbeat_stop.is_set():
                self._heartbeat_stop.wait(next_interval())
                if self._heartbeat_stop.is_set():
                    break
                try:
                    if self.sock:
                        with self._send_lock:
                            self.sock.sendall(build_padding_packet())
                except Exception:
                    break
        except Exception:
            pass

    def _start_heartbeat(self):
        """Start heartbeat thread"""
        self._heartbeat_stop.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True
        )
        self._heartbeat_thread.start()

    def _stop_heartbeat(self):
        """Stop heartbeat thread"""
        self._heartbeat_stop.set()

    # ------------------------------------------------------------------
    # Local trust database
    def _get_trust_db_path(self):
        if not os.path.exists('local_keys'):
            os.makedirs('local_keys')
        return 'local_keys/trusted_fingerprints.json'

    def _get_hmac_key_path(self):
        return 'local_keys/.hmac_key'

    def _load_or_create_hmac_key(self):
        if not os.path.exists('local_keys'):
            os.makedirs('local_keys')
        path = self._get_hmac_key_path()
        if os.path.exists(path):
            with open(path, 'rb') as f:
                return f.read()
        key = os.urandom(32)
        with open(path, 'wb') as f:
            f.write(key)
        return key

    def _load_trust_db(self):
        path = self._get_trust_db_path()
        if not os.path.exists(path):
            return {'servers': {}, 'users': {}}
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = f.read()
            # Verify HMAC
            hmac_path = path + '.hmac'
            if not os.path.exists(hmac_path):
                raise ValueError("Missing HMAC signature file")
            with open(hmac_path, 'rb') as f:
                stored_hmac = f.read()
            calc = hmac.new(self._hmac_key, data.encode('utf-8'), 'sha256').digest()
            if not hmac.compare_digest(calc, stored_hmac):
                raise ValueError("Trust database integrity check failed, may have been tampered")
            db = json.loads(data)
            # Migrate old servers string format to object format
            for endpoint, val in db.get('servers', {}).items():
                if isinstance(val, str):
                    db['servers'][endpoint] = {'ed25519': val}
            return db
        except Exception as e:
            if self.callback:
                self.callback('WARNING', f"Trust database load failed: {e}, all trust relationships reset")
            return {'servers': {}, 'users': {}}

    def _save_trust_db(self):
        path = self._get_trust_db_path()
        with self._trust_lock:
            data = json.dumps(self.trust_db, indent=2, ensure_ascii=False)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(data)
            hmac_val = hmac.new(self._hmac_key, data.encode('utf-8'), 'sha256').digest()
            with open(path + '.hmac', 'wb') as f:
                f.write(hmac_val)

    def _key_fingerprint(self, pub_key_pem):
        """Ed25519 public key fingerprint (SHA256 of raw bytes)"""
        pub = IdentityKeyManager.deserialize_public_key(pub_key_pem)
        raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return hashlib.sha256(raw).hexdigest()

    def _fingerprint_from_bytes(self, pem_str):
        return hashlib.sha256(pem_str.encode('utf-8')).hexdigest()

    def _canonical_json(self, data):
        return json.dumps(data or {}, ensure_ascii=False, sort_keys=True, separators=(',', ':'))

    def _build_authenticated_payload(self, cmd, data=None):
        if not self.session_id or not self.session_key:
            raise ValueError('Session not established')
        payload_data = data or {}
        self._auth_sequence += 1
        seq = self._auth_sequence
        timestamp = int(time.time() * 1000) + get_socket_time_offset(self.sock)
        # Ensure timestamps are monotonically increasing to avoid replay false positives for rapid requests
        if timestamp <= self._last_timestamp:
            timestamp = self._last_timestamp + 1
        self._last_timestamp = timestamp
        message = f'{self.session_id}{seq}{timestamp}{self._canonical_json(payload_data)}'.encode('utf-8')
        signature = hmac.new(self.session_key, message, hashlib.sha256).hexdigest()
        return {
            'cmd': cmd,
            'session_id': self.session_id,
            'seq': seq,
            'timestamp': timestamp,
            'hmac': signature,
            'data': payload_data,
        }

    def _decrypt_session_key(self, encrypted_session_key):
        eph_pub_bytes = base64.b64decode(encrypted_session_key['eph_pub'])
        ct = base64.b64decode(encrypted_session_key['ct'])
        tag = base64.b64decode(encrypted_session_key['tag'])
        nonce_b64 = encrypted_session_key.get('nonce')
        eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
        shared_secret = self.x_priv.exchange(eph_pub)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'kaleidotalk-session-key',
            backend=default_backend(),
        )
        aes_key = hkdf.derive(shared_secret)
        if nonce_b64:
            nonce = base64.b64decode(nonce_b64)
        else:
            hkdf_legacy = HKDF(
                algorithm=hashes.SHA256(),
                length=32 + 12,
                salt=None,
                info=b'kaleidotalk-session-key',
                backend=default_backend(),
            )
            legacy_km = hkdf_legacy.derive(shared_secret)
            nonce = legacy_km[32:44]
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    # ------------------------------------------------------------------
    # Connection and protocol communication
    def connect(self):
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(5)
            raw_sock.connect((self.host, self.port))

            # Establish TLS connection
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Manual fingerprint verification
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            tls_sock = context.wrap_socket(raw_sock, server_hostname=self.host)
            self.sock = tls_sock
            self.sock.settimeout(30.0)

            # Get certificate fingerprint and verify
            der_cert = self.sock.getpeercert(binary_form=True)
            tls_fingerprint = hashlib.sha256(der_cert).hexdigest()
            endpoint = f"{self.host}:{self.port}"

            # Check trust database
            server_trust = self.trust_db['servers'].get(endpoint)
            if server_trust is None:
                # First connection, prompt for confirmation
                if self.cert_verify_callback:
                    ok = self.cert_verify_callback(endpoint, tls_fingerprint)
                    if not ok:
                        self.sock.close()
                        self.sock = None
                        if self.callback:
                            self.callback('ERROR', 'TLS certificate rejected')
                        return False
                    # Trust
                    self.trust_db['servers'][endpoint] = {'tls': tls_fingerprint}
                    self._save_trust_db()
                else:
                    # Trust directly when no callback (avoid blocking)
                    self.trust_db['servers'][endpoint] = {'tls': tls_fingerprint}
                    self._save_trust_db()
            else:
                stored_tls = server_trust.get('tls')
                if stored_tls and stored_tls != tls_fingerprint:
                    self.sock.close()
                    self.sock = None
                    if self.callback:
                        self.callback('ERROR', 'Server TLS certificate fingerprint mismatch! Possible MITM attack')
                    return False
                elif not stored_tls:
                    # Only legacy ed25519 fingerprint found; add TLS fingerprint
                    server_trust['tls'] = tls_fingerprint
                    self._save_trust_db()

            self.running = True

            # Receive welcome message using fixed-size packets
            receiver = PaddedReceiver()
            try:
                welcome_bytes = receiver.recv(self.sock)
                welcome = json.loads(welcome_bytes.decode('utf-8'))
            except Exception as e:
                if self.callback:
                    self.callback('ERROR', f'Failed to receive welcome message: {e}')
                self.sock.close()
                self.sock = None
                return False

            if welcome.get('type') == 'welcome':
                server_time_text = welcome.get('data', {}).get('server_time')
                try:
                    server_time = datetime.fromisoformat(server_time_text.replace('Z', '+00:00'))
                    local_time = datetime.now(server_time.tzinfo) if server_time.tzinfo else datetime.now()
                    offset_ms = int((server_time.timestamp() - local_time.timestamp()) * 1000)
                    set_socket_time_offset(self.sock, offset_ms)
                except Exception:
                    pass
                if self.callback:
                    self.callback('SYS', welcome['data']['message'])

            # Start receiver thread (fixed-size packets)
            threading.Thread(target=self._recv_loop, daemon=True).start()

            # Start heartbeat thread (traffic masking)
            self._start_heartbeat()

            # Request server public keys
            self._send({'cmd': 'get_server_pubkey'})
            # Query registration policy
            self._send({'cmd': 'get_reg_policy'})
            return True

        except ssl.SSLError as e:
            if self.callback:
                self.callback('ERROR', f'TLS error: {e}')
            return False
        except socket.timeout:
            if self.callback:
                self.callback('ERROR', 'Connection timeout')
            return False
        except ConnectionRefusedError:
            if self.callback:
                self.callback('ERROR', 'Connection refused, server may not be running')
            return False
        except Exception as e:
            if self.callback:
                self.callback('ERROR', f'Connection failed: {e}')
            return False

    def _send(self, obj):
        if not self.sock:
            return False
        try:
            # Send using fixed-size packets (traffic masking)
            data = json.dumps(obj, ensure_ascii=False).encode('utf-8')
            with self._send_lock:
                PaddedSender.send(self.sock, data)
            return True
        except Exception as e:
            if self.callback:
                self.callback('ERROR', f'Send failed: {e}')
            return False

    def _recv_loop(self):
        receiver = PaddedReceiver()
        while self.running and self.sock:
            try:
                # Receive using fixed-size packets (traffic masking)
                raw = receiver.recv(self.sock)
                if not raw:
                    break
                try:
                    msg = json.loads(raw.decode('utf-8'))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if msg.get('type') == 'ping':
                    continue
                self._handle_msg(msg)
            except ConnectionError:
                break
            except socket.timeout:
                continue
            except OSError as e:
                if not self.running or not self.sock:
                    break
                if getattr(e, 'winerror', None) == 10038:
                    break
                if self.callback:
                    self.callback('ERROR', f'Receive error: {e}')
                break
            except Exception as e:
                if self.callback:
                    self.callback('ERROR', f'Receive error: {e}')
                break
        self._disconnect_cleanup()

    def _handle_msg(self, msg):
        """Dispatch server pushes or responses"""
        if 'type' in msg:
            if msg['type'] == 'msg':
                sender = msg['sender']
                payload = msg['payload']
                self._process_incoming_message(sender, payload)
            elif msg['type'] == 'force_logout':
                self._disconnect_cleanup()
                if self.callback:
                    self.callback('SYS', 'Your account logged in on another device; forced offline')
            return

        status = msg.get('status')
        cmd = msg.get('cmd')
        data = msg.get('data', {})

        if status == 'error':
            if cmd == 'pubkey':
                target = data.get('username')
                if target:
                    self._clear_pending_outgoing_messages(target)
                    with self.pending_manual_verifications_lock:
                        self.pending_manual_verifications.discard(target)
                    self._end_verification(target)
            if self.callback:
                self.callback('ERROR', msg.get('error') or data.get('error', 'Unknown error'))
            return

        if cmd == 'server_pubkey':
            self.server_ed25519_pub = IdentityKeyManager.deserialize_public_key(data['ed25519'])
            self.server_x25519_pub = ExchangeKeyManager.deserialize_public_key(data['x25519'])
            ServerCrypto._ed25519_pub = self.server_ed25519_pub
            ServerCrypto._x25519_pub = self.server_x25519_pub
            endpoint = f"{self.host}:{self.port}"
            ed_fingerprint = self._fingerprint_from_bytes(data['ed25519'])

            # Update Ed25519 fingerprint in trust database (TLS already verified)
            server_entry = self.trust_db['servers'].get(endpoint, {})
            server_entry['ed25519'] = ed_fingerprint
            self.trust_db['servers'][endpoint] = server_entry
            self._save_trust_db()

            if self.callback:
                self.callback('SYS', "Server public keys trusted via TLS certificate")
            if self.callback:
                self.callback('UPDATE_BUTTONS', None)

        elif cmd == 'reg_user':
            if self.callback:
                self.callback('SUCCESS', 'Registration successful, please log in')

        elif cmd == 'reg_policy':
            self.require_invite_for_register = bool(data.get('require_invite', False))

        elif cmd == 'login':
            if status == 'challenge':
                challenge = data['challenge']
                timestamp = data['timestamp']
                self._respond_challenge(challenge, timestamp)
                return

            if status != 'ok':
                if self.callback:
                    self.callback('ERROR', f'Unknown login response status: {status}')
                return

            self.session_id = data['session_id']
            self.token = None
            self.username = self.pending_login_user
            self.pending_login_user = None

            # Load my own x25519 key list
            self.x25519_keys_info = data.get('x25519_keys', [])
            encrypted_privates = data.get('encrypted_privates', {})
            if encrypted_privates and self.x25519_keys_info:
                try:
                    self.current_key_id = self.x25519_keys_info[0]['id']
                    first_enc = encrypted_privates.get(self.current_key_id)
                    if first_enc:
                        salt = bytes.fromhex(first_enc['salt'])
                        nonce = bytes.fromhex(first_enc['nonce'])
                        ct = bytes.fromhex(first_enc['ct'])
                        tag = bytes.fromhex(first_enc['tag'])
                        key = PasswordManager.derive_key(self.last_password, salt)
                        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
                        decryptor = cipher.decryptor()
                        plain = decryptor.update(ct) + decryptor.finalize()
                        keys = json.loads(plain.decode('utf-8'))
                        self.id_priv = IdentityKeyManager.deserialize_private_key(keys['ed25519_priv'])
                        self.x_priv = ExchangeKeyManager.deserialize_private_key(keys['x25519_priv'])
                        self.id_pub = self.id_priv.public_key()
                        self.x_pub = self.x_priv.public_key()
                        self.x25519_privates[self.current_key_id] = self.x_priv
                        self.x25519_publics[self.current_key_id] = ExchangeKeyManager.serialize_public_key(self.x_pub)
                    # Decrypt remaining keys
                    for kid, enc in encrypted_privates.items():
                        if kid == self.current_key_id:
                            continue
                        try:
                            salt2 = bytes.fromhex(enc['salt'])
                            nonce2 = bytes.fromhex(enc['nonce'])
                            ct2 = bytes.fromhex(enc['ct'])
                            tag2 = bytes.fromhex(enc['tag'])
                            key2 = PasswordManager.derive_key(self.last_password, salt2)
                            cipher2 = Cipher(algorithms.AES(key2), modes.GCM(nonce2, tag2), backend=default_backend())
                            decryptor2 = cipher2.decryptor()
                            plain2 = decryptor2.update(ct2) + decryptor2.finalize()
                            keys2 = json.loads(plain2.decode('utf-8'))
                            x_priv2 = ExchangeKeyManager.deserialize_private_key(keys2['x25519_priv'])
                            self.x25519_privates[kid] = x_priv2
                            self.x25519_publics[kid] = ExchangeKeyManager.serialize_public_key(x_priv2.public_key())
                        except Exception:
                            pass  # Skip keys from unknown devices
                except Exception as e:
                    if self.callback:
                        self.callback('ERROR', f"Failed to decrypt server private key: {e}")
                    self._disconnect_cleanup()
                    return
            else:
                try:
                    self.id_pub = IdentityKeyManager.deserialize_public_key(data['ed25519_pub'])
                    self.x_pub = ExchangeKeyManager.deserialize_public_key(data['x25519_pub'])
                except Exception as e:
                    if self.callback:
                        self.callback('ERROR', f"Failed to load public key: {e}")
                    self._disconnect_cleanup()
                    return

            try:
                self.session_key = self._decrypt_session_key(data['encrypted_session_key'])
            except Exception as e:
                if self.callback:
                    self.callback('ERROR', f'Failed to decrypt session key: {e}')
                self._disconnect_cleanup()
                return

            # In local mode, x25519_key info comes from login response
            self.x25519_keys_info = data.get('x25519_keys', [])
            if self.x25519_keys_info:
                self.current_key_id = self.x25519_keys_info[0]['id']
                self.x25519_privates[self.current_key_id] = self.x_priv
                self.x25519_publics[self.current_key_id] = ExchangeKeyManager.serialize_public_key(self.x_pub)
            self.user_pubkeys[self.username] = {
                'ed25519': self.id_pub,
                'x25519_keys': self.x25519_keys_info,
            }

            self.clear_password()
            if self.callback:
                self.callback('SUCCESS', f"Login successful ({self.username})")
            self._request_online_users()
            self.check_and_rotate()
            if self.callback:
                self.callback('UPDATE_BUTTONS', None)

        elif cmd == 'challenge_response' or status == 'challenge':
            challenge = data['challenge']
            timestamp = data['timestamp']
            self._respond_challenge(challenge, timestamp)

        elif cmd == 'pubkey':
            username = data['username']
            ed_pub = IdentityKeyManager.deserialize_public_key(data['ed25519_pub'])
            x_keys = data.get('x25519_pub_list', [])
            x_pub = ExchangeKeyManager.deserialize_public_key(x_keys[0]['pub_hex']) if x_keys else None
            self.user_pubkeys[username] = {'ed25519': ed_pub, 'x25519_keys': x_keys}
            if self.callback:
                self.callback('PUBKEY_OK', username)
            self._check_manual_verification(username)
            self._check_pending_outgoing_verification(username)
            self._check_pending_verification(username)

        elif cmd == 'users':
            users = data.get('users', [])
            if self.callback:
                self.callback('USERS', users)

        elif cmd == 'logout':
            self._clear_session_state()
            if self.callback:
                self.callback('UPDATE_BUTTONS', None)

        elif cmd == 'rotate_key':
            key_id = data.get('key_id', '')
            if self.callback:
                self.callback('SYS', f"Key rotation successful: {key_id}")

        elif cmd == 'get_my_keys':
            self.x25519_keys_info = data.get('x25519_keys', [])
            encrypted_privates = data.get('encrypted_privates', {})
            if self.x25519_keys_info:
                self.current_key_id = self.x25519_keys_info[0]['id']
            # Try to decrypt new keys with stored password
            if self.last_password and encrypted_privates:
                for kid, enc in encrypted_privates.items():
                    if kid in self.x25519_privates:
                        continue
                    try:
                        salt = bytes.fromhex(enc['salt'])
                        nonce = bytes.fromhex(enc['nonce'])
                        ct = bytes.fromhex(enc['ct'])
                        tag = bytes.fromhex(enc['tag'])
                        key = PasswordManager.derive_key(self.last_password, salt)
                        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
                        decryptor = cipher.decryptor()
                        plain = decryptor.update(ct) + decryptor.finalize()
                        keys = json.loads(plain.decode('utf-8'))
                        x_priv = ExchangeKeyManager.deserialize_private_key(keys['x25519_priv'])
                        self.x25519_privates[kid] = x_priv
                        self.x25519_publics[kid] = ExchangeKeyManager.serialize_public_key(x_priv.public_key())
                    except Exception:
                        pass

    # ------------------------------------------------------------------
    # Message encryption/decryption and cache
    def _process_incoming_message(self, sender, encrypted_payload):
        if sender not in self.user_pubkeys:
            with self.pending_msg_lock:
                self.pending_messages.setdefault(sender, []).append(encrypted_payload)
            self._request_public_key(sender)
            return

        if not self._is_user_trusted(sender):
            with self.pending_msg_lock:
                self.pending_messages.setdefault(sender, []).append(encrypted_payload)
            if self._begin_verification(sender):
                finger = self._fingerprint_from_bytes(
                    IdentityKeyManager.serialize_public_key(self.user_pubkeys[sender]['ed25519'])
                )
                self.callback('USER_VERIFY', {'username': sender, 'fingerprint': finger})
            return

        self._decrypt_and_display(sender, encrypted_payload)

    def _decrypt_and_display(self, sender, encrypted_payload):
        try:
            # Determine which private key to use (backward compat: no key_id = use current)
            payload_obj = json.loads(encrypted_payload) if isinstance(encrypted_payload, str) else encrypted_payload
            key_id = payload_obj.get('key_id') if isinstance(payload_obj, dict) else None
            if key_id and key_id in self.x25519_privates:
                my_priv = self.x25519_privates[key_id]
            else:
                my_priv = self.x_priv  # fallback: current (or only) key
            plain, err = MessageEncryptorV2.decrypt(
                encrypted_payload,
                my_priv,
                self.user_pubkeys[sender]['ed25519']
            )
            if plain:
                self.callback('MESSAGE', {'sender': sender, 'message': plain})
            else:
                self.callback('ERROR', f"Failed to decrypt message from  {sender} : {err}")
        except Exception as e:
            self.callback('ERROR', f"Decryption exception: {e}")

    def _queue_pending_outgoing_message(self, receiver, plaintext):
        with self.pending_outgoing_lock:
            self.pending_outgoing_messages.setdefault(receiver, []).append(plaintext)

    def _pop_pending_outgoing_messages(self, receiver):
        with self.pending_outgoing_lock:
            return self.pending_outgoing_messages.pop(receiver, [])

    def _clear_pending_outgoing_messages(self, receiver):
        with self.pending_outgoing_lock:
            self.pending_outgoing_messages.pop(receiver, None)

    def _flush_pending_outgoing_messages(self, receiver):
        msgs = self._pop_pending_outgoing_messages(receiver)
        for plaintext in msgs:
            self._send_encrypted_message(receiver, plaintext)

    def _send_encrypted_message(self, receiver, plaintext):
        receiver_info = self.user_pubkeys[receiver]
        # Get receiver's latest x25519 pub and its key_id
        x_keys = receiver_info.get('x25519_keys', [])
        if x_keys:
            receiver_x = ExchangeKeyManager.deserialize_public_key(x_keys[0]['pub_hex'])
            key_id = x_keys[0]['id']  # recipient's key_id so they know which priv to use
        else:
            receiver_x = receiver_info.get('x25519')
            key_id = None
        enc = MessageEncryptorV2.encrypt(
            plaintext,
            receiver_x,
            self.id_priv,
            key_id=key_id
        )
        return self._send(self._build_authenticated_payload('message', {
            'receiver': receiver,
            'payload': enc,
        }))

    def _check_pending_verification(self, username):
        with self.pending_manual_verifications_lock:
            if username in self.pending_manual_verifications:
                return
        with self.pending_msg_lock:
            has_pending = username in self.pending_messages and bool(self.pending_messages[username])

        if not has_pending:
            return

        if self._is_user_trusted(username):
            with self.pending_msg_lock:
                msgs = self.pending_messages.pop(username, [])
            for payload in msgs:
                self._decrypt_and_display(username, payload)
            return

        if self._begin_verification(username):
            finger = self._fingerprint_from_bytes(
                IdentityKeyManager.serialize_public_key(self.user_pubkeys[username]['ed25519'])
            )
            self.callback('USER_VERIFY', {'username': username, 'fingerprint': finger})

    def _check_pending_outgoing_verification(self, username):
        with self.pending_manual_verifications_lock:
            if username in self.pending_manual_verifications:
                return
        with self.pending_outgoing_lock:
            has_pending = username in self.pending_outgoing_messages and bool(self.pending_outgoing_messages[username])

        if not has_pending:
            return

        if self._is_user_trusted(username):
            self._flush_pending_outgoing_messages(username)
            return

        if self._begin_verification(username):
            finger = self._fingerprint_from_bytes(
                IdentityKeyManager.serialize_public_key(self.user_pubkeys[username]['ed25519'])
            )
            self.callback('USER_VERIFY', {'username': username, 'fingerprint': finger})

    # ------------------------------------------------------------------
    # Trust management
    def _is_user_trusted(self, username):
        if username not in self.user_pubkeys:
            return False
        finger = self._fingerprint_from_bytes(
            IdentityKeyManager.serialize_public_key(self.user_pubkeys[username]['ed25519'])
        )
        return self.trust_db['users'].get(username) == finger

    def trust_user(self, username):
        if username not in self.user_pubkeys:
            return False
        finger = self._fingerprint_from_bytes(
            IdentityKeyManager.serialize_public_key(self.user_pubkeys[username]['ed25519'])
        )
        self.trust_db['users'][username] = finger
        self._save_trust_db()
        with self.pending_msg_lock:
            msgs = self.pending_messages.pop(username, [])
        for payload in msgs:
            self._decrypt_and_display(username, payload)
        self._flush_pending_outgoing_messages(username)
        self._end_verification(username)
        return True

    def distrust_user(self, username):
        with self._trust_lock:
            self.trust_db['users'].pop(username, None)
        self._save_trust_db()

    def get_user_fingerprint(self, username):
        if username not in self.user_pubkeys:
            return None
        return self._fingerprint_from_bytes(
            IdentityKeyManager.serialize_public_key(self.user_pubkeys[username]['ed25519'])
        )

    def get_fingerprint_words(self, username, word_count=6):
        fingerprint_hex = self.get_user_fingerprint(username)
        if not fingerprint_hex:
            return None
        try:
            from src.common.crypto_utils import FingerprintWords
            return FingerprintWords.fingerprint_to_words(fingerprint_hex, word_count)
        except Exception as e:
            if self.callback:
                self.callback('ERROR', f"Failed to generate fingerprint words: {e}")
            return None

    def get_own_fingerprint_words(self, word_count=6):
        if not self.id_pub:
            return None
        try:
            from src.common.crypto_utils import FingerprintWords
            fingerprint_hex = self._fingerprint_from_bytes(
                IdentityKeyManager.serialize_public_key(self.id_pub)
            )
            return FingerprintWords.fingerprint_to_words(fingerprint_hex, word_count)
        except Exception as e:
            if self.callback:
                self.callback('ERROR', f"Failed to generate own fingerprint words: {e}")
            return None

    def _begin_verification(self, username):
        with self.pending_verifications_lock:
            if username in self.pending_verifications:
                return False
            self.pending_verifications.add(username)
            return True

    def _end_verification(self, username):
        with self.pending_verifications_lock:
            self.pending_verifications.discard(username)

    def _check_manual_verification(self, username):
        with self.pending_manual_verifications_lock:
            if username not in self.pending_manual_verifications:
                return
            self.pending_manual_verifications.discard(username)

        if username not in self.user_pubkeys:
            return

        finger = self._fingerprint_from_bytes(
            IdentityKeyManager.serialize_public_key(self.user_pubkeys[username]['ed25519'])
        )
        if self.callback:
            self.callback('USER_VERIFY', {'username': username, 'fingerprint': finger})

    # ------------------------------------------------------------------
    # Server trust (TLS certificate confirmation handled by cert_verify_callback)
    def confirm_server_trust(self, approved):
        pass

    # ------------------------------------------------------------------
    # Login and registration
    def login(self, username, password):
        self.pending_login_user = username
        self.last_password = password

        if not self.id_priv:
            local = self._load_local_private(username, password)
            if local:
                self.id_priv, self.x_priv = local
                self.id_pub = self.id_priv.public_key()
                self.x_pub = self.x_priv.public_key()
                self.local_key_loaded = True
            else:
                self.local_key_loaded = False

        if self.local_key_loaded:
            self._send({'cmd': 'login', 'data': {'username': username, 'no_password': True}})
        else:
            enc_pw = ServerCrypto.encrypt_for_server(password.encode('utf-8'))
            self._send({'cmd': 'login', 'data': {'username': username, 'password': enc_pw}})

    def _respond_challenge(self, challenge, timestamp):
        if not self.id_priv:
            if self.callback:
                self.callback('ERROR', 'Missing local identity private key, cannot complete challenge response')
            return
        data_to_sign = f"{challenge}:{timestamp}".encode('utf-8')
        sig = self.id_priv.sign(data_to_sign)
        self._send({
            'cmd': 'challenge_response',
            'data': {
                'username': self.pending_login_user,
                'challenge': challenge,
                'timestamp': timestamp,
                'signature': sig.hex()
            }
        })

    def register(self, username, password, store_private_key=True, invite_code=''):
        if self.token:
            self.logout()

        id_priv, id_pub = IdentityKeyManager.generate()
        x_priv, x_pub = ExchangeKeyManager.generate()

        # Generate recovery key pair (Ed25519) for irreversible account freeze
        self.recovery_priv, recovery_pub = IdentityKeyManager.generate()

        self.id_priv = id_priv
        self.id_pub = id_pub
        self.x_priv = x_priv
        self.x_pub = x_pub

        data = {
            'username': username,
            'store_private_key': store_private_key,
            'ed25519_priv_pem': IdentityKeyManager.serialize_private_key(id_priv),
            'x25519_priv_hex': ExchangeKeyManager.serialize_private_key(x_priv),
            'invite_code': invite_code,
            'recovery_pub': IdentityKeyManager.serialize_public_key(recovery_pub),
        }

        # Save recovery private key locally
        try:
            recovery_path = f'local_keys/{username}_recovery.priv'
            if not os.path.exists('local_keys'):
                os.makedirs('local_keys')
            with open(recovery_path, 'w', encoding='utf-8') as f:
                f.write(IdentityKeyManager.serialize_private_key(self.recovery_priv))
        except Exception:
            if self.callback:
                self.callback('WARNING', 'Failed to save recovery key locally')

        if store_private_key:
            key_id = f"{username}_key_1"
            keys = {
                'ed25519_priv': IdentityKeyManager.serialize_private_key(id_priv),
                'x25519_priv': ExchangeKeyManager.serialize_private_key(x_priv),
            }
            plain = json.dumps(keys).encode('utf-8')
            salt = os.urandom(16)
            key = PasswordManager.derive_key(password, salt)
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(plain) + encryptor.finalize()
            tag = encryptor.tag
            data['encrypted_private'] = {
                key_id: {
                    'salt': salt.hex(),
                    'nonce': nonce.hex(),
                    'ct': ct.hex(),
                    'tag': tag.hex()
                }
            }
            enc_pw = ServerCrypto.encrypt_for_server(password.encode('utf-8'))
            data['password'] = enc_pw
        else:
            self._save_local_private(username, password)

        self._send({'cmd': 'reg_user', 'data': data})

    def _save_local_private(self, username, password, key_id=None):
        if key_id is None:
            key_id = f"{username}_key_1"
        keys = {
            'ed25519_priv': IdentityKeyManager.serialize_private_key(self.id_priv),
            'x25519_priv': ExchangeKeyManager.serialize_private_key(self.x_priv),
            'key_id': key_id,
        }
        plain = json.dumps(keys).encode('utf-8')
        salt = os.urandom(16)
        key = PasswordManager.derive_key(password, salt)
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(plain) + encryptor.finalize()
        tag = encryptor.tag
        path = f'local_keys/{username}_private.enc'
        with open(path, 'wb') as f:
            f.write(salt + nonce + tag + ct)

    def _load_local_private(self, username, password):
        path = f'local_keys/{username}_private.enc'
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'rb') as f:
                data = f.read()
            salt = data[:16]
            nonce = data[16:28]
            tag = data[28:44]
            ct = data[44:]
            key = PasswordManager.derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plain = decryptor.update(ct) + decryptor.finalize()
            keys = json.loads(plain.decode('utf-8'))
            id_priv = IdentityKeyManager.deserialize_private_key(keys['ed25519_priv'])
            x_priv = ExchangeKeyManager.deserialize_private_key(keys['x25519_priv'])
            # Set rotation fields
            kid = keys.get('key_id', f"{username}_key_1")
            self.x25519_privates[kid] = x_priv
            self.x25519_publics[kid] = ExchangeKeyManager.serialize_public_key(x_priv.public_key())
            self.current_key_id = kid
            return id_priv, x_priv
        except Exception:
            return None

    def clear_password(self):
        self.last_password = None

    # ------------------------------------------------------------------
    # Message sending
    def send_message(self, receiver, plaintext):
        if not self.id_priv:
            if self.callback:
                self.callback('ERROR', 'Local identity private key not loaded, cannot send message')
            return False
        if not self.session_id or not self.session_key:
            if self.callback:
                self.callback('ERROR', 'Session not established, cannot send message')
            return False
        if not re.match(r'^[A-Za-z0-9]{3,20}$', receiver):
            if self.callback:
                self.callback('ERROR', 'Invalid username format')
            return False
        if receiver not in self.user_pubkeys:
            self._queue_pending_outgoing_message(receiver, plaintext)
            self._request_public_key(receiver)
            return True
        if not self._is_user_trusted(receiver):
            self._queue_pending_outgoing_message(receiver, plaintext)
            if self._begin_verification(receiver):
                finger = self._fingerprint_from_bytes(
                    IdentityKeyManager.serialize_public_key(self.user_pubkeys[receiver]['ed25519'])
                )
                self.callback('USER_VERIFY', {'username': receiver, 'fingerprint': finger})
            return True
        return self._send_encrypted_message(receiver, plaintext)

    def _request_public_key(self, username):
        self._send(self._build_authenticated_payload('get_pubkey', {'username': username}))

    def _request_online_users(self):
        self._send(self._build_authenticated_payload('list_users'))

    # ------------------------------------------------------------------
    # Key rotation
    ROTATE_INTERVAL = 86400  # 24 hours

    def _request_my_keys(self):
        """Download my own key list and encrypted privates from server."""
        self._send(self._build_authenticated_payload('get_my_keys'))

    def check_and_rotate(self):
        """Check if key rotation is needed and perform it."""
        if not self.last_password:
            return
        if not self.x25519_keys_info:
            return
        latest = self.x25519_keys_info[0]
        if time.time() - latest.get('created_at', 0) > self.ROTATE_INTERVAL:
            self.rotate_key()

    def rotate_key(self):
        """Generate new X25519 key pair and upload to server."""
        if not self.last_password or not self.id_priv:
            return
        # Generate new key pair
        new_priv = x25519.X25519PrivateKey.generate()
        new_pub = new_priv.public_key()
        new_pub_hex = ExchangeKeyManager.serialize_public_key(new_pub)

        # Encrypt new private key
        keys = {
            'ed25519_priv': IdentityKeyManager.serialize_private_key(self.id_priv),
            'x25519_priv': ExchangeKeyManager.serialize_private_key(new_priv),
        }
        plain = json.dumps(keys).encode('utf-8')
        salt = os.urandom(16)
        key = PasswordManager.derive_key(self.last_password, salt)
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(plain) + encryptor.finalize()
        tag = encryptor.tag

        encrypted_priv = {
            'salt': salt.hex(),
            'nonce': nonce.hex(),
            'ct': ct.hex(),
            'tag': tag.hex(),
        }

        # Sign the rotation request
        rotate_ts = int(time.time())
        data_to_sign = f"{new_pub_hex}{rotate_ts}".encode('utf-8')
        signature = self.id_priv.sign(data_to_sign).hex()

        self._send(self._build_authenticated_payload('rotate_key', {
            'new_pub': new_pub_hex,
            'encrypted_priv': encrypted_priv,
            'timestamp': rotate_ts,
            'signature': signature,
        }))

        # Update local state optimistically
        key_id = f"{self.username}_{rotate_ts}"
        self.current_key_id = key_id
        self.x25519_privates[key_id] = new_priv
        self.x25519_publics[key_id] = new_pub_hex
        self.x_priv = new_priv
        self.x_pub = new_pub
        self.x25519_keys_info.insert(0, {
            'id': key_id,
            'pub_hex': new_pub_hex,
            'created_at': rotate_ts,
        })
        # Also save locally if using local mode
        if not self.local_key_loaded:
            self._save_local_private(self.username, self.last_password, key_id=key_id)

    def logout(self):
        # Stop heartbeat first to avoid send-lock contention; then send a valid authenticated logout request.
        # This makes the server remove the user from online list immediately; other clients see the change on next poll.
        if self.session_id and self.session_key and self.sock:
            self._stop_heartbeat()
            try:
                payload = self._build_authenticated_payload('logout')
                with self._send_lock:
                    PaddedSender.send(self.sock, json.dumps(payload, ensure_ascii=False).encode('utf-8'))
            except Exception:
                pass
        else:
            self._stop_heartbeat()

        self._clear_session_state()
        self._auth_sequence = 0
        self._last_timestamp = 0
        # Close connection
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        if self.callback:
            self.callback('UPDATE_BUTTONS', None)

    def _clear_session_state(self):
        self.session_id = None
        self.session_key = None
        self._auth_sequence = 0
        self._last_timestamp = 0
        self.token = None
        self.username = None
        self.pending_login_user = None
        self.local_key_loaded = False
        self.id_priv = None
        self.id_pub = None
        self.x_priv = None
        self.x_pub = None
        self.user_pubkeys.clear()
        self.x25519_privates.clear()
        self.x25519_publics.clear()
        self.current_key_id = None
        self.x25519_keys_info = []
        self.recovery_priv = None
        with self.pending_msg_lock:
            self.pending_messages.clear()
        with self.pending_outgoing_lock:
            self.pending_outgoing_messages.clear()
        with self.pending_verifications_lock:
            self.pending_verifications.clear()
        with self.pending_manual_verifications_lock:
            self.pending_manual_verifications.clear()
        self.clear_password()

    def _disconnect_cleanup(self):
        self.running = False
        self._stop_heartbeat()
        self._clear_session_state()
        self.server_ed25519_pub = None
        self.server_x25519_pub = None
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
        if self.callback:
            self.callback('UPDATE_BUTTONS', None)


# ----------------------------------------------------------------------
# GUI utility functions (ctypes structs defined at file header)
# ----------------------------------------------------------------------
def flash_taskbar(root, count=3):
    try:
        hwnd = root.winfo_id()
        info = FLASHWINFO(
            ctypes.sizeof(FLASHWINFO),
            hwnd,
            FLASHW_TRAY,
            count,
            0
        )
        ctypes.windll.user32.FlashWindowEx(ctypes.byref(info))
    except Exception:
        pass

