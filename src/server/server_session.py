# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


# server_session.py - session and security management
import socket
import threading
import json
import os
import base64
import hashlib
import hmac
import time
import secrets
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend
from src.common.network import send_msg, recv_msg
from src.common.crypto_utils import (
    ExchangeKeyManager,
)
from src.server.server_storage import (
    load_bans_file,
    locks as storage_locks,
)
from src.server.config import load_config

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Thread locks (non-file-lock section)
locks = {
    'clients': threading.Lock(),
    'logged_in': threading.Lock(),
    'pending': threading.Lock(),
    'ip_attempts': threading.Lock(),
    'ip_ban': threading.Lock(),
    'challenges': threading.Lock(),
    'tokens': threading.Lock(),
    'sessions': threading.Lock(),
}

# ----------------------------------------------------------------------
# Global state
clients = {}                # socket -> {'username': str, 'session_id': str}
tokens = {}                 # token -> username
sessions = {}               # session_id -> {'username': str, 'session_key': bytes, 'timestamps': {int: int}}
logged_in_users = {}        # username -> socket
pending_messages = {}       # username -> list of dicts (to be sent on login)
ip_attempts = {}            # ip -> {'reg': [timestamps], 'login': [timestamps], 'banned_until': float}
ip_ban_list = {}            # ip -> banned_until
user_ban_list = {}          # username -> True
challenges = {}             # username -> {'challenge': str, 'timestamp': str}

# ----------------------------------------------------------------------
# Load security configuration from config.json
_config = load_config()
_security = _config.get("security", {})

IP_BAN_DURATION = _security.get("ip_ban_duration", 3600)
REGISTER_LIMIT = _security.get("register_limit", 10)
LOGIN_LIMIT = _security.get("login_limit", 20)
TIME_WINDOW = _security.get("time_window", 60)
MAX_MSG_SIZE = _security.get("max_message_size", 10 * 1024 * 1024)
SESSION_TIME_WINDOW = _security.get("session_time_window", 300)
SESSION_TIME_WINDOW_MS = SESSION_TIME_WINDOW * 1000
AUTH_COMMANDS = ('message', 'list_users', 'logout', 'get_pubkey', 'rotate_key', 'get_my_keys')


def _canonical_json(data):
    return json.dumps(data or {}, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def _auth_message(session_id, seq, timestamp, data):
    return f'{session_id}{seq}{timestamp}{_canonical_json(data)}'.encode('utf-8')


def _encrypt_session_key_for_client(session_key, client_x25519_pub_pem):
    client_pub = ExchangeKeyManager.deserialize_public_key(client_x25519_pub_pem)
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key()
    shared_secret = eph_priv.exchange(client_pub)
    salt = os.urandom(16)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'kaleidotalk-session-key',
        backend=default_backend(),
    )
    aes_key = hkdf.derive(shared_secret)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(session_key) + encryptor.finalize()
    return {
        'eph_pub': base64.b64encode(eph_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )).decode('utf-8'),
        'ct': base64.b64encode(ciphertext).decode('utf-8'),
        'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8'),
    }


def _create_session(username, client_x25519_pub_pem):
    session_id = secrets.token_hex(32)
    session_key = os.urandom(32)
    with locks['sessions']:
        sessions[session_id] = {
            'username': username,
            'session_key': session_key,
            'last_seq': 0,
            'timestamps': {},
            'client_x25519_pub': client_x25519_pub_pem,
        }
    return session_id, session_key


def _remove_session(session_id):
    with locks['sessions']:
        sessions.pop(session_id, None)


def _verify_authenticated_request(payload):
    session_id = payload.get('session_id', '')
    seq_raw = payload.get('seq')
    timestamp_raw = payload.get('timestamp')
    provided_hmac = payload.get('hmac', '')
    data = payload.get('data', {})

    if not session_id or not isinstance(data, dict):
        return False, 'missing session or request data', None, None

    try:
        seq = int(seq_raw)
    except Exception:
        return False, 'invalid sequence number', None, None

    try:
        timestamp = int(timestamp_raw)
    except Exception:
        return False, 'invalid timestamp', None, None

    now_ms = int(time.time() * 1000)
    if abs(now_ms - timestamp) > SESSION_TIME_WINDOW_MS:
        return False, 'timestamp out of allowed range', None, None

    with locks['sessions']:
        session = sessions.get(session_id)
        if not session:
            return False, 'session expired', None, None
        session_key = session['session_key']
        last_seq = int(session.get('last_seq', 0))
        timestamp_cache = session.setdefault('timestamps', {})
        stale = [ts for ts, seen_at in timestamp_cache.items() if now_ms - seen_at > SESSION_TIME_WINDOW_MS]
        for ts in stale:
            timestamp_cache.pop(ts, None)
        if timestamp in timestamp_cache:
            return False, 'replayed request', None, None
        if seq <= last_seq:
            return False, 'replayed request', None, None

    expected = hmac.new(session_key, _auth_message(session_id, seq, timestamp, data), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(provided_hmac)):
        return False, 'HMAC verification failed', None, None

    with locks['sessions']:
        session = sessions.get(session_id)
        if not session:
            return False, 'session expired', None, None
        timestamp_cache = session.setdefault('timestamps', {})
        if timestamp in timestamp_cache:
            return False, 'replayed request', None, None
        if seq <= int(session.get('last_seq', 0)):
            return False, 'replayed request', None, None
        timestamp_cache[timestamp] = now_ms
        session['last_seq'] = seq
        username = session['username']

    return True, username, session_id, data

# ----------------------------------------------------------------------
# DoS protection
def check_dos(ip, attempt_type='reg'):
    now = time.time()
    try:
        bans_now = load_bans_file()
        with locks['ip_ban']:
            for ip_k, until_v in bans_now.get('ip_bans', {}).items():
                try:
                    ip_ban_list[ip_k] = float(until_v)
                except Exception:
                    continue
    except Exception:
        pass
    with locks['ip_ban']:
        if ip in ip_ban_list and now < ip_ban_list[ip]:
            remaining = int(ip_ban_list[ip] - now)
            return False, f"IP is banned, {remaining}s remaining"
    with locks['ip_attempts']:
        if ip not in ip_attempts:
            ip_attempts[ip] = {'reg': [], 'login': [], 'banned_until': 0}
        record = ip_attempts[ip]
        key = 'reg' if attempt_type == 'reg' else 'login'
        limit = REGISTER_LIMIT if attempt_type == 'reg' else LOGIN_LIMIT
        record[key] = [t for t in record[key] if now - t < TIME_WINDOW]
        if len(record[key]) >= limit:
            with locks['ip_ban']:
                ip_ban_list[ip] = now + IP_BAN_DURATION
            logger.warning(f"IP {ip} banned for {IP_BAN_DURATION}s due to {attempt_type} rate limit")
            return False, f"IP banned for {IP_BAN_DURATION}s"
        record[key].append(now)
    return True, "OK"

# ----------------------------------------------------------------------
# Session token
def create_token():
    return secrets.token_hex(32)

def bind_token(username):
    token = create_token()
    with locks['tokens']:
        tokens[token] = username
    return token

def consume_token(token):
    with locks['tokens']:
        return tokens.pop(token, None)

def verify_token(token):
    with locks['tokens']:
        return token in tokens

def get_user_by_token(token):
    with locks['tokens']:
        return tokens.get(token)

# ----------------------------------------------------------------------
# Offline messages
def store_offline_message(username, message_obj):
    with locks['pending']:
        pending_messages.setdefault(username, []).append(message_obj)

def send_pending_messages(sock, username):
    with locks['pending']:
        msgs = pending_messages.pop(username, [])
    for msg in msgs:
        try:
            send_msg(sock, msg)
        except Exception:
            pass
    if msgs:
        logger.info(f"Sent {len(msgs)} offline messages to {username}")

# ----------------------------------------------------------------------
# Connection and user management
def register_socket(sock, username, session_id):
    with locks['clients']:
        clients[sock] = {'username': username, 'session_id': session_id}
    with locks['logged_in']:
        old_sock = logged_in_users.get(username)
        if old_sock and old_sock != sock:
            try:
                send_msg(old_sock, {'type': 'force_logout', 'data': 'Your account has signed in on another device'})
                old_info = clients.get(old_sock, {})
                old_session_id = old_info.get('session_id')
                if old_session_id:
                    _remove_session(old_session_id)
                old_sock.close()
            except Exception:
                pass
        logged_in_users[username] = sock

def unregister_socket(sock):
    with locks['clients']:
        info = clients.pop(sock, None)
    if not info:
        return
    username = info['username']
    session_id = info.get('session_id')
    if session_id:
        _remove_session(session_id)
    with locks['logged_in']:
        if logged_in_users.get(username) == sock:
            logged_in_users.pop(username, None)
    with locks['challenges']:
        challenges.pop(username, None)
    logger.info(f"User {username} disconnected")
