# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.

"""test_freeze_e2e.py — end-to-end integration test for account freeze.

Validates the full freeze lifecycle against a running KaleidoTalk server
at 127.0.0.1:5555:
register (with recovery_pub) -> login -> freeze -> verify frozen login fails.

Requires the server to be running.  Run:  python test_freeze_e2e.py
"""

import json
import os
import sys
import time
import struct
import socket
import ssl
import threading
import queue
import hashlib
import hmac as hmac_mod
import base64
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend

from src.common.crypto_utils import (
    IdentityKeyManager,
    ExchangeKeyManager,
    PasswordManager,
    MessageEncryptorV2,
    ServerCrypto,
)
from src.common.padding import PaddedSender, PaddedReceiver

# ────────────────────────────────────────────────
# Config
# ────────────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 5555
USERNAME = "testfreez"
PASSWORD = "Test1234!"

passed = 0
failed = 0


def log_pass(msg):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def log_fail(msg):
    global failed
    failed += 1
    print(f"  [FAIL] {msg}")


# ────────────────────────────────────────────────
# Low-level protocol helpers (same as test_e2e_rotation.py)
# ────────────────────────────────────────────────
def send_msg(sock, obj):
    """Send a JSON message using PaddedSender."""
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    PaddedSender.send(sock, data)


def recv_msg(sock, receiver):
    """Receive one JSON message using PaddedReceiver. Blocks."""
    raw = receiver.recv(sock)
    if not raw:
        return None
    return json.loads(raw.decode("utf-8"))


def build_authenticated_payload(session_id, session_key, seq_counter, last_ts, cmd, data=None):
    """Build an HMAC-authenticated command payload.
    Modifies mutable seq_counter and last_ts.
    """
    payload_data = data or {}
    seq_counter[0] += 1
    seq = seq_counter[0]
    timestamp = int(time.time() * 1000)
    if timestamp <= last_ts[0]:
        timestamp = last_ts[0] + 1
    last_ts[0] = timestamp
    canonical = json.dumps(payload_data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    message = f"{session_id}{seq}{timestamp}{canonical}".encode("utf-8")
    signature = hmac_mod.new(session_key, message, hashlib.sha256).hexdigest()
    return {
        "cmd": cmd,
        "session_id": session_id,
        "seq": seq,
        "timestamp": timestamp,
        "hmac": signature,
        "data": payload_data,
    }


def decrypt_session_key(encrypted_session_key, x_priv):
    """Decrypt session key from server's login response."""
    eph_pub_bytes = base64.b64decode(encrypted_session_key["eph_pub"])
    ct = base64.b64decode(encrypted_session_key["ct"])
    tag = base64.b64decode(encrypted_session_key["tag"])
    nonce_b64 = encrypted_session_key.get("nonce")
    eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
    shared_secret = x_priv.exchange(eph_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"kaleidotalk-session-key",
        backend=default_backend(),
    )
    aes_key = hkdf.derive(shared_secret)
    if nonce_b64:
        nonce = base64.b64decode(nonce_b64)
    else:
        hkdf_legacy = HKDF(
            algorithm=hashes.SHA256(),
            length=44,
            salt=None,
            info=b"kaleidotalk-session-key",
            backend=default_backend(),
        )
        nonce = hkdf_legacy.derive(shared_secret)[32:44]
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()


def encrypt_private_keys(ed_priv_pem, x_priv_hex, password):
    """Encrypt both private keys into a single encrypted blob."""
    keys_blob = json.dumps({
        "ed25519_priv": ed_priv_pem,
        "x25519_priv": x_priv_hex,
    }).encode("utf-8")
    salt = os.urandom(16)
    key = PasswordManager.derive_key(password, salt)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(keys_blob) + encryptor.finalize()
    return {
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ct": ct.hex(),
        "tag": encryptor.tag.hex(),
    }


# ────────────────────────────────────────────────
# Clean up old test user
# ────────────────────────────────────────────────
def cleanup_test_user():
    """Delete testfreez from server JSON files if present."""
    for fname in ["users.json", "user_keys.json"]:
        if os.path.exists(fname):
            try:
                with open(fname, "r", encoding="utf-8") as f:
                    db = json.load(f)
                if USERNAME in db:
                    del db[USERNAME]
                    tmp = fname + ".tmp"
                    with open(tmp, "w", encoding="utf-8") as f:
                        json.dump(db, f, indent=2, ensure_ascii=False)
                    os.replace(tmp, fname)
                    print(f"  Cleaned {USERNAME} from {fname}")
            except Exception:
                pass


# ────────────────────────────────────────────────
# Main test
# ────────────────────────────────────────────────
def main():
    global passed, failed

    print("=" * 55)
    print("  KaleidoTalk Account Freeze E2E Test")
    print("=" * 55)

    # ── 0. Cleanup ──
    print("\n--- 0. Cleanup previous test user ---")
    cleanup_test_user()
    log_pass("Previous test user removed (if existed)")

    # ── 1. Connect ──
    print("\n--- 1. Connect to server ---")
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(5)
    raw_sock.connect((HOST, PORT))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls_sock = ctx.wrap_socket(raw_sock, server_hostname=HOST)
    tls_sock.settimeout(30.0)
    log_pass(f"TLS connected to {HOST}:{PORT}")

    receiver = PaddedReceiver()

    # Welcome message
    welcome = recv_msg(tls_sock, receiver)
    if welcome and welcome.get("type") == "welcome":
        log_pass(f"Welcome: {welcome['data']['message']}")
    else:
        log_fail("No welcome message")
        sys.exit(1)

    # ── 2. Get server public keys ──
    print("\n--- 2. Get server public key ---")
    send_msg(tls_sock, {"cmd": "get_server_pubkey"})
    resp = recv_msg(tls_sock, receiver)
    if resp and resp.get("cmd") == "server_pubkey":
        server_ed = IdentityKeyManager.deserialize_public_key(resp["data"]["ed25519"])
        server_x = ExchangeKeyManager.deserialize_public_key(resp["data"]["x25519"])
        ServerCrypto._ed25519_pub = server_ed
        ServerCrypto._x25519_pub = server_x
        log_pass("Server public keys received")
    else:
        log_fail(f"server_pubkey failed: {resp}")
        sys.exit(1)

    # ── 3. Generate identity + recovery keypairs ──
    print("\n--- 3. Generate identity + recovery keypairs ---")
    id_priv, id_pub = IdentityKeyManager.generate()
    recovery_priv, recovery_pub = IdentityKeyManager.generate()
    recovery_pub_pem = IdentityKeyManager.serialize_public_key(recovery_pub)

    x1_priv, x1_pub = ExchangeKeyManager.generate()
    x1_pub_hex = ExchangeKeyManager.serialize_public_key(x1_pub)
    key1_id = f"{USERNAME}_key_1"

    enc1 = encrypt_private_keys(
        IdentityKeyManager.serialize_private_key(id_priv),
        ExchangeKeyManager.serialize_private_key(x1_priv),
        PASSWORD,
    )
    log_pass("Generated Ed25519 identity keypair")
    log_pass("Generated Ed25519 recovery keypair")
    log_pass(f"Generated X25519 exchange keypair ({key1_id})")

    # ── 4. Register ──
    print("\n--- 4. Register ---")
    enc_pw = ServerCrypto.encrypt_for_server(PASSWORD.encode("utf-8"))
    reg_data = {
        "username": USERNAME,
        "store_private_key": True,
        "ed25519_priv_pem": IdentityKeyManager.serialize_private_key(id_priv),
        "x25519_priv_hex": ExchangeKeyManager.serialize_private_key(x1_priv),
        "invite_code": "",
        "encrypted_private": {key1_id: enc1},
        "password": enc_pw,
        "recovery_pub": recovery_pub_pem,
    }
    send_msg(tls_sock, {"cmd": "reg_user", "data": reg_data})
    reg_resp = recv_msg(tls_sock, receiver)
    if reg_resp and reg_resp.get("status") == "ok":
        log_pass(f"Registration successful: {reg_resp['data'].get('message', '')}")
    else:
        err = reg_resp.get("error", str(reg_resp)) if reg_resp else "no response"
        log_fail(f"Registration failed: {err}")
        sys.exit(1)

    # ── 5. Login ──
    print("\n--- 5. Login ---")
    enc_pw2 = ServerCrypto.encrypt_for_server(PASSWORD.encode("utf-8"))
    send_msg(tls_sock, {"cmd": "login", "data": {"username": USERNAME, "password": enc_pw2}})
    login_resp = recv_msg(tls_sock, receiver)
    if not login_resp or login_resp.get("status") != "ok":
        err = login_resp.get("error", str(login_resp)) if login_resp else "no response"
        log_fail(f"Login failed: {err}")
        sys.exit(1)

    ld = login_resp["data"]
    session_id = ld["session_id"]
    session_key = decrypt_session_key(ld["encrypted_session_key"], x1_priv)
    seq_counter = [0]
    last_ts = [0]
    log_pass("Login successful, session established")

    # ── 6. Send freeze_account command (plain JSON, no authentication) ──
    print("\n--- 6. Freeze account ---")
    freeze_ts = int(time.time())
    nonce = os.urandom(16).hex()
    data_to_sign = f"{USERNAME}{freeze_ts}{nonce}".encode("utf-8")
    signature = recovery_priv.sign(data_to_sign).hex()

    freeze_cmd = {
        "cmd": "freeze_account",
        "data": {
            "username": USERNAME,
            "timestamp": freeze_ts,
            "nonce": nonce,
            "signature": signature,
        },
    }
    send_msg(tls_sock, freeze_cmd)
    freeze_resp = recv_msg(tls_sock, receiver)
    if freeze_resp and freeze_resp.get("status") == "ok":
        log_pass(f"Freeze accepted: {freeze_resp.get('data', {}).get('message', '')}")
    else:
        err = freeze_resp.get("error", str(freeze_resp)) if freeze_resp else "no response"
        log_fail(f"Freeze failed: {err}")
        sys.exit(1)

    # ── 7. Attempt login again — must get "Account frozen" ──
    print("\n--- 7. Verify frozen login is rejected ---")
    # Need fresh connection because the frozen user may have been force-disconnected
    try:
        tls_sock.close()
    except Exception:
        pass

    raw_sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock2.settimeout(5)
    raw_sock2.connect((HOST, PORT))
    ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx2.check_hostname = False
    ctx2.verify_mode = ssl.CERT_NONE
    tls_sock2 = ctx2.wrap_socket(raw_sock2, server_hostname=HOST)
    tls_sock2.settimeout(30.0)

    receiver2 = PaddedReceiver()
    # Drain welcome
    welcome2 = recv_msg(tls_sock2, receiver2)
    if welcome2 and welcome2.get("type") == "welcome":
        log_pass("Second connection: welcome received")

    # Get server pubkey on new connection
    send_msg(tls_sock2, {"cmd": "get_server_pubkey"})
    pk_resp = recv_msg(tls_sock2, receiver2)
    if pk_resp and pk_resp.get("cmd") == "server_pubkey":
        server_ed2 = IdentityKeyManager.deserialize_public_key(pk_resp["data"]["ed25519"])
        server_x2 = ExchangeKeyManager.deserialize_public_key(pk_resp["data"]["x25519"])
        ServerCrypto._ed25519_pub = server_ed2
        ServerCrypto._x25519_pub = server_x2

    # Attempt login on frozen account
    enc_pw3 = ServerCrypto.encrypt_for_server(PASSWORD.encode("utf-8"))
    send_msg(tls_sock2, {"cmd": "login", "data": {"username": USERNAME, "password": enc_pw3}})
    frozen_login_resp = recv_msg(tls_sock2, receiver2)
    if frozen_login_resp and frozen_login_resp.get("status") == "error":
        err_msg = frozen_login_resp.get("error", "")
        if "frozen" in err_msg.lower():
            log_pass(f"Frozen login correctly rejected: '{err_msg}'")
        else:
            log_fail(f"Expected 'Account frozen' error, got: '{err_msg}'")
    else:
        log_fail(f"Login should have been rejected, got: {frozen_login_resp}")

    # ── 8. Cleanup ──
    print("\n--- 8. Cleanup ---")
    try:
        tls_sock2.close()
    except Exception:
        pass
    cleanup_test_user()
    log_pass("Test user cleaned up")

    # ── Summary ──
    print(f"\n{'=' * 55}")
    print(f"RESULTS:  {passed} PASSED,  {failed} FAILED")
    print(f"{'=' * 55}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
