# -*- coding: utf-8 -*-
"""test_e2e_rotation.py — end-to-end integration test for X25519 key rotation.

Validates the full lifecycle against a running KaleidoTalk server at 127.0.0.1:5555:
register → login → get_my_keys → rotate_key → send → receive → decrypt.

Requires the server to be running.  Run:  python test_e2e_rotation.py
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
USERNAME = "testrot1"
PASSWORD = "Test1234!"
PACKET_SIZE = 2048

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
# Low-level protocol helpers
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
    """Build an HMAC-authenticated command payload. Modifies mutable seq_counter and last_ts."""
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
    return {"cmd": cmd, "session_id": session_id, "seq": seq, "timestamp": timestamp, "hmac": signature, "data": payload_data}


def decrypt_session_key(encrypted_session_key, x_priv):
    """Decrypt session key from server's login response."""
    eph_pub_bytes = base64.b64decode(encrypted_session_key["eph_pub"])
    ct = base64.b64decode(encrypted_session_key["ct"])
    tag = base64.b64decode(encrypted_session_key["tag"])
    nonce_b64 = encrypted_session_key.get("nonce")
    eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
    shared_secret = x_priv.exchange(eph_pub)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"kaleidotalk-session-key", backend=default_backend())
    aes_key = hkdf.derive(shared_secret)
    if nonce_b64:
        nonce = base64.b64decode(nonce_b64)
    else:
        hkdf_legacy = HKDF(algorithm=hashes.SHA256(), length=44, salt=None, info=b"kaleidotalk-session-key", backend=default_backend())
        nonce = hkdf_legacy.derive(shared_secret)[32:44]
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()


def encrypt_private_keys(ed_priv_pem, x_priv_hex, password):
    """Encrypt both private keys into a single encrypted blob."""
    keys_blob = json.dumps({"ed25519_priv": ed_priv_pem, "x25519_priv": x_priv_hex}).encode("utf-8")
    salt = os.urandom(16)
    key = PasswordManager.derive_key(password, salt)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(keys_blob) + encryptor.finalize()
    return {"salt": salt.hex(), "nonce": nonce.hex(), "ct": ct.hex(), "tag": encryptor.tag.hex()}


def decrypt_private_keys(enc, password):
    """Decrypt an encrypted private-key blob."""
    salt = bytes.fromhex(enc["salt"])
    nonce = bytes.fromhex(enc["nonce"])
    ct = bytes.fromhex(enc["ct"])
    tag = bytes.fromhex(enc["tag"])
    key = PasswordManager.derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plain = decryptor.update(ct) + decryptor.finalize()
    return json.loads(plain.decode("utf-8"))


def wait_for_msg(msg_queue, timeout=5):
    """Get next 'msg' push from queue, discarding non-msg items (like cmd responses)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            m = msg_queue.get(timeout=0.5)
            if m.get("type") == "msg":
                return m
        except queue.Empty:
            continue
    return None


# ────────────────────────────────────────────────
# Clean up old test user
# ────────────────────────────────────────────────
def cleanup_test_user():
    """Delete test_rotation from server JSON files if present."""
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
    print("  KaleidoTalk Key Rotation E2E Test")
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

    # ── 3. Generate identity keys ──
    print("\n--- 3. Generate identity keys ---")
    id_priv, id_pub = IdentityKeyManager.generate()
    x1_priv, x1_pub = ExchangeKeyManager.generate()
    x1_pub_hex = ExchangeKeyManager.serialize_public_key(x1_pub)
    key1_id = f"{USERNAME}_key_1"

    enc1 = encrypt_private_keys(
        IdentityKeyManager.serialize_private_key(id_priv),
        ExchangeKeyManager.serialize_private_key(x1_priv),
        PASSWORD,
    )
    log_pass(f"Generated Ed25519 + X25519 key_1 ({key1_id})")

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

    # Load my own keys from server
    encrypted_privates = ld.get("encrypted_privates", {})
    x25519_keys = ld.get("x25519_keys", [])
    my_privates = {}

    if encrypted_privates and x25519_keys:
        for kid, enc in encrypted_privates.items():
            try:
                keys = decrypt_private_keys(enc, PASSWORD)
                xp = ExchangeKeyManager.deserialize_private_key(keys["x25519_priv"])
                my_privates[kid] = xp
            except Exception as e:
                log_fail(f"Decrypt private key {kid}: {e}")
        log_pass(f"Decrypted {len(my_privates)} private key(s) from server")
    else:
        log_fail("No encrypted_privates returned by server")
        sys.exit(1)

    # Build my own pubkey cache (for self-messaging)
    my_pubkeys = {
        "ed25519": id_pub,
        "x25519_keys": x25519_keys,
    }
    log_pass("Login successful, session established")

    # ── 6. get_my_keys ──
    print("\n--- 6. get_my_keys ---")
    p = build_authenticated_payload(session_id, session_key, seq_counter, last_ts, "get_my_keys")
    send_msg(tls_sock, p)
    gmk_resp = recv_msg(tls_sock, receiver)
    if gmk_resp and gmk_resp.get("status") == "ok":
        gd = gmk_resp["data"]
        gmk_xkeys = gd.get("x25519_keys", [])
        gmk_encs = gd.get("encrypted_privates", {})
        if len(gmk_xkeys) >= 1 and gmk_xkeys[0]["id"] == key1_id:
            log_pass(f"get_my_keys returned {len(gmk_xkeys)} key(s), latest={gmk_xkeys[0]['id']}")
        else:
            log_fail(f"get_my_keys unexpected: {gmk_xkeys}")
    else:
        log_fail(f"get_my_keys failed: {gmk_resp}")
        sys.exit(1)

    # ── 7. Rotate key (key_2) ──
    print("\n--- 7. Rotate: create key_2 ---")
    x2_priv, x2_pub = ExchangeKeyManager.generate()
    x2_pub_hex = ExchangeKeyManager.serialize_public_key(x2_pub)

    enc2 = encrypt_private_keys(
        IdentityKeyManager.serialize_private_key(id_priv),
        ExchangeKeyManager.serialize_private_key(x2_priv),
        PASSWORD,
    )

    rotate_ts = int(time.time())
    data_to_sign = f"{x2_pub_hex}{rotate_ts}".encode("utf-8")
    sig_hex = id_priv.sign(data_to_sign).hex()

    rp = build_authenticated_payload(session_id, session_key, seq_counter, last_ts, "rotate_key", {
        "new_pub": x2_pub_hex,
        "encrypted_priv": enc2,
        "timestamp": rotate_ts,
        "signature": sig_hex,
    })
    send_msg(tls_sock, rp)
    rot_resp = recv_msg(tls_sock, receiver)
    if rot_resp and rot_resp.get("status") == "ok":
        key2_id = rot_resp["data"]["key_id"]  # use server-assigned key_id
        my_privates[key2_id] = x2_priv
        log_pass(f"Rotate successful, new key_id={key2_id}")
    else:
        err = rot_resp.get("error", str(rot_resp)) if rot_resp else "no response"
        log_fail(f"Rotate failed: {err}")
        sys.exit(1)

    # ── 8. Verify rotation via get_my_keys ──
    print("\n--- 8. Verify rotation ---")
    p2 = build_authenticated_payload(session_id, session_key, seq_counter, last_ts, "get_my_keys")
    send_msg(tls_sock, p2)
    gmk2 = recv_msg(tls_sock, receiver)
    if gmk2 and gmk2.get("status") == "ok":
        xkeys2 = gmk2["data"].get("x25519_keys", [])
        encs2 = gmk2["data"].get("encrypted_privates", {})
        if len(xkeys2) == 2 and xkeys2[0]["id"] == key2_id:
            log_pass(f"Verified: {len(xkeys2)} keys, latest={xkeys2[0]['id']}")
            log_pass(f"encrypted_privates has {len(encs2)} entries")
        else:
            log_fail(f"Expected 2 keys with latest={key2_id}, got {xkeys2}")
    else:
        log_fail(f"get_my_keys after rotation failed: {gmk2}")
        sys.exit(1)

    # ── 9. Incoming message queue (for self-messages) ──
    msg_queue = queue.Queue()
    stop_recv = threading.Event()

    def recv_loop():
        r2 = PaddedReceiver()
        while not stop_recv.is_set():
            try:
                raw = r2.recv(tls_sock)
                if not raw:
                    break
                m = json.loads(raw.decode("utf-8"))
                msg_queue.put(m)
            except Exception:
                break

    recv_thread = threading.Thread(target=recv_loop, daemon=True)
    recv_thread.start()

    # ── 10. Send message to self with key_1's pub ──
    print("\n--- 10. Send message to self (encrypt to key_1 pub) ---")
    PLAIN1 = "Hello from key_1"
    enc_msg_1 = MessageEncryptorV2.encrypt(PLAIN1, x1_pub, id_priv, key_id=key1_id)
    sp = build_authenticated_payload(session_id, session_key, seq_counter, last_ts, "message", {
        "receiver": USERNAME,
        "payload": enc_msg_1,
    })
    send_msg(tls_sock, sp)

    pushed = wait_for_msg(msg_queue)
    if pushed and pushed.get("type") == "msg":
        payload = pushed["payload"]
        pkt = json.loads(payload) if isinstance(payload, str) else payload
        rcv_key_id = pkt.get("key_id", "(none)")
        if rcv_key_id == key1_id:
            log_pass(f"Received self-message, key_id={rcv_key_id}")
        else:
            log_fail(f"Expected key_id={key1_id}, got {rcv_key_id}")

        plain, err = MessageEncryptorV2.decrypt(payload, my_privates[key1_id], id_pub)
        if plain == PLAIN1:
            log_pass(f"Decrypted key_1 message: '{plain}'")
        else:
            log_fail(f"key_1 decrypt: expected '{PLAIN1}', got '{plain}' err={err}")
    else:
        log_fail("Timed out waiting for self-message (key_1)")

    # ── 11. Send message to self with key_2's pub ──
    print("\n--- 11. Send message to self (encrypt to key_2 pub) ---")
    PLAIN2 = "Hello from key_2"
    enc_msg_2 = MessageEncryptorV2.encrypt(PLAIN2, x2_pub, id_priv, key_id=key2_id)
    sp2 = build_authenticated_payload(session_id, session_key, seq_counter, last_ts, "message", {
        "receiver": USERNAME,
        "payload": enc_msg_2,
    })
    send_msg(tls_sock, sp2)

    pushed2 = wait_for_msg(msg_queue)
    if pushed2 and pushed2.get("type") == "msg":
        payload2 = pushed2["payload"]
        pkt2 = json.loads(payload2) if isinstance(payload2, str) else payload2
        rcv_key_id2 = pkt2.get("key_id", "(none)")
        if rcv_key_id2 == key2_id:
            log_pass(f"Received self-message, key_id={rcv_key_id2}")
        else:
            log_fail(f"Expected key_id={key2_id}, got {rcv_key_id2}")

        plain2, err2 = MessageEncryptorV2.decrypt(payload2, my_privates[key2_id], id_pub)
        if plain2 == PLAIN2:
            log_pass(f"Decrypted key_2 message: '{plain2}'")
        else:
            log_fail(f"key_2 decrypt: expected '{PLAIN2}', got '{plain2}' err={err2}")
    else:
        log_fail("Timed out waiting for self-message (key_2)")

    # ── 12. Cross-check: decrypt key_1 msg with key_2 priv → should FAIL ──
    print("\n--- 12. Cross-check: wrong key rejection ---")
    plain_bad, err_bad = MessageEncryptorV2.decrypt(enc_msg_1, my_privates[key2_id], id_pub)
    if plain_bad is None and err_bad is not None:
        log_pass(f"key_1 message correctly rejected by key_2 priv: {err_bad[:60]}")
    else:
        log_fail(f"key_1 message unexpectedly decrypted with key_2 priv")

    # ── 13. Logout ──
    print("\n--- 13. Logout ---")
    lp = build_authenticated_payload(session_id, session_key, seq_counter, last_ts, "logout")
    send_msg(tls_sock, lp)
    time.sleep(0.3)

    # ── Cleanup ──
    stop_recv.set()
    try:
        tls_sock.close()
    except Exception:
        pass
    cleanup_test_user()
    log_pass("Logged out and cleaned up")

    # ── Summary ──
    print(f"\n{'=' * 55}")
    print(f"RESULTS:  {passed} PASSED,  {failed} FAILED")
    print(f"{'=' * 55}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
