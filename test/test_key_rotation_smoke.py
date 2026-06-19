# -*- coding: utf-8 -*-
"""test_key_rotation_smoke.py — smoke test for X25519 key rotation.

Validates full lifecycle: register → rotate → send → receive,
using the project's own crypto primitives without any network.
"""

import json
import os
import sys
import time

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from src.common.crypto_utils import (
    IdentityKeyManager,
    ExchangeKeyManager,
    PasswordManager,
    MessageEncryptorV2,
)

# ────────────────────────────────────────────────
# helpers
# ────────────────────────────────────────────────
PASSWORD = "testpassword1"
USERNAME = "hbz"
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


def encrypt_private_keys(ed25519_priv_pem, x25519_priv_hex):
    """Encrypt both private keys as a JSON blob with the user's password."""
    keys_blob = json.dumps({
        "ed25519_priv": ed25519_priv_pem,
        "x25519_priv": x25519_priv_hex,
    }).encode("utf-8")
    salt = os.urandom(16)
    key = PasswordManager.derive_key(PASSWORD, salt)
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


def decrypt_private_keys(enc_dict):
    """Decrypt a single encrypted private-key blob."""
    salt = bytes.fromhex(enc_dict["salt"])
    nonce = bytes.fromhex(enc_dict["nonce"])
    ct = bytes.fromhex(enc_dict["ct"])
    tag = bytes.fromhex(enc_dict["tag"])
    key = PasswordManager.derive_key(PASSWORD, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plain = decryptor.update(ct) + decryptor.finalize()
    return json.loads(plain.decode("utf-8"))


# ────────────────────────────────────────────────
# 1. Setup — generate identity keys
# ────────────────────────────────────────────────
print("=== 1. Setup: generate identity keys ===")
ed_priv, ed_pub = IdentityKeyManager.generate()
ed_pub_pem = IdentityKeyManager.serialize_public_key(ed_pub)
log_pass(f"Ed25519 keypair generated (pub PEM length={len(ed_pub_pem)})")

# ────────────────────────────────────────────────
# 2. Register — key_1
# ────────────────────────────────────────────────
print("\n=== 2. Register: create key_1 ===")
x1_priv, x1_pub = ExchangeKeyManager.generate()
x1_pub_hex = ExchangeKeyManager.serialize_public_key(x1_pub)

enc1 = encrypt_private_keys(
    IdentityKeyManager.serialize_private_key(ed_priv),
    ExchangeKeyManager.serialize_private_key(x1_priv),
)

key1_id = f"{USERNAME}_key_1"
mock_db = {
    "ed25519_pub": ed_pub_pem,
    "x25519_keys": [
        {"id": key1_id, "pub_hex": x1_pub_hex, "created_at": int(time.time())}
    ],
    "encrypted_privates": {key1_id: enc1},
}
log_pass(f"key_1 stored in mock_db (id={key1_id})")

# verify round-trip
restored = decrypt_private_keys(enc1)
_ = IdentityKeyManager.deserialize_private_key(restored["ed25519_priv"])
x1_priv_rt = ExchangeKeyManager.deserialize_private_key(restored["x25519_priv"])
x1_pub_rt = x1_priv_rt.public_key()
if ExchangeKeyManager.serialize_public_key(x1_pub_rt) == x1_pub_hex:
    log_pass("key_1 round-trip encrypt/decrypt")
else:
    log_fail("key_1 round-trip pub mismatch")

# Keep the actual key object for later use
x1_priv_loaded = x1_priv_rt

# ────────────────────────────────────────────────
# 3. Rotate — key_2
# ────────────────────────────────────────────────
print("\n=== 3. Rotate: create key_2 ===")
x2_priv, x2_pub = ExchangeKeyManager.generate()
x2_pub_hex = ExchangeKeyManager.serialize_public_key(x2_pub)

enc2 = encrypt_private_keys(
    IdentityKeyManager.serialize_private_key(ed_priv),
    ExchangeKeyManager.serialize_private_key(x2_priv),
)

key2_id = f"{USERNAME}_key_2"
mock_db["x25519_keys"].insert(0, {"id": key2_id, "pub_hex": x2_pub_hex, "created_at": int(time.time())})
mock_db["encrypted_privates"][key2_id] = enc2
log_pass(f"key_2 appended (id={key2_id}), x25519_keys now has {len(mock_db['x25519_keys'])} entries")
log_pass(f"encrypted_privates now has {len(mock_db['encrypted_privates'])} entries")

# verify round-trip
restored2 = decrypt_private_keys(enc2)
x2_priv_rt = ExchangeKeyManager.deserialize_private_key(restored2["x25519_priv"])
x2_pub_rt = x2_priv_rt.public_key()
if ExchangeKeyManager.serialize_public_key(x2_pub_rt) == x2_pub_hex:
    log_pass("key_2 round-trip encrypt/decrypt")
else:
    log_fail("key_2 round-trip pub mismatch")

x2_priv_loaded = x2_priv_rt

# ────────────────────────────────────────────────
# 4. Encrypt messages — one to key_1 pub, one to key_2 pub
# ────────────────────────────────────────────────
print("\n=== 4. Encrypt messages ===")
PLAINTEXT = "Hello"

# Message A: encrypt to key_1's pub → must be decrypted with key_1's priv
recip_pub_1 = x1_pub_rt
enc_msg_1 = MessageEncryptorV2.encrypt(PLAINTEXT, recip_pub_1, ed_priv, key_id=key1_id)
pkt1 = json.loads(enc_msg_1)
if pkt1.get("key_id") == key1_id:
    log_pass(f"Message A carries sender key_id={key1_id}")
else:
    log_fail(f"Message A missing key_id (got {pkt1.get('key_id')})")

# Message B: encrypt to key_2's pub → must be decrypted with key_2's priv
recip_pub_2 = x2_pub_rt
enc_msg_2 = MessageEncryptorV2.encrypt(PLAINTEXT, recip_pub_2, ed_priv, key_id=key2_id)
pkt2 = json.loads(enc_msg_2)
if pkt2.get("key_id") == key2_id:
    log_pass(f"Message B carries sender key_id={key2_id}")
else:
    log_fail(f"Message B missing key_id (got {pkt2.get('key_id')})")

# ────────────────────────────────────────────────
# 5. Decrypt messages using correct key per key_id
# ────────────────────────────────────────────────
print("\n=== 5. Decrypt messages ===")

# Build local private-key lookup (simulates client state after login)
local_privates = {
    key1_id: x1_priv_loaded,
    key2_id: x2_priv_loaded,
}

def receive_message(enc_json_str, sender_ed_pub):
    """Simulate receiver: extract key_id, find matching priv, decrypt."""
    pkt = json.loads(enc_json_str) if isinstance(enc_json_str, str) else enc_json_str
    kid = pkt.get("key_id")
    if kid is None:
        log_fail(f"Decrypt: no key_id in packet")
        return None
    priv = local_privates.get(kid)
    if priv is None:
        # fallback: try to load from mock_db
        enc = mock_db["encrypted_privates"].get(kid)
        if not enc:
            log_fail(f"Decrypt: key_id={kid} not found in local or mock_db")
            return None
        restored = decrypt_private_keys(enc)
        priv = ExchangeKeyManager.deserialize_private_key(restored["x25519_priv"])
        local_privates[kid] = priv
        print(f"    (loaded key_id={kid} from mock_db encrypted_privates on-the-fly)")
    plain, err = MessageEncryptorV2.decrypt(enc_json_str, priv, sender_ed_pub)
    if err:
        log_fail(f"Decrypt with key_id={kid}: {err}")
        return None
    return plain

# Decrypt key_1 message
result1 = receive_message(enc_msg_1, ed_pub)
if result1 == PLAINTEXT:
    log_pass(f"key_1 message decrypted: '{result1}'")
else:
    log_fail(f"key_1 message: expected '{PLAINTEXT}', got '{result1}'")

# Decrypt key_2 message
result2 = receive_message(enc_msg_2, ed_pub)
if result2 == PLAINTEXT:
    log_pass(f"key_2 message decrypted: '{result2}'")
else:
    log_fail(f"key_2 message: expected '{PLAINTEXT}', got '{result2}'")

# ────────────────────────────────────────────────
# 6. Cross-check: message encrypted to key_2 pub → cannot decrypt with key_1 priv
# ────────────────────────────────────────────────
print("\n=== 6. Cross-check: wrong key ===")
# Attempt to decrypt key_2-encrypted message with key_1 priv
plain_bad, err_bad = MessageEncryptorV2.decrypt(enc_msg_2, x1_priv_loaded, ed_pub)
if plain_bad is None and err_bad is not None:
    log_pass(f"Message B rejected by key_1 priv (expected): {err_bad[:60]}")
else:
    log_fail(f"Message B unexpectedly decrypted with key_1 priv")

# ────────────────────────────────────────────────
# 7. Cold-start round-trip through mock_db
# ────────────────────────────────────────────────
print("\n=== 7. Cold-start through mock_db ===")
# Load key_1 from mock_db as if from server; decrypt message A
enc1_db = mock_db["encrypted_privates"][key1_id]
restored_cold = decrypt_private_keys(enc1_db)
x1_priv_cold = ExchangeKeyManager.deserialize_private_key(restored_cold["x25519_priv"])
plain_cold, err_cold = MessageEncryptorV2.decrypt(enc_msg_1, x1_priv_cold, ed_pub)
if plain_cold == PLAINTEXT:
    log_pass(f"Cold-start decrypt Message A (key_1): '{plain_cold}'")
else:
    log_fail(f"Cold-start Message A: '{plain_cold}' err={err_cold}")

# Load key_2 from mock_db; decrypt message B
enc2_db = mock_db["encrypted_privates"][key2_id]
restored_cold2 = decrypt_private_keys(enc2_db)
x2_priv_cold = ExchangeKeyManager.deserialize_private_key(restored_cold2["x25519_priv"])
plain_cold2, err_cold2 = MessageEncryptorV2.decrypt(enc_msg_2, x2_priv_cold, ed_pub)
if plain_cold2 == PLAINTEXT:
    log_pass(f"Cold-start decrypt Message B (key_2): '{plain_cold2}'")
else:
    log_fail(f"Cold-start Message B: '{plain_cold2}' err={err_cold2}")

# ────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────
print(f"\n{'='*50}")
print(f"RESULTS:  {passed} PASSED,  {failed} FAILED")
print(f"{'='*50}")
sys.exit(0 if failed == 0 else 1)
