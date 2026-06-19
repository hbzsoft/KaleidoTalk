# -*- coding: utf-8 -*-
"""test_freeze_smoke.py — standalone smoke test for account freeze flow.

Simulates the entire freeze lifecycle using an in-memory mock_db,
with zero network dependencies.  Validates all server-side checks:
signature verification, nonce replay protection, already-frozen
rejection, wrong-key rejection, and timestamp expiry.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.common.crypto_utils import IdentityKeyManager

# ────────────────────────────────────────────────
# Test constants
# ────────────────────────────────────────────────
USERNAME = "smoketest"
TIMESTAMP_WINDOW = 300  # seconds (5 minutes), same as server

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
# Step 1 — Generate keypairs
# ────────────────────────────────────────────────
print("=== 1. Generate Ed25519 recovery keypair and identity keypair ===")
recovery_priv, recovery_pub = IdentityKeyManager.generate()
id_priv, id_pub = IdentityKeyManager.generate()
recovery_pub_pem = IdentityKeyManager.serialize_public_key(recovery_pub)
id_pub_pem = IdentityKeyManager.serialize_public_key(id_pub)
log_pass("Ed25519 recovery keypair generated")
log_pass("Ed25519 identity keypair generated")


# ────────────────────────────────────────────────
# Step 2 — Store user data in mock_db
# ────────────────────────────────────────────────
print("\n=== 2. Store user data in mock_db ===")
mock_db = {
    "ed25519_pub": id_pub_pem,
    "recovery_pub": recovery_pub_pem,
    "frozen": False,
    "used_nonces": [],
    "x25519_keys": [],
    "encrypted_privates": {},
}
log_pass("mock_db initialized: ed25519_pub, recovery_pub, frozen=False, used_nonces=[]")


# ────────────────────────────────────────────────
# Helper — simulate a single freeze attempt
# ────────────────────────────────────────────────
def attempt_freeze(username, timestamp, nonce, signature_hex):
    """Run the server-side freeze logic against mock_db.
    Returns (accepted: bool, error: str or None).
    """
    kd = mock_db  # in a real server this is user_keys[username]

    # 1. Missing params (shouldn't happen from test, but guard)
    if not username or not timestamp or not nonce or not signature_hex:
        return False, "Missing freeze parameters"

    # 2. Timestamp window check
    if abs(int(time.time()) - int(timestamp)) > TIMESTAMP_WINDOW:
        return False, "Timestamp expired"

    # 3. Recovery key exists?
    recovery_pub_pem_local = kd.get("recovery_pub")
    if not recovery_pub_pem_local:
        return False, "No recovery key set for this account"

    # 4. Already frozen?
    if kd.get("frozen", False):
        return False, "Account already frozen"

    # 5. Verify recovery signature
    try:
        recovery_pub_local = IdentityKeyManager.deserialize_public_key(recovery_pub_pem_local)
        sig_bytes = bytes.fromhex(signature_hex)
        data_to_sign = f"{username}{timestamp}{nonce}".encode("utf-8")
        if not IdentityKeyManager.verify(recovery_pub_local, sig_bytes, data_to_sign):
            return False, "Recovery signature verification failed"
    except Exception:
        return False, "Recovery signature verification failed"

    # 6. Nonce replay check
    used = kd.setdefault("used_nonces", [])
    if nonce in used:
        return False, "Nonce already used"

    # 7. Commit freeze
    used.append(nonce)
    if len(used) > 100:
        kd["used_nonces"] = used[-100:]
    kd["frozen"] = True
    return True, None


# ────────────────────────────────────────────────
# Step 3 — Test: Valid freeze
# ────────────────────────────────────────────────
print("\n=== 3. Test: Valid freeze ===")
freeze_ts = int(time.time())
nonce = os.urandom(16).hex()
data_to_sign = f"{USERNAME}{freeze_ts}{nonce}".encode("utf-8")
signature = recovery_priv.sign(data_to_sign).hex()

accepted, err = attempt_freeze(USERNAME, freeze_ts, nonce, signature)
if accepted and mock_db["frozen"]:
    log_pass("Freeze accepted, frozen=True")
else:
    log_fail(f"Freeze should have been accepted, got err={err}")


# ────────────────────────────────────────────────
# Step 4 — Test: Nonce replay
# ────────────────────────────────────────────────
print("\n=== 4. Test: Nonce replay ===")
# Temporarily un-freeze to isolate the nonce check from already-frozen
mock_db["frozen"] = False
accepted2, err2 = attempt_freeze(USERNAME, freeze_ts, nonce, signature)
mock_db["frozen"] = True  # restore
if not accepted2 and err2 == "Nonce already used":
    log_pass("Nonce replay correctly rejected")
else:
    log_fail(f"Nonce replay should have been rejected, got accepted={accepted2} err={err2}")


# ────────────────────────────────────────────────
# Step 5 — Test: Tampered signature
# ────────────────────────────────────────────────
print("\n=== 5. Test: Signature verification (tampered) ===")
new_ts = int(time.time())
new_nonce = os.urandom(16).hex()
new_data = f"{USERNAME}{new_ts}{new_nonce}".encode("utf-8")
valid_sig_bytes = recovery_priv.sign(new_data)
# Flip the first byte to tamper
tampered_sig_bytes = bytes([valid_sig_bytes[0] ^ 0xFF]) + valid_sig_bytes[1:]
tampered_sig_hex = tampered_sig_bytes.hex()

# Undo the freeze so we can test
mock_db["frozen"] = False

accepted3, err3 = attempt_freeze(USERNAME, new_ts, new_nonce, tampered_sig_hex)
if not accepted3 and "signature" in (err3 or "").lower():
    log_pass("Tampered signature correctly fails verification")
else:
    log_fail(f"Tampered signature should have failed, got accepted={accepted3} err={err3}")

# Restore frozen state for next test
mock_db["frozen"] = True


# ────────────────────────────────────────────────
# Step 6 — Test: Already frozen
# ────────────────────────────────────────────────
print("\n=== 6. Test: Already frozen ===")
accepted4, err4 = attempt_freeze(USERNAME, freeze_ts, nonce + "_new", signature)
if not accepted4 and err4 == "Account already frozen":
    log_pass("Already-frozen account correctly returns 'already frozen'")
else:
    log_fail(f"Already-frozen should have been rejected, got accepted={accepted4} err={err4}")


# ────────────────────────────────────────────────
# Step 7 — Test: Wrong key
# ────────────────────────────────────────────────
print("\n=== 7. Test: Wrong key ===")
wrong_priv, wrong_pub = IdentityKeyManager.generate()
wrong_ts = int(time.time())
wrong_nonce = os.urandom(16).hex()
wrong_data = f"{USERNAME}{wrong_ts}{wrong_nonce}".encode("utf-8")
wrong_sig = wrong_priv.sign(wrong_data).hex()

# Temporarily un-freeze to check signature separately
mock_db["frozen"] = False
accepted5, err5 = attempt_freeze(USERNAME, wrong_ts, wrong_nonce, wrong_sig)
if not accepted5 and "signature" in (err5 or "").lower():
    log_pass("Wrong key: signature correctly fails verification")
else:
    log_fail(f"Wrong key should have been rejected, got accepted={accepted5} err={err5}")

mock_db["frozen"] = True


# ────────────────────────────────────────────────
# Step 8 — Test: Timestamp expired
# ────────────────────────────────────────────────
print("\n=== 8. Test: Timestamp expired ===")
old_ts = int(time.time()) - 600  # 10 minutes ago
old_nonce = os.urandom(16).hex()
old_data = f"{USERNAME}{old_ts}{old_nonce}".encode("utf-8")
old_sig = recovery_priv.sign(old_data).hex()

# Un-freeze to isolate the timestamp check
mock_db["frozen"] = False
accepted6, err6 = attempt_freeze(USERNAME, old_ts, old_nonce, old_sig)
if not accepted6 and err6 == "Timestamp expired":
    log_pass("Timestamp expired: correctly rejected (>5 min old)")
else:
    log_fail(f"Timestamp expired should have been rejected, got accepted={accepted6} err={err6}")

# Restore
mock_db["frozen"] = True


# ────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────
print(f"\n{'=' * 50}")
print(f"RESULTS:  {passed} PASSED,  {failed} FAILED")
print(f"{'=' * 50}")
sys.exit(0 if failed == 0 else 1)
