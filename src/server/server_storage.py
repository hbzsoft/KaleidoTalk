# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


# server_storage.py - data persistence layer
import threading
import json
import os
import re
import time
import logging

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# File locks
locks = {
    'bans_file': threading.Lock(),
    'users_file': threading.Lock(),
    'keys_file': threading.Lock(),
    'invites_file': threading.Lock(),
}

# ----------------------------------------------------------------------
# File paths
USERS_FILE = 'users.json'
KEYS_FILE = 'user_keys.json'
INVITES_FILE = 'invite_codes.json'
BANS_FILE = 'bans.json'
WEAK_PASSWORDS = {
    '12345678', 'password', '123456789', '1234567890',
    'qwerty123', 'abc123456', 'password1', 'iloveyou',
    'admin123', 'letmein12', 'monkey123', 'football'
}

# ----------------------------------------------------------------------
# File operations (with locking)
def load_data(filename, default=None):
    if default is None:
        default = {}
    lock = locks['users_file'] if filename == USERS_FILE else locks['keys_file']
    with lock:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return default

def save_data(filename, data):
    lock = locks['users_file'] if filename == USERS_FILE else locks['keys_file']
    with lock:
        temp = filename + '.tmp'
        with open(temp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(temp, filename)

def load_users():
    return load_data(USERS_FILE, {})
def save_users(users):
    save_data(USERS_FILE, users)

def load_user_keys():
    data = load_data(KEYS_FILE, {})
    # Auto-migrate old format (single x25519_pub) to new format (x25519_keys list)
    migrated = False
    for username, kd in list(data.items()):
        if 'x25519_keys' not in kd and 'x25519_pub' in kd:
            key_id = f"{username}_{kd.get('reg_date', '0').replace(' ', 'T').replace(':','-')}_0"
            data[username] = {
                'ed25519_pub': kd.get('ed25519_pub', ''),
                'x25519_keys': [
                    {'id': key_id, 'pub_hex': kd['x25519_pub'], 'created_at': int(time.time())}
                ],
                'store_private_key': kd.get('store_private_key', True),
                'reg_date': kd.get('reg_date', ''),
            }
            if 'encrypted_private' in kd:
                data[username]['encrypted_privates'] = {key_id: kd['encrypted_private']}
            migrated = True
        # Ensure freeze fields exist (backfill for existing users)
        if 'frozen' not in kd:
            kd['frozen'] = False
            migrated = True
        if 'used_nonces' not in kd:
            kd['used_nonces'] = []
            migrated = True
    if migrated:
        save_user_keys(data)
        logger.info("Migrated user_keys.json to new format")
    return data
def save_user_keys(keys):
    save_data(KEYS_FILE, keys)


def is_user_frozen(username):
    """Check if a user is frozen. Returns (frozen_bool, reason_or_None)."""
    data = load_user_keys()
    kd = data.get(username, {})
    if kd.get('frozen', False):
        return True, 'account frozen'
    return False, None

def load_invites():
    if not os.path.exists(INVITES_FILE):
        return {'require_invite': False, 'codes': {}}
    with locks['invites_file']:
        try:
            with open(INVITES_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            return {'require_invite': False, 'codes': {}}
    require = data.get('require_invite', False)
    codes = {}
    for code, info in data.get('codes', {}).items():
        if isinstance(info, dict):
            codes[code] = {
                'remaining': max(0, int(info.get('remaining', 0))),
                'created_at': info.get('created_at', '')
            }
        elif isinstance(info, int):
            codes[code] = {'remaining': max(0, info), 'created_at': ''}
    return {'require_invite': require, 'codes': codes}

def save_invites(invites):
    with locks['invites_file']:
        temp = INVITES_FILE + '.tmp'
        with open(temp, 'w', encoding='utf-8') as f:
            json.dump(invites, f, indent=2, ensure_ascii=False)
        os.replace(temp, INVITES_FILE)


def load_bans_file():
    if not os.path.exists(BANS_FILE):
        return {'ip_bans': {}, 'user_bans': {}}
    with locks['bans_file']:
        try:
            with open(BANS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {'ip_bans': {}, 'user_bans': {}}

def save_bans_file(bans):
    with locks['bans_file']:
        temp = BANS_FILE + '.tmp'
        with open(temp, 'w', encoding='utf-8') as f:
            json.dump(bans, f, indent=2, ensure_ascii=False)
        os.replace(temp, BANS_FILE)


# ----------------------------------------------------------------------
# Password strength check
def is_password_strong(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password):
        return False, "Password must include both letters and numbers"
    if password.lower() in WEAK_PASSWORDS:
        return False, "This is a common weak password, please choose another"
    return True, "OK"

# ----------------------------------------------------------------------
# Invite codes
def require_invite_code():
    return load_invites()['require_invite']

def verify_invite(code_str):
    if not require_invite_code():
        return True, 'invite_not_required'
    code_str = (code_str or '').strip()
    if not code_str:
        return False, 'invite_required'
    invites = load_invites()
    if code_str not in invites['codes']:
        return False, 'invalid_invite_code'
    item = invites['codes'][code_str]
    if item['remaining'] <= 0:
        return False, 'invite_code_exhausted'
    return True, 'invite_valid'


def consume_invite(code_str):
    if not require_invite_code():
        return True, 'invite_not_required'
    code_str = (code_str or '').strip()
    if not code_str:
        return False, 'invite_required'
    invites = load_invites()
    item = invites['codes'].get(code_str)
    if not item:
        return False, 'invalid_invite_code'
    if item['remaining'] <= 0:
        return False, 'invite_code_exhausted'
    item['remaining'] -= 1
    invites['codes'][code_str] = item
    save_invites(invites)
    return True, 'invite_accepted'
