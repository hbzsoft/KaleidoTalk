# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


# server_storage.py — 数据持久化层
import threading
import json
import os
import re
import logging

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# 文件锁
locks = {
    'bans_file': threading.Lock(),
    'users_file': threading.Lock(),
    'keys_file': threading.Lock(),
    'invites_file': threading.Lock(),
}

# ----------------------------------------------------------------------
# 文件路径
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
# 文件操作（带锁）
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
    return load_data(KEYS_FILE, {})
def save_user_keys(keys):
    save_data(KEYS_FILE, keys)

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
# 密码强度检查
def is_password_strong(password):
    if len(password) < 8:
        return False, "密码长度至少 8 位"
    if not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password):
        return False, "密码必须包含字母和数字"
    if password.lower() in WEAK_PASSWORDS:
        return False, "该密码为常见弱密码，请更换"
    return True, "OK"

# ----------------------------------------------------------------------
# 邀请码
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
