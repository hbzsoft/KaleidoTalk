# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


"""Local administrator script (directly edit local configuration files, no network connection required)

Usage examples:
  python admin.py invites add --count 5 --uses 1 --length 8
  python admin.py invites delete CODE123
  python admin.py invites set-require true
  python admin.py invites list
  
  python admin.py ban ip 1.2.3.4 --duration 3600
  python admin.py ban user alice
  python admin.py unban ip 1.2.3.4
  python admin.py unban user alice
  python admin.py list-bans
  
  python admin.py users list          # List all registered users
    python admin.py users delete alice  # Delete user

Notes:
  - This script directly reads and writes server local configuration files (invite_codes.json, bans.json, users.json, user_keys.json)
  - No need to start the server, no network connection required
  - Requires file system permissions to access the above configuration files
"""
import argparse
import json
import os
import secrets
import string
import time
import sys
from datetime import datetime

# Configuration file paths (relative to script running directory)
INVITE_FILE = 'invite_codes.json'
BANS_FILE = 'bans.json'
USERS_FILE = 'users.json'
KEYS_FILE = 'user_keys.json'

ALPHABET = string.ascii_uppercase + string.digits


def load_json(path, default=None):
    """Safely load JSON file"""
    if default is None:
        default = {}
    if not os.path.exists(path):
        return default
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    """Safely save JSON file (write temp file then rename)"""
    temp = path + '.tmp'
    with open(temp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(temp, path)


def load_invites():
    """Load invite code configuration"""
    data = load_json(INVITE_FILE, {'require_invite': False, 'codes': {}})
    if not isinstance(data, dict):
        return {'require_invite': False, 'codes': {}}
    require_invite = bool(data.get('require_invite', False))
    codes = data.get('codes', {})
    if not isinstance(codes, dict):
        codes = {}
    normalized = {}
    for code, item in codes.items():
        if not isinstance(code, str) or not code:
            continue
        if isinstance(item, dict):
            try:
                remaining = int(item.get('remaining', 0))
            except Exception:
                remaining = 0
            created_at = item.get('created_at', '') if isinstance(item.get('created_at', ''), str) else ''
        elif isinstance(item, int):
            remaining = item
            created_at = ''
        else:
            remaining = 0
            created_at = ''
        normalized[code] = {'remaining': max(0, remaining), 'created_at': created_at}
    return {'require_invite': require_invite, 'codes': normalized}


def save_invites(data):
    """Save invite code configuration"""
    save_json(INVITE_FILE, data)


def load_bans():
    """Load ban list"""
    return load_json(BANS_FILE, {'ip_bans': {}, 'user_bans': {}})


def save_bans(data):
    """Save ban list"""
    save_json(BANS_FILE, data)


def load_users():
    """Load user password table"""
    return load_json(USERS_FILE, {})


def save_users(data):
    """Save user password table"""
    save_json(USERS_FILE, data)


def load_user_keys():
    """Load user key table"""
    return load_json(KEYS_FILE, {})


def save_user_keys(data):
    """Save user key table"""
    save_json(KEYS_FILE, data)


def generate_unique_code(existing, length):
    """Generate unique invite code"""
    while True:
        code = ''.join(secrets.choice(ALPHABET) for _ in range(length))
        if code not in existing:
            return code


# =============================================================================
# Invite code management commands
# =============================================================================

def cmd_invites_add(args):
    """Add invite code"""
    data = load_invites()
    existing = set(data['codes'].keys())
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    new_codes = []
    for _ in range(args.count):
        code = generate_unique_code(existing, args.length)
        existing.add(code)
        data['codes'][code] = {'remaining': args.uses, 'created_at': now}
        new_codes.append(code)
    save_invites(data)
    print(f'Number of new invite codes: {len(new_codes)}')
    for c in new_codes:
        print(c)


def cmd_invites_delete(args):
    """Delete invite code"""
    data = load_invites()
    removed = []
    for code in args.codes:
        if code in data['codes']:
            data['codes'].pop(code, None)
            removed.append(code)
    save_invites(data)
    print('Deleted:', removed)


def cmd_invites_set_require(args):
    """Set whether invite code is required for registration"""
    data = load_invites()
    data['require_invite'] = args.value
    save_invites(data)
    print('require_invite set to', args.value)


def cmd_invites_list(args):
    """List all invite codes"""
    data = load_invites()
    print(f'require_invite = {data.get("require_invite", False)}')
    print('Invite code list:')
    codes = data.get('codes', {})
    if not codes:
        print('  (none)')
    for code, info in codes.items():
        remaining = info.get('remaining', 0) if isinstance(info, dict) else info
        created = info.get('created_at', '') if isinstance(info, dict) else ''
        print(f"  {code}: remaining uses={remaining}, created at={created}")


# =============================================================================
# Ban management commands
# =============================================================================

def cmd_ban_ip(args):
    """Ban IP"""
    bans = load_bans()
    until = 0
    if args.duration:
        until = int(time.time()) + int(args.duration)
    bans.setdefault('ip_bans', {})[args.target] = until
    save_bans(bans)
    if until:
        print(f'Banned IP {args.target} until {datetime.fromtimestamp(until)}')
    else:
        print(f'Permanently banned IP {args.target}')


def cmd_unban_ip(args):
    """Unban IP"""
    bans = load_bans()
    if args.target in bans.get('ip_bans', {}):
        bans['ip_bans'].pop(args.target, None)
        save_bans(bans)
        print('Unbanned IP', args.target)
    else:
        print('Ban record not found:', args.target)


def cmd_ban_user(args):
    """Ban user"""
    bans = load_bans()
    bans.setdefault('user_bans', {})[args.target] = True
    save_bans(bans)
    print('Banned user', args.target)


def cmd_unban_user(args):
    """Unban user"""
    bans = load_bans()
    if args.target in bans.get('user_bans', {}):
        bans['user_bans'].pop(args.target, None)
        save_bans(bans)
        print('Unbanned user', args.target)
    else:
        print('Ban record not found:', args.target)


def cmd_list_bans(args):
    """List all bans"""
    bans = load_bans()
    print('IP bans:')
    ip_bans = bans.get('ip_bans', {})
    if not ip_bans:
        print('  (none)')
    for ip, until in ip_bans.items():
        if until and until > 0:
            print(f'  {ip} -> expiration time: {datetime.fromtimestamp(until)}')
        else:
            print(f'  {ip} -> permanently banned')
    print('\nUser bans:')
    user_bans = bans.get('user_bans', {})
    if not user_bans:
        print('  (none)')
    for u in user_bans.keys():
        print(f'  {u}')


# =============================================================================
# User management commands
# =============================================================================

def cmd_users_list(args):
    """List all registered users"""
    users = load_users()
    user_keys = load_user_keys()
    
    print('Registered users list:')
    if not users and not user_keys:
        print('  (none)')
        return
    
    all_usernames = set(users.keys()) | set(user_keys.keys())
    for username in sorted(all_usernames):
        has_password = username in users
        has_keys = username in user_keys
        store_private = False
        if has_keys:
            store_private = user_keys[username].get('store_private_key', False)
        
        status = []
        if has_password:
            status.append('has password')
        if has_keys:
            status.append('has keys')
        if store_private:
            status.append('private key stored on server')
        
        print(f'  {username}: {", ".join(status) if status else "(incomplete data)"}')


def cmd_users_delete(args):
    """Delete user (also delete password and keys)"""
    username = args.target
    
    users = load_users()
    user_keys = load_user_keys()
    
    deleted = False
    
    if username in users:
        del users[username]
        save_users(users)
        deleted = True
        print(f'Deleted user {username}  password record')
    
    if username in user_keys:
        del user_keys[username]
        save_user_keys(user_keys)
        deleted = True
        print(f'Deleted user {username}  key record')
    
    if not deleted:
        print(f'User {username} does not exist')
        sys.exit(1)
    else:
        print(f'User {username} completely deleted')


# =============================================================================
# Main function
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Local administrator script (directly edit configuration files, no network required)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Invite code management
  python admin.py invites add --count 5 --uses 1 --length 8
  python admin.py invites delete CODE123
  python admin.py invites set-require true
  python admin.py invites list

  # Ban management
  python admin.py ban ip 1.2.3.4 --duration 3600
  python admin.py ban user alice
  python admin.py unban ip 1.2.3.4
  python admin.py unban user alice
  python admin.py list-bans

  # User management
  python admin.py users list
  python admin.py users delete alice
        '''
    )
    sub = parser.add_subparsers(dest='cmd', help='Available commands')

    # -------------------------------------------------------------------------
    # invites subcommand
    # -------------------------------------------------------------------------
    invites = sub.add_parser('invites', help='Manage invite codes')
    invites_sub = invites.add_subparsers(dest='action', help='Invite code operations')
    
    a_add = invites_sub.add_parser('add', help='Add invite code')
    a_add.add_argument('--count', type=int, default=10, help='Number to generate')
    a_add.add_argument('--uses', type=int, default=1, help='Uses per invite code')
    a_add.add_argument('--length', type=int, default=10, help='Invite code length')
    a_add.set_defaults(func=cmd_invites_add)

    a_del = invites_sub.add_parser('delete', help='Delete invite code')
    a_del.add_argument('codes', nargs='+', help='Invite codes to delete')
    a_del.set_defaults(func=cmd_invites_delete)

    a_req = invites_sub.add_parser('set-require', help='Set whether invite code is required for registration')
    a_req.add_argument('value', choices=['true', 'false'], help='true=required, false=not required')
    a_req.set_defaults(func=lambda args: cmd_invites_set_require(type('X', (object,), {'value': args.value == 'true'})))

    a_list = invites_sub.add_parser('list', help='List all invite codes')
    a_list.set_defaults(func=cmd_invites_list)

    # -------------------------------------------------------------------------
    # ban subcommand
    # -------------------------------------------------------------------------
    bans = sub.add_parser('ban', help='Ban IP or user')
    bans_sub = bans.add_subparsers(dest='what', help='Type of ban target')
    
    b_ip = bans_sub.add_parser('ip', help='Ban IP address')
    b_ip.add_argument('target', help='IP address')
    b_ip.add_argument('--duration', type=int, default=0, help='Ban duration in seconds (blank or 0 means permanent)')
    b_ip.set_defaults(func=cmd_ban_ip)
    
    b_user = bans_sub.add_parser('user', help='Ban user')
    b_user.add_argument('target', help='Username')
    b_user.set_defaults(func=cmd_ban_user)

    # -------------------------------------------------------------------------
    # unban subcommand
    # -------------------------------------------------------------------------
    unb = sub.add_parser('unban', help='Unban IP or user')
    unb_sub = unb.add_subparsers(dest='what', help='Type of unban target')
    
    ub_ip = unb_sub.add_parser('ip', help='Unban IP address')
    ub_ip.add_argument('target', help='IP address')
    ub_ip.set_defaults(func=cmd_unban_ip)
    
    ub_user = unb_sub.add_parser('user', help='Unban user')
    ub_user.add_argument('target', help='Username')
    ub_user.set_defaults(func=cmd_unban_user)

    # -------------------------------------------------------------------------
    # list-bans command
    # -------------------------------------------------------------------------
    blist = sub.add_parser('list-bans', help='List all bans')
    blist.set_defaults(func=cmd_list_bans)

    # -------------------------------------------------------------------------
    # users subcommand
    # -------------------------------------------------------------------------
    users = sub.add_parser('users', help='Manage users')
    users_sub = users.add_subparsers(dest='action', help='User operations')
    
    u_list = users_sub.add_parser('list', help='List all users')
    u_list.set_defaults(func=cmd_users_list)
    
    u_del = users_sub.add_parser('delete', help='Delete user')
    u_del.add_argument('target', help='Username to delete')
    u_del.set_defaults(func=cmd_users_delete)

    # -------------------------------------------------------------------------
    # Parse and execute
    # -------------------------------------------------------------------------
    args = parser.parse_args()
    if not hasattr(args, 'func'):
        parser.print_help()
        return
    args.func(args)


if __name__ == '__main__':
    main()

