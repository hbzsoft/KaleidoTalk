# Copyright (C) 2026 Bangze Han

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.

"""本地管理员脚本（仅在服务器本机运行）

用法示例:
  python admin.py invites add --count 5 --uses 1 --length 8
  python admin.py invites delete CODE123
  python admin.py invites set-require true
  python admin.py ban ip 1.2.3.4 --duration 3600
  python admin.py unban ip 1.2.3.4
  python admin.py ban user alice
  python admin.py unban user alice
"""
import argparse
import json
import os
import secrets
import string
import time
from datetime import datetime

from crypto_utils import ServerCrypto

ALPHABET = string.ascii_uppercase + string.digits
INVITE_FILE = 'invite_codes.json'
BANS_FILE = 'bans.json'


def load_invites(path):
    if not os.path.exists(path):
        return {'require_invite': False, 'codes': {}}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        return {'require_invite': False, 'codes': {}}
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


def save_invites(path, data):
    temp = path + '.tmp'
    with open(temp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(temp, path)


def generate_unique_code(existing, length):
    while True:
        code = ''.join(secrets.choice(ALPHABET) for _ in range(length))
        if code not in existing:
            return code


def load_bans(path):
    if not os.path.exists(path):
        return {'ip_bans': {}, 'user_bans': {}}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {'ip_bans': {}, 'user_bans': {}}


def save_bans(path, data):
    temp = path + '.tmp'
    with open(temp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(temp, path)


def require_admin_password():
    # 交互式输入管理员密码并尝试加载服务器密钥以验证密码
    import getpass

    pwd = getpass.getpass('管理员密码: ')
    try:
        ServerCrypto.initialize(pwd)
    except Exception as e:
        print('管理员密码验证失败或密钥文件错误:', e)
        return None
    return pwd


def cmd_invites_add(args):
    pwd = require_admin_password()
    if not pwd:
        return
    data = load_invites(INVITE_FILE)
    existing = set(data['codes'].keys())
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    new_codes = []
    for _ in range(args.count):
        code = generate_unique_code(existing, args.length)
        existing.add(code)
        data['codes'][code] = {'remaining': args.uses, 'created_at': now}
        new_codes.append(code)
    save_invites(INVITE_FILE, data)
    print('新增邀请码数量:', len(new_codes))
    for c in new_codes:
        print(c)


def cmd_invites_delete(args):
    pwd = require_admin_password()
    if not pwd:
        return
    data = load_invites(INVITE_FILE)
    removed = []
    for code in args.codes:
        if code in data['codes']:
            data['codes'].pop(code, None)
            removed.append(code)
    save_invites(INVITE_FILE, data)
    print('已删除:', removed)


def cmd_invites_set_require(args):
    pwd = require_admin_password()
    if not pwd:
        return
    data = load_invites(INVITE_FILE)
    data['require_invite'] = args.value
    save_invites(INVITE_FILE, data)
    print('require_invite 已设置为', args.value)


def cmd_ban_ip(args):
    pwd = require_admin_password()
    if not pwd:
        return
    bans = load_bans(BANS_FILE)
    until = 0
    if args.duration:
        until = int(time.time()) + int(args.duration)
    bans.setdefault('ip_bans', {})[args.target] = until
    save_bans(BANS_FILE, bans)
    if until:
        print(f'已封禁 IP {args.target} 到 {datetime.fromtimestamp(until)}')
    else:
        print(f'已永久封禁 IP {args.target}')


def cmd_unban_ip(args):
    pwd = require_admin_password()
    if not pwd:
        return
    bans = load_bans(BANS_FILE)
    if args.target in bans.get('ip_bans', {}):
        bans['ip_bans'].pop(args.target, None)
        save_bans(BANS_FILE, bans)
        print('已解封 IP', args.target)
    else:
        print('未找到封禁记录:', args.target)


def cmd_ban_user(args):
    pwd = require_admin_password()
    if not pwd:
        return
    bans = load_bans(BANS_FILE)
    bans.setdefault('user_bans', {})[args.target] = True
    save_bans(BANS_FILE, bans)
    print('已封禁用户', args.target)


def cmd_unban_user(args):
    pwd = require_admin_password()
    if not pwd:
        return
    bans = load_bans(BANS_FILE)
    if args.target in bans.get('user_bans', {}):
        bans['user_bans'].pop(args.target, None)
        save_bans(BANS_FILE, bans)
        print('已解封用户', args.target)
    else:
        print('未找到封禁记录:', args.target)


def cmd_list_bans(args):
    bans = load_bans(BANS_FILE)
    print('IP 封禁:')
    for ip, until in bans.get('ip_bans', {}).items():
        if until and until > 0:
            print(f'  {ip} -> until {datetime.fromtimestamp(until)}')
        else:
            print(f'  {ip} -> permanent')
    print('\n用户封禁:')
    for u in bans.get('user_bans', {}).keys():
        print(f'  {u}')


def cmd_list_invites(args):
    data = load_invites(INVITE_FILE)
    print('require_invite =', data.get('require_invite', False))
    print('codes:')
    for code, info in data.get('codes', {}).items():
        print(f"  {code}: remaining={info.get('remaining')} created_at={info.get('created_at')}")


def main():
    parser = argparse.ArgumentParser(description='本地管理员脚本（仅限在服务器本机运行）')
    sub = parser.add_subparsers(dest='cmd')

    # invites
    invites = sub.add_parser('invites', help='管理邀请码')
    invites_sub = invites.add_subparsers(dest='action')
    a_add = invites_sub.add_parser('add')
    a_add.add_argument('--count', type=int, default=10)
    a_add.add_argument('--uses', type=int, default=1)
    a_add.add_argument('--length', type=int, default=10)
    a_add.set_defaults(func=cmd_invites_add)

    a_del = invites_sub.add_parser('delete')
    a_del.add_argument('codes', nargs='+')
    a_del.set_defaults(func=cmd_invites_delete)

    a_req = invites_sub.add_parser('set-require')
    a_req.add_argument('value', choices=['true', 'false'])
    a_req.set_defaults(func=lambda args: cmd_invites_set_require(type('X',(object,),{'value': args.value=='true'})))

    a_list = invites_sub.add_parser('list')
    a_list.set_defaults(func=cmd_list_invites)

    # bans
    bans = sub.add_parser('ban', help='封禁 IP 或用户')
    bans_sub = bans.add_subparsers(dest='what')
    b_ip = bans_sub.add_parser('ip')
    b_ip.add_argument('target')
    b_ip.add_argument('--duration', type=int, default=0, help='封禁秒数（不填或0表示永久）')
    b_ip.set_defaults(func=cmd_ban_ip)
    b_user = bans_sub.add_parser('user')
    b_user.add_argument('target')
    b_user.set_defaults(func=cmd_ban_user)

    unb = sub.add_parser('unban', help='解封 IP 或用户')
    unb_sub = unb.add_subparsers(dest='what')
    ub_ip = unb_sub.add_parser('ip')
    ub_ip.add_argument('target')
    ub_ip.set_defaults(func=cmd_unban_ip)
    ub_user = unb_sub.add_parser('user')
    ub_user.add_argument('target')
    ub_user.set_defaults(func=cmd_unban_user)

    blist = sub.add_parser('list-bans')
    blist.set_defaults(func=cmd_list_bans)

    args = parser.parse_args()
    if not hasattr(args, 'func'):
        parser.print_help()
        return
    args.func(args)


if __name__ == '__main__':
    main()
