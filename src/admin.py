# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


"""本地管理员脚本（直接编辑本地配置文件，无需网络连接）

用法示例:
  python admin.py invites add --count 5 --uses 1 --length 8
  python admin.py invites delete CODE123
  python admin.py invites set-require true
  python admin.py invites list
  
  python admin.py ban ip 1.2.3.4 --duration 3600
  python admin.py ban user alice
  python admin.py unban ip 1.2.3.4
  python admin.py unban user alice
  python admin.py list-bans
  
  python admin.py users list          # 列出所有注册用户
  python admin.py users delete alice  # 删除用户

说明:
  - 本脚本直接读写服务器本地配置文件（invite_codes.json, bans.json, users.json, user_keys.json）
  - 无需启动服务器，无需网络连接
  - 需要具有文件系统权限访问上述配置文件
"""
import argparse
import json
import os
import secrets
import string
import time
import sys
from datetime import datetime

# 配置文件路径（相对于脚本运行目录）
INVITE_FILE = 'invite_codes.json'
BANS_FILE = 'bans.json'
USERS_FILE = 'users.json'
KEYS_FILE = 'user_keys.json'

ALPHABET = string.ascii_uppercase + string.digits


def load_json(path, default=None):
    """安全加载 JSON 文件"""
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
    """安全保存 JSON 文件（先写临时文件再重命名）"""
    temp = path + '.tmp'
    with open(temp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(temp, path)


def load_invites():
    """加载邀请码配置"""
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
    """保存邀请码配置"""
    save_json(INVITE_FILE, data)


def load_bans():
    """加载封禁列表"""
    return load_json(BANS_FILE, {'ip_bans': {}, 'user_bans': {}})


def save_bans(data):
    """保存封禁列表"""
    save_json(BANS_FILE, data)


def load_users():
    """加载用户密码表"""
    return load_json(USERS_FILE, {})


def save_users(data):
    """保存用户密码表"""
    save_json(USERS_FILE, data)


def load_user_keys():
    """加载用户密钥表"""
    return load_json(KEYS_FILE, {})


def save_user_keys(data):
    """保存用户密钥表"""
    save_json(KEYS_FILE, data)


def generate_unique_code(existing, length):
    """生成唯一邀请码"""
    while True:
        code = ''.join(secrets.choice(ALPHABET) for _ in range(length))
        if code not in existing:
            return code


# =============================================================================
# 邀请码管理命令
# =============================================================================

def cmd_invites_add(args):
    """添加邀请码"""
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
    print(f'新增邀请码数量: {len(new_codes)}')
    for c in new_codes:
        print(c)


def cmd_invites_delete(args):
    """删除邀请码"""
    data = load_invites()
    removed = []
    for code in args.codes:
        if code in data['codes']:
            data['codes'].pop(code, None)
            removed.append(code)
    save_invites(data)
    print('已删除:', removed)


def cmd_invites_set_require(args):
    """设置是否需要邀请码注册"""
    data = load_invites()
    data['require_invite'] = args.value
    save_invites(data)
    print('require_invite 已设置为', args.value)


def cmd_invites_list(args):
    """列出所有邀请码"""
    data = load_invites()
    print(f'require_invite = {data.get("require_invite", False)}')
    print('邀请码列表:')
    codes = data.get('codes', {})
    if not codes:
        print('  (无)')
    for code, info in codes.items():
        remaining = info.get('remaining', 0) if isinstance(info, dict) else info
        created = info.get('created_at', '') if isinstance(info, dict) else ''
        print(f"  {code}: 剩余次数={remaining}, 创建时间={created}")


# =============================================================================
# 封禁管理命令
# =============================================================================

def cmd_ban_ip(args):
    """封禁 IP"""
    bans = load_bans()
    until = 0
    if args.duration:
        until = int(time.time()) + int(args.duration)
    bans.setdefault('ip_bans', {})[args.target] = until
    save_bans(bans)
    if until:
        print(f'已封禁 IP {args.target} 到 {datetime.fromtimestamp(until)}')
    else:
        print(f'已永久封禁 IP {args.target}')


def cmd_unban_ip(args):
    """解封 IP"""
    bans = load_bans()
    if args.target in bans.get('ip_bans', {}):
        bans['ip_bans'].pop(args.target, None)
        save_bans(bans)
        print('已解封 IP', args.target)
    else:
        print('未找到封禁记录:', args.target)


def cmd_ban_user(args):
    """封禁用户"""
    bans = load_bans()
    bans.setdefault('user_bans', {})[args.target] = True
    save_bans(bans)
    print('已封禁用户', args.target)


def cmd_unban_user(args):
    """解封用户"""
    bans = load_bans()
    if args.target in bans.get('user_bans', {}):
        bans['user_bans'].pop(args.target, None)
        save_bans(bans)
        print('已解封用户', args.target)
    else:
        print('未找到封禁记录:', args.target)


def cmd_list_bans(args):
    """列出所有封禁"""
    bans = load_bans()
    print('IP 封禁:')
    ip_bans = bans.get('ip_bans', {})
    if not ip_bans:
        print('  (无)')
    for ip, until in ip_bans.items():
        if until and until > 0:
            print(f'  {ip} -> 到期时间: {datetime.fromtimestamp(until)}')
        else:
            print(f'  {ip} -> 永久封禁')
    print('\n用户封禁:')
    user_bans = bans.get('user_bans', {})
    if not user_bans:
        print('  (无)')
    for u in user_bans.keys():
        print(f'  {u}')


# =============================================================================
# 用户管理命令
# =============================================================================

def cmd_users_list(args):
    """列出所有注册用户"""
    users = load_users()
    user_keys = load_user_keys()
    
    print('注册用户列表:')
    if not users and not user_keys:
        print('  (无)')
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
            status.append('有密码')
        if has_keys:
            status.append('有密钥')
        if store_private:
            status.append('私钥存服务器')
        
        print(f'  {username}: {", ".join(status) if status else "(数据不完整)"}')


def cmd_users_delete(args):
    """删除用户（同时删除密码和密钥）"""
    username = args.target
    
    users = load_users()
    user_keys = load_user_keys()
    
    deleted = False
    
    if username in users:
        del users[username]
        save_users(users)
        deleted = True
        print(f'已删除用户 {username} 的密码记录')
    
    if username in user_keys:
        del user_keys[username]
        save_user_keys(user_keys)
        deleted = True
        print(f'已删除用户 {username} 的密钥记录')
    
    if not deleted:
        print(f'用户 {username} 不存在')
        sys.exit(1)
    else:
        print(f'用户 {username} 已完全删除')


# =============================================================================
# 主函数
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='本地管理员脚本（直接编辑配置文件，无需网络）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  # 邀请码管理
  python admin.py invites add --count 5 --uses 1 --length 8
  python admin.py invites delete CODE123
  python admin.py invites set-require true
  python admin.py invites list

  # 封禁管理
  python admin.py ban ip 1.2.3.4 --duration 3600
  python admin.py ban user alice
  python admin.py unban ip 1.2.3.4
  python admin.py unban user alice
  python admin.py list-bans

  # 用户管理
  python admin.py users list
  python admin.py users delete alice
        '''
    )
    sub = parser.add_subparsers(dest='cmd', help='可用命令')

    # -------------------------------------------------------------------------
    # invites 子命令
    # -------------------------------------------------------------------------
    invites = sub.add_parser('invites', help='管理邀请码')
    invites_sub = invites.add_subparsers(dest='action', help='邀请码操作')
    
    a_add = invites_sub.add_parser('add', help='添加邀请码')
    a_add.add_argument('--count', type=int, default=10, help='生成数量')
    a_add.add_argument('--uses', type=int, default=1, help='每个邀请码可使用次数')
    a_add.add_argument('--length', type=int, default=10, help='邀请码长度')
    a_add.set_defaults(func=cmd_invites_add)

    a_del = invites_sub.add_parser('delete', help='删除邀请码')
    a_del.add_argument('codes', nargs='+', help='要删除的邀请码')
    a_del.set_defaults(func=cmd_invites_delete)

    a_req = invites_sub.add_parser('set-require', help='设置是否需要邀请码才能注册')
    a_req.add_argument('value', choices=['true', 'false'], help='true=需要, false=不需要')
    a_req.set_defaults(func=lambda args: cmd_invites_set_require(type('X', (object,), {'value': args.value == 'true'})))

    a_list = invites_sub.add_parser('list', help='列出所有邀请码')
    a_list.set_defaults(func=cmd_invites_list)

    # -------------------------------------------------------------------------
    # ban 子命令
    # -------------------------------------------------------------------------
    bans = sub.add_parser('ban', help='封禁 IP 或用户')
    bans_sub = bans.add_subparsers(dest='what', help='封禁对象类型')
    
    b_ip = bans_sub.add_parser('ip', help='封禁 IP 地址')
    b_ip.add_argument('target', help='IP 地址')
    b_ip.add_argument('--duration', type=int, default=0, help='封禁秒数（不填或0表示永久）')
    b_ip.set_defaults(func=cmd_ban_ip)
    
    b_user = bans_sub.add_parser('user', help='封禁用户')
    b_user.add_argument('target', help='用户名')
    b_user.set_defaults(func=cmd_ban_user)

    # -------------------------------------------------------------------------
    # unban 子命令
    # -------------------------------------------------------------------------
    unb = sub.add_parser('unban', help='解封 IP 或用户')
    unb_sub = unb.add_subparsers(dest='what', help='解封对象类型')
    
    ub_ip = unb_sub.add_parser('ip', help='解封 IP 地址')
    ub_ip.add_argument('target', help='IP 地址')
    ub_ip.set_defaults(func=cmd_unban_ip)
    
    ub_user = unb_sub.add_parser('user', help='解封用户')
    ub_user.add_argument('target', help='用户名')
    ub_user.set_defaults(func=cmd_unban_user)

    # -------------------------------------------------------------------------
    # list-bans 命令
    # -------------------------------------------------------------------------
    blist = sub.add_parser('list-bans', help='列出所有封禁')
    blist.set_defaults(func=cmd_list_bans)

    # -------------------------------------------------------------------------
    # users 子命令
    # -------------------------------------------------------------------------
    users = sub.add_parser('users', help='管理用户')
    users_sub = users.add_subparsers(dest='action', help='用户操作')
    
    u_list = users_sub.add_parser('list', help='列出所有用户')
    u_list.set_defaults(func=cmd_users_list)
    
    u_del = users_sub.add_parser('delete', help='删除用户')
    u_del.add_argument('target', help='要删除的用户名')
    u_del.set_defaults(func=cmd_users_delete)

    # -------------------------------------------------------------------------
    # 解析并执行
    # -------------------------------------------------------------------------
    args = parser.parse_args()
    if not hasattr(args, 'func'):
        parser.print_help()
        return
    args.func(args)


if __name__ == '__main__':
    main()
