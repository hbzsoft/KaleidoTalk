# Copyright (C) 2026 Bangze Han

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


# server.py
import socket
import threading
import json
import os
import base64
import hashlib
import time
import re
import secrets
import logging
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from network import send_msg, recv_msg
from crypto_utils import (
    IdentityKeyManager,
    ExchangeKeyManager,
    PasswordManager,
    MessageEncryptorV2,
    ServerCrypto,
)

# ----------------------------------------------------------------------
# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('server.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# 线程锁
locks = {
    'clients': threading.Lock(),
    'logged_in': threading.Lock(),
    'pending': threading.Lock(),
    'ip_attempts': threading.Lock(),
    'ip_ban': threading.Lock(),
    'bans_file': threading.Lock(),
    'challenges': threading.Lock(),
    'users_file': threading.Lock(),
    'keys_file': threading.Lock(),
    'invites_file': threading.Lock(),
    'tokens': threading.Lock(),
}

# ----------------------------------------------------------------------
# 全局状态
clients = {}                # socket -> {'username': str, 'token': str}
tokens = {}                 # token -> username
logged_in_users = {}        # username -> socket
pending_messages = {}       # username -> list of dicts (to be sent on login)
ip_attempts = {}            # ip -> {'reg': [timestamps], 'login': [timestamps], 'banned_until': float}
ip_ban_list = {}            # ip -> banned_until
user_ban_list = {}          # username -> True
challenges = {}             # username -> {'challenge': str, 'timestamp': str}

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
# DoS 参数
IP_BAN_DURATION = 3600
REGISTER_LIMIT = 10
LOGIN_LIMIT = 20
TIME_WINDOW = 60
MAX_MSG_SIZE = 10 * 1024 * 1024

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

def verify_and_consume_invite(code_str):
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
    item['remaining'] -= 1
    invites['codes'][code_str] = item
    save_invites(invites)
    return True, 'invite_accepted'

# ----------------------------------------------------------------------
# DoS 防护
def check_dos(ip, attempt_type='reg'):
    now = time.time()
    # 运行时从持久化文件更新封禁（允许 admin.py 修改后生效）
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
            return False, f"IP 被封禁，剩余 {remaining} 秒"
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
            logger.warning(f"IP {ip} 因 {attempt_type} 超限被禁 {IP_BAN_DURATION}s")
            return False, f"IP 被封禁 {IP_BAN_DURATION} 秒"
        record[key].append(now)
    return True, "OK"

# ----------------------------------------------------------------------
# 会话 Token
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
# 离线消息
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
        logger.info(f"已向 {username} 发送 {len(msgs)} 条离线消息")

# ----------------------------------------------------------------------
# 连接与用户管理
def register_socket(sock, username, token):
    with locks['clients']:
        clients[sock] = {'username': username, 'token': token}
    with locks['logged_in']:
        old_sock = logged_in_users.get(username)
        if old_sock and old_sock != sock:
            # 顶替旧连接
            try:
                send_msg(old_sock, {'type': 'force_logout', 'data': '您的账号已在其他设备登录'})
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
    token = info['token']
    with locks['tokens']:
        tokens.pop(token, None)
    with locks['logged_in']:
        if logged_in_users.get(username) == sock:
            logged_in_users.pop(username, None)
    with locks['challenges']:
        challenges.pop(username, None)
    logger.info(f"用户 {username} 断开连接")

# ----------------------------------------------------------------------
# 命令处理
def handle_message(sock, addr, payload):
    cmd = payload.get('cmd')
    data = payload.get('data', {})
    token = payload.get('token', '')

    # 需要登录的命令
    if cmd in ('message', 'list_users', 'logout', 'get_pubkey'):
        username = get_user_by_token(token)
        if not username:
            send_msg(sock, {'status': 'error', 'error': '未登录或会话过期'})
            return
    else:
        username = None

    if cmd == 'get_server_pubkey':
        # 返回服务器 Ed25519 和 X25519 公钥
        send_msg(sock, {
            'status': 'ok',
            'cmd': 'server_pubkey',
            'data': {
                'ed25519': IdentityKeyManager.serialize_public_key(ServerCrypto._ed25519_pub),
                'x25519': ServerCrypto.get_x25519_pub_hex(),
            }
        })

    elif cmd == 'get_reg_policy':
        send_msg(sock, {
            'status': 'ok',
            'cmd': 'reg_policy',
            'data': {'require_invite': require_invite_code()}
        })

    elif cmd == 'reg_user':
        reg_data = data
        username = reg_data['username']
        if not re.match(r'^[A-Za-z0-9]{3,20}$', username):
            send_msg(sock, {'status': 'error', 'error': '用户名格式无效'})
            return
        # DoS 检查
        ok, msg = check_dos(addr[0], 'reg')
        if not ok:
            send_msg(sock, {'status': 'error', 'error': msg})
            return

        # 密码强度检查（仅当存储私钥时需要密码）
        store_private_key = reg_data.get('store_private_key', True)
        if store_private_key:
            password_enc = reg_data['password']
            try:
                password_bytes = ServerCrypto.decrypt_from_client(password_enc)
                password = password_bytes.decode('utf-8')
            except Exception as e:
                send_msg(sock, {'status': 'error', 'error': '密码解密失败'})
                return
            valid, pw_msg = is_password_strong(password)
            if not valid:
                send_msg(sock, {'status': 'error', 'error': pw_msg})
                return
            password_hash = PasswordManager.hash_password(password)
        else:
            password_hash = None
            password = None

        # 邀请码
        invite_code = reg_data.get('invite_code', '')
        inv_ok, inv_msg = verify_and_consume_invite(invite_code)
        if not inv_ok:
            send_msg(sock, {'status': 'error', 'error': inv_msg})
            return

        # 解析密钥
        try:
            ed_priv = IdentityKeyManager.deserialize_private_key(reg_data['ed25519_priv_pem'])
            ed_pub = ed_priv.public_key()
            x_priv = ExchangeKeyManager.deserialize_private_key(reg_data['x25519_priv_hex'])
            x_pub = x_priv.public_key()
        except Exception as e:
            send_msg(sock, {'status': 'error', 'error': f'密钥格式错误: {e}'})
            return

        # 保存到文件
        users = load_users()
        user_keys = load_user_keys()
        if username in user_keys:
            send_msg(sock, {'status': 'error', 'error': '用户名已存在'})
            return

        if store_private_key:
            # 加密私钥
            enc_priv = reg_data['encrypted_private']
            users[username] = password_hash
            save_users(users)

        key_data = {
            'ed25519_pub': IdentityKeyManager.serialize_public_key(ed_pub),
            'x25519_pub': ExchangeKeyManager.serialize_public_key(x_pub),
            'store_private_key': store_private_key,
            'reg_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
        if store_private_key:
            key_data['encrypted_private'] = enc_priv
        user_keys[username] = key_data
        save_user_keys(user_keys)

        send_msg(sock, {'status': 'ok', 'cmd': 'reg_user', 'data': {'message': '注册成功'}})
        logger.info(f"注册成功: {username} (store_key={store_private_key})")

    elif cmd == 'login':
        # 已有 token 则先注销
        if token and username:
            unregister_socket(sock)
        username = data['username']
        if not re.match(r'^[A-Za-z0-9]{3,20}$', username):
            send_msg(sock, {'status': 'error', 'error': '用户名格式无效'})
            return
        ok, msg = check_dos(addr[0], 'login')
        if not ok:
            send_msg(sock, {'status': 'error', 'error': msg})
            return

        user_keys = load_user_keys()
        if username not in user_keys:
            send_msg(sock, {'status': 'error', 'error': '用户不存在'})
            return

        # 检查用户封禁（从持久化文件重新加载以保证 admin.py 的更改即时生效）
        try:
            bans_now = load_bans_file()
            with locks['bans_file']:
                user_ban_list.clear()
                for u in bans_now.get('user_bans', {}):
                    user_ban_list[u] = True
                if user_ban_list.get(username):
                    send_msg(sock, {'status': 'error', 'error': '用户被封禁'})
                    return
        except Exception:
            # 若加载失败则按原有内存状态判断
            with locks['bans_file']:
                if user_ban_list.get(username):
                    send_msg(sock, {'status': 'error', 'error': '用户被封禁'})
                    return

        key_data = user_keys[username]
        store_private_key = key_data.get('store_private_key', True)

        if store_private_key:
            # 密码验证
            enc_password = data.get('password')
            if not enc_password:
                send_msg(sock, {'status': 'error', 'error': '缺少加密密码'})
                return
            try:
                password_bytes = ServerCrypto.decrypt_from_client(enc_password)
                password = password_bytes.decode('utf-8')
            except Exception:
                send_msg(sock, {'status': 'error', 'error': '密码解密失败'})
                return
            users = load_users()
            stored_hash = users.get(username)
            if not stored_hash or not PasswordManager.verify_password(stored_hash, password):
                send_msg(sock, {'status': 'error', 'error': '密码错误'})
                return
            # 登录成功
            token = bind_token(username)
            register_socket(sock, username, token)
            send_msg(sock, {
                'status': 'ok',
                'cmd': 'login',
                'data': {
                    'token': token,
                    'encrypted_private': key_data.get('encrypted_private', ''),
                    'ed25519_pub': key_data['ed25519_pub'],
                    'x25519_pub': key_data['x25519_pub'],
                }
            })
            logger.info(f"登录成功: {username}")
            send_pending_messages(sock, username)
        else:
            # 本地私钥模式：挑战-应答
            challenge = secrets.token_hex(32)
            timestamp = str(int(time.time()))
            with locks['challenges']:
                challenges[username] = {'challenge': challenge, 'timestamp': timestamp}
            send_msg(sock, {
                'status': 'challenge',
                'cmd': 'login',
                'data': {'challenge': challenge, 'timestamp': timestamp}
            })

    elif cmd == 'challenge_response':
        username = data.get('username')
        signature_hex = data.get('signature')
        challenge = data.get('challenge')
        timestamp = data.get('timestamp')
        with locks['challenges']:
            stored = challenges.pop(username, None)
        if not stored or stored['challenge'] != challenge or stored['timestamp'] != timestamp:
            send_msg(sock, {'status': 'error', 'error': '挑战无效或已过期'})
            return
        if abs(int(time.time()) - int(timestamp)) > 300:
            send_msg(sock, {'status': 'error', 'error': '挑战已过期'})
            return
        user_keys = load_user_keys()
        if username not in user_keys:
            send_msg(sock, {'status': 'error', 'error': '用户不存在'})
            return
        pub_pem = user_keys[username]['ed25519_pub']
        try:
            ed_pub = IdentityKeyManager.deserialize_public_key(pub_pem)
            sig_bytes = bytes.fromhex(signature_hex)
            data_to_sign = f"{challenge}:{timestamp}".encode('utf-8')
            if not IdentityKeyManager.verify(ed_pub, sig_bytes, data_to_sign):
                raise Exception("签名无效")
        except Exception:
            send_msg(sock, {'status': 'error', 'error': '签名验证失败'})
            return
        token = bind_token(username)
        register_socket(sock, username, token)
        send_msg(sock, {
            'status': 'ok',
            'cmd': 'login',
            'data': {
                'token': token,
                'ed25519_pub': pub_pem,
                'x25519_pub': user_keys[username]['x25519_pub'],
            }
        })
        logger.info(f"登录成功 (签名验证): {username}")
        send_pending_messages(sock, username)

    elif cmd == 'get_pubkey':
        target = data.get('username')
        if not re.match(r'^[A-Za-z0-9]{3,20}$', target):
            send_msg(sock, {'status': 'error', 'error': '用户名格式无效'})
            return
        user_keys = load_user_keys()
        if target in user_keys:
            k = user_keys[target]
            send_msg(sock, {
                'status': 'ok',
                'cmd': 'pubkey',
                'data': {
                    'username': target,
                    'ed25519_pub': k['ed25519_pub'],
                    'x25519_pub': k['x25519_pub'],
                }
            })
        else:
            send_msg(sock, {
                'status': 'error',
                'cmd': 'pubkey',
                'data': {'username': target},
                'error': '用户不存在'
            })

    elif cmd == 'message':
        receiver = data['receiver']
        encrypted_payload = data['payload']  # 已经是 base64 字符串
        if not re.match(r'^[A-Za-z0-9]{3,20}$', receiver):
            send_msg(sock, {'status': 'error', 'error': '无效的接收者'})
            return
        sender_username = username
        msg_obj = {
            'type': 'msg',
            'sender': sender_username,
            'payload': encrypted_payload,
            'timestamp': int(time.time())
        }
        with locks['logged_in']:
            receiver_sock = logged_in_users.get(receiver)
        if receiver_sock:
            try:
                send_msg(receiver_sock, msg_obj)
                send_msg(sock, {'status': 'ok', 'cmd': 'message', 'data': {'status': 'delivered'}})
            except Exception:
                store_offline_message(receiver, msg_obj)
                send_msg(sock, {'status': 'ok', 'cmd': 'message', 'data': {'status': 'offline_saved'}})
        else:
            store_offline_message(receiver, msg_obj)
            send_msg(sock, {'status': 'ok', 'cmd': 'message', 'data': {'status': 'offline_saved'}})

    elif cmd == 'list_users':
        with locks['logged_in']:
            online = list(logged_in_users.keys())
        send_msg(sock, {'status': 'ok', 'cmd': 'users', 'data': {'users': online}})

    elif cmd == 'logout':
        unregister_socket(sock)
        send_msg(sock, {'status': 'ok', 'cmd': 'logout'})

    elif cmd == 'admin_ip':
        if addr[0] not in ['127.0.0.1', '::1']:
            send_msg(sock, {'status': 'error', 'error': '仅限本地管理'})
            return
        action = data.get('action')
        target_ip = data.get('ip')
        if action == 'ban':
            duration = data.get('duration', IP_BAN_DURATION)
            with locks['ip_ban']:
                ip_ban_list[target_ip] = time.time() + duration
            # 持久化到 bans.json
            try:
                bans = load_bans_file()
                bans.setdefault('ip_bans', {})[target_ip] = ip_ban_list[target_ip]
                save_bans_file(bans)
            except Exception:
                logger.exception('持久化封禁失败')
            send_msg(sock, {'status': 'ok', 'cmd': 'admin_ip', 'data': f'已封禁 {target_ip}'})
        elif action == 'unban':
            with locks['ip_ban']:
                ip_ban_list.pop(target_ip, None)
            with locks['ip_attempts']:
                ip_attempts.pop(target_ip, None)
            try:
                bans = load_bans_file()
                if 'ip_bans' in bans and target_ip in bans['ip_bans']:
                    bans['ip_bans'].pop(target_ip, None)
                    save_bans_file(bans)
            except Exception:
                logger.exception('更新持久化封禁失败')
            send_msg(sock, {'status': 'ok', 'cmd': 'admin_ip', 'data': f'已解封 {target_ip}'})
        elif action == 'list':
            now = time.time()
            banned = []
            with locks['ip_ban']:
                for ip, until in ip_ban_list.items():
                    if now < until:
                        banned.append(f"{ip}(剩余{int(until-now)}s)")
            send_msg(sock, {'status': 'ok', 'cmd': 'admin_ip', 'data': banned})
        else:
            send_msg(sock, {'status': 'error', 'error': '未知操作'})

    else:
        send_msg(sock, {'status': 'error', 'error': '未知命令'})

# ----------------------------------------------------------------------
# 客户端处理线程
def handle_client(sock, addr):
    logger.info(f"新连接: {addr}")
    sock.settimeout(30.0)
    try:
        # 发送欢迎信息
        send_msg(sock, {
            'type': 'welcome',
            'data': {
                'message': '欢迎使用万花筒聊天软件 V2.2',
                'server_time': datetime.now().isoformat()
            }
        })
    except Exception:
        sock.close()
        return

    while True:
        try:
            msg = recv_msg(sock)
            if msg is None:
                break
            handle_message(sock, addr, msg)
        except socket.timeout:
            # 发送心跳
            try:
                send_msg(sock, {'type': 'ping'})
            except Exception:
                break
        except Exception as e:
            logger.error(f"处理消息异常 ({addr}): {e}")
            break

    unregister_socket(sock)
    try:
        sock.close()
    except Exception:
        pass
    logger.info(f"连接关闭: {addr}")

# ----------------------------------------------------------------------
# 主函数
def start_server(host='0.0.0.0', port=5555):
    # 初始化服务器密钥（需要管理员密码）
    try:
        admin_pw = input("请输入服务器管理密码: ")
    except (EOFError, KeyboardInterrupt):
        print("\n启动取消")
        return
    try:
        ServerCrypto.initialize(admin_pw)
    except ValueError as e:
        print(f"初始化失败: {e}")
        return

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)

    logger.info(f"服务器已启动 {host}:{port}")
    logger.info(f"服务器 ed25519 指纹: {hashlib.sha256(ServerCrypto.get_ed25519_pub_pem().encode()).hexdigest()}")
    logger.info(f"邀请码注册状态: {require_invite_code()}")

    if not os.path.exists(USERS_FILE):
        save_users({})
    if not os.path.exists(KEYS_FILE):
        save_user_keys({})
    if not os.path.exists(INVITES_FILE):
        save_invites({'require_invite': False, 'codes': {}})

    # 加载持久化封禁信息
    try:
        bans = load_bans_file()
        with locks['ip_ban']:
            # 仅加载未过期或永久封禁项（0 表示永久）
            now_t = time.time()
            for ip, until in bans.get('ip_bans', {}).items():
                try:
                    if not until or float(until) > now_t:
                        ip_ban_list[ip] = float(until)
                except Exception:
                    continue
        with locks['bans_file']:
            user_ban_list.clear()
            for u in bans.get('user_bans', {}):
                user_ban_list[u] = True
        logger.info('已加载封禁列表')
    except Exception:
        logger.warning('加载封禁列表失败或文件不存在')

    try:
        while True:
            sock, addr = server.accept()
            threading.Thread(target=handle_client, args=(sock, addr), daemon=True).start()
    except KeyboardInterrupt:
        logger.info("服务器关闭中...")
    finally:
        server.close()

if __name__ == '__main__':
    print("KaleidoTalk Copyright (C) 2026 Bangze Han")
    print("This program comes with ABSOLUTELY NO WARRANTY.")
    print("This is free software, and you are welcome to redistribute it")
    print("under the terms of the GNU General Public License version 3 or later.")
    start_server('0.0.0.0', 5555)