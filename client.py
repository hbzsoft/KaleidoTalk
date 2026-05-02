# Copyright (C) 2026 Bangze Han


# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


# client.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import queue
import socket
import threading
import json
import os
import time
import re
import base64
import hashlib
import hmac
import secrets
import ctypes
from datetime import datetime
from network import send_msg, recv_msg
from crypto_utils import (
    IdentityKeyManager,
    ExchangeKeyManager,
    PasswordManager,
    MessageEncryptorV2,
    ServerCrypto,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:
    pystray = None
    Image = None
    ImageDraw = None

# ----------------------------------------------------------------------
# 窗口闪烁（Windows）
FLASHW_STOP = 0
FLASHW_CAPTION = 0x00000001
FLASHW_TRAY = 0x00000002
FLASHW_ALL = FLASHW_CAPTION | FLASHW_TRAY
FLASHW_TIMER = 0x00000004
FLASHW_TIMERNOFG = 0x0000000C

class FLASHWINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint),
        ("hwnd", ctypes.c_void_p),
        ("dwFlags", ctypes.c_uint),
        ("uCount", ctypes.c_uint),
        ("dwTimeout", ctypes.c_uint),
    ]
# ----------------------------------------------------------------------

class ChatClient:
    """
    客户端核心逻辑：连接、登录、注册、发送消息、密钥管理、信任库
    """
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.sock = None
        self.running = False
        self.username = None
        self.callback = None
        self.token = None

        # 身份密钥 (Ed25519)
        self.id_priv = None
        self.id_pub = None
        # 密钥交换密钥 (X25519)
        self.x_priv = None
        self.x_pub = None

        # 服务器公钥
        self.server_ed25519_pub = None
        self.server_x25519_pub = None
        self.require_invite_for_register = None

        # 用户公钥缓存
        self.user_pubkeys = {}  # username -> {'ed25519': ..., 'x25519': ...}

        # 信任库
        self._trust_lock = threading.Lock()
        self._hmac_key = self._load_or_create_hmac_key()
        self.trust_db = self._load_trust_db()

        # 待处理消息缓存
        self.pending_messages = {}  # username -> list of encrypted payloads
        self.pending_msg_lock = threading.Lock()
        self.pending_outgoing_messages = {}  # username -> list of plaintext messages waiting for pubkey
        self.pending_outgoing_lock = threading.Lock()
        self.pending_verifications = set()
        self.pending_verifications_lock = threading.Lock()

        # 注册/登录临时状态
        self.last_password = None
        self.pending_login_user = None
        self.local_key_loaded = False
        self._color_palette = [
            '#1f77b4',
            '#2ca02c',
            '#d62728',
            '#9467bd',
            '#ff7f0e',
            '#17becf',
            '#8c564b',
            '#e377c2',
            '#7f7f7f',
            '#bcbd22',
            '#17a2b8',
            '#5f27cd',
        ]
        self._name_colors = {}

    # ------------------------------------------------------------------
    # 本地信任库
    def _get_trust_db_path(self):
        if not os.path.exists('local_keys'):
            os.makedirs('local_keys')
        return 'local_keys/trusted_fingerprints.json'

    def _get_hmac_key_path(self):
        return 'local_keys/.hmac_key'

    def _load_or_create_hmac_key(self):
        if not os.path.exists('local_keys'):
            os.makedirs('local_keys')
        path = self._get_hmac_key_path()
        if os.path.exists(path):
            with open(path, 'rb') as f:
                return f.read()
        key = os.urandom(32)
        with open(path, 'wb') as f:
            f.write(key)
        return key

    def _load_trust_db(self):
        path = self._get_trust_db_path()
        if not os.path.exists(path):
            return {'servers': {}, 'users': {}}
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = f.read()
            # 验证 HMAC
            hmac_path = path + '.hmac'
            if not os.path.exists(hmac_path):
                raise ValueError("缺少HMAC签名文件")
            with open(hmac_path, 'rb') as f:
                stored_hmac = f.read()
            calc = hmac.new(self._hmac_key, data.encode('utf-8'), 'sha256').digest()
            if not hmac.compare_digest(calc, stored_hmac):
                raise ValueError("信任库完整性校验失败，可能被篡改")
            return json.loads(data)
        except Exception as e:
            # 校验失败：提示用户并重置
            if self.callback:
                self.callback('WARNING', f"信任库加载失败: {e}，已重置所有信任关系")
            return {'servers': {}, 'users': {}}

    def _save_trust_db(self):
        path = self._get_trust_db_path()
        with self._trust_lock:
            data = json.dumps(self.trust_db, indent=2, ensure_ascii=False)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(data)
            hmac_val = hmac.new(self._hmac_key, data.encode('utf-8'), 'sha256').digest()
            with open(path + '.hmac', 'wb') as f:
                f.write(hmac_val)

    def _key_fingerprint(self, pub_key_pem):
        """Ed25519 公钥指纹 (SHA256 of raw bytes)"""
        pub = IdentityKeyManager.deserialize_public_key(pub_key_pem)
        raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )  # wait, Ed25519 public key raw bytes are 32 bytes. Use cryptography's public_bytes(Encoding.Raw, PublicFormat.Raw)
        return hashlib.sha256(raw).hexdigest()
    # Note: cryptography's Ed25519PublicKey has method public_bytes (since some version). To avoid version issues, we will use PEM SHA256.

    def _fingerprint_from_bytes(self, pem_str):
        return hashlib.sha256(pem_str.encode('utf-8')).hexdigest()

    # ------------------------------------------------------------------
    # 连接与协议通信
    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.connect((self.host, self.port))
            self.sock.settimeout(30.0)
            self.running = True

            # 接收欢迎信息
            msg = recv_msg(self.sock)
            if msg and msg.get('type') == 'welcome':
                if self.callback:
                    self.callback('SYS', msg['data']['message'])

            # 启动接收线程
            threading.Thread(target=self._recv_loop, daemon=True).start()

            # 请求服务器公钥
            self._send({'cmd': 'get_server_pubkey'})
            # 查询注册策略（是否需要邀请码）
            self._send({'cmd': 'get_reg_policy'})
            return True
        except socket.timeout:
            if self.callback:
                self.callback('ERROR', '连接超时')
            return False
        except ConnectionRefusedError:
            if self.callback:
                self.callback('ERROR', '连接被拒绝，服务器可能未启动')
            return False
        except Exception as e:
            if self.callback:
                self.callback('ERROR', f'连接失败: {e}')
            return False

    def _send(self, obj):
        if not self.sock:
            return False
        try:
            send_msg(self.sock, obj)
            return True
        except Exception as e:
            if self.callback:
                self.callback('ERROR', f'发送失败: {e}')
            return False

    def _recv_loop(self):
        while self.running and self.sock:
            try:
                msg = recv_msg(self.sock)
                if msg is None:
                    break
                # 心跳忽略
                if msg.get('type') == 'ping':
                    continue
                self._handle_msg(msg)
            except socket.timeout:
                continue
            except OSError as e:
                if not self.running or not self.sock:
                    break
                if getattr(e, 'winerror', None) == 10038:
                    break
                if self.callback:
                    self.callback('ERROR', f'接收错误: {e}')
                break
            except Exception as e:
                if self.callback:
                    self.callback('ERROR', f'接收错误: {e}')
                break
        self._disconnect_cleanup()

    def _handle_msg(self, msg):
        """服务端推送或响应分发"""
        if 'type' in msg:
            if msg['type'] == 'msg':
                # 新消息到达
                sender = msg['sender']
                payload = msg['payload']
                self._process_incoming_message(sender, payload)
            elif msg['type'] == 'force_logout':
                self._disconnect_cleanup()
                if self.callback:
                    self.callback('SYS', '您的账号在其他设备登录，被迫下线')
            return

        # 响应处理
        status = msg.get('status')
        cmd = msg.get('cmd')
        data = msg.get('data', {})

        if status == 'error':
            if cmd == 'pubkey':
                target = data.get('username')
                if target:
                    self._clear_pending_outgoing_messages(target)
            if self.callback:
                self.callback('ERROR', msg.get('error') or data.get('error', '未知错误'))
            return

        if cmd == 'server_pubkey':
            self.server_ed25519_pub = IdentityKeyManager.deserialize_public_key(data['ed25519'])
            self.server_x25519_pub = ExchangeKeyManager.deserialize_public_key(data['x25519'])
            ServerCrypto._ed25519_pub = self.server_ed25519_pub
            ServerCrypto._x25519_pub = self.server_x25519_pub
            endpoint = f"{self.host}:{self.port}"
            fingerprint = self._fingerprint_from_bytes(data['ed25519'])

            trusted = self.trust_db['servers'].get(endpoint)
            if trusted is None:
                # 首次连接，要求用户确认
                if self.callback:
                    self.callback('SERVER_VERIFY', {'endpoint': endpoint, 'fingerprint': fingerprint})
            elif trusted != fingerprint:
                if self.callback:
                    self.callback('ERROR', f"服务器公钥指纹不匹配！可能遭受中间人攻击。\n已记录: {trusted}\n当前: {fingerprint}")
            else:
                if self.callback:
                    self.callback('SYS', "服务器公钥已通过信任验证")
            if self.callback:
                self.callback('UPDATE_BUTTONS',None)

        elif cmd == 'reg_user':
            if self.callback:
                self.callback('SUCCESS', '注册成功，请登录')

        elif cmd == 'reg_policy':
            self.require_invite_for_register = bool(data.get('require_invite', False))

        elif cmd == 'login':
            if status == 'challenge':
                challenge = data['challenge']
                timestamp = data['timestamp']
                self._respond_challenge(challenge, timestamp)
                return

            if status != 'ok':
                if self.callback:
                    self.callback('ERROR', f'未知登录响应状态: {status}')
                return

            self.token = data['token']
            self.username = self.pending_login_user
            self.pending_login_user = None

            # 加载服务器返回的密钥（如果存在）
            if 'encrypted_private' in data and data['encrypted_private']:
                # 解密私钥
                try:
                    enc = data['encrypted_private']
                    salt = bytes.fromhex(enc['salt'])
                    nonce = bytes.fromhex(enc['nonce'])
                    ct = bytes.fromhex(enc['ct'])
                    tag = bytes.fromhex(enc['tag'])
                    key = PasswordManager.derive_key(self.last_password, salt)
                    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
                    decryptor = cipher.decryptor()
                    plain = decryptor.update(ct) + decryptor.finalize()
                    keys = json.loads(plain.decode('utf-8'))
                    self.id_priv = IdentityKeyManager.deserialize_private_key(keys['ed25519_priv'])
                    self.x_priv = ExchangeKeyManager.deserialize_private_key(keys['x25519_priv'])
                    self.id_pub = self.id_priv.public_key()
                    self.x_pub = self.x_priv.public_key()
                except Exception as e:
                    if self.callback:
                        self.callback('ERROR', f"解密服务器私钥失败: {e}")
                    self._disconnect_cleanup()
                    return
            else:
                # 本地私钥已经加载，此处加载公钥
                try:
                    self.id_pub = IdentityKeyManager.deserialize_public_key(data['ed25519_pub'])
                    self.x_pub = ExchangeKeyManager.deserialize_public_key(data['x25519_pub'])
                except Exception as e:
                    if self.callback:
                        self.callback('ERROR', f"加载公钥失败: {e}")
                    self._disconnect_cleanup()
                    return

            # 缓存自己的公钥
            self.user_pubkeys[self.username] = {
                'ed25519': self.id_pub,
                'x25519': self.x_pub,
            }

            self.clear_password()
            if self.callback:
                self.callback('SUCCESS', f"登录成功 ({self.username})")
            self._request_online_users()
            self.callback('UPDATE_BUTTONS',None)

        elif cmd == 'challenge_response' or status == 'challenge':
            # 处理挑战
            challenge = data['challenge']
            timestamp = data['timestamp']
            self._respond_challenge(challenge, timestamp)

        elif cmd == 'pubkey':
            username = data['username']
            ed_pub = IdentityKeyManager.deserialize_public_key(data['ed25519_pub'])
            x_pub = ExchangeKeyManager.deserialize_public_key(data['x25519_pub'])
            self.user_pubkeys[username] = {'ed25519': ed_pub, 'x25519': x_pub}
            self._flush_pending_outgoing_messages(username)
            # 检查是否有待验证消息
            self._check_pending_verification(username)

        elif cmd == 'users':
            users = data.get('users', [])
            if self.callback:
                self.callback('USERS', users)

        elif cmd == 'logout':
            self._disconnect_cleanup()

    # ------------------------------------------------------------------
    # 消息加解密与缓存
    def _process_incoming_message(self, sender, encrypted_payload):
        # 检查是否有发送者公钥
        if sender not in self.user_pubkeys:
            # 请求公钥并缓存消息
            with self.pending_msg_lock:
                self.pending_messages.setdefault(sender, []).append(encrypted_payload)
            self._request_public_key(sender)
            return

        # 检查信任
        if not self._is_user_trusted(sender):
            with self.pending_msg_lock:
                self.pending_messages.setdefault(sender, []).append(encrypted_payload)
            if self._begin_verification(sender):
                finger = self._fingerprint_from_bytes(
                    IdentityKeyManager.serialize_public_key(self.user_pubkeys[sender]['ed25519'])
                )
                self.callback('USER_VERIFY', {'username': sender, 'fingerprint': finger})
            return

        # 立即解密
        self._decrypt_and_display(sender, encrypted_payload)

    def _decrypt_and_display(self, sender, encrypted_payload):
        try:
            plain, err = MessageEncryptorV2.decrypt(
                encrypted_payload,
                self.x_priv,
                self.user_pubkeys[sender]['ed25519']
            )
            if plain:
                self.callback('MESSAGE', {'sender': sender, 'message': plain})
            else:
                self.callback('ERROR', f"解密来自 {sender} 的消息失败: {err}")
        except Exception as e:
            self.callback('ERROR', f"解密异常: {e}")

    def _queue_pending_outgoing_message(self, receiver, plaintext):
        with self.pending_outgoing_lock:
            self.pending_outgoing_messages.setdefault(receiver, []).append(plaintext)

    def _pop_pending_outgoing_messages(self, receiver):
        with self.pending_outgoing_lock:
            return self.pending_outgoing_messages.pop(receiver, [])

    def _clear_pending_outgoing_messages(self, receiver):
        with self.pending_outgoing_lock:
            self.pending_outgoing_messages.pop(receiver, None)

    def _flush_pending_outgoing_messages(self, receiver):
        msgs = self._pop_pending_outgoing_messages(receiver)
        for plaintext in msgs:
            self._send_encrypted_message(receiver, plaintext)

    def _send_encrypted_message(self, receiver, plaintext):
        enc = MessageEncryptorV2.encrypt(
            plaintext,
            self.user_pubkeys[receiver]['x25519'],
            self.id_priv
        )
        return self._send({'cmd': 'message', 'token': self.token, 'data': {
            'receiver': receiver,
            'payload': enc
        }})

    def _check_pending_verification(self, username):
        with self.pending_msg_lock:
            has_pending = username in self.pending_messages and bool(self.pending_messages[username])

        if not has_pending:
            return

        if self._is_user_trusted(username):
            with self.pending_msg_lock:
                msgs = self.pending_messages.pop(username, [])
            for payload in msgs:
                self._decrypt_and_display(username, payload)
            return

        if self._begin_verification(username):
            finger = self._fingerprint_from_bytes(
                IdentityKeyManager.serialize_public_key(self.user_pubkeys[username]['ed25519'])
            )
            self.callback('USER_VERIFY', {'username': username, 'fingerprint': finger})

    # ------------------------------------------------------------------
    # 信任管理
    def _is_user_trusted(self, username):
        if username not in self.user_pubkeys:
            return False
        finger = self._fingerprint_from_bytes(
            IdentityKeyManager.serialize_public_key(self.user_pubkeys[username]['ed25519'])
        )
        return self.trust_db['users'].get(username) == finger

    def trust_user(self, username):
        if username not in self.user_pubkeys:
            return False
        finger = self._fingerprint_from_bytes(
            IdentityKeyManager.serialize_public_key(self.user_pubkeys[username]['ed25519'])
        )
        self.trust_db['users'][username] = finger
        self._save_trust_db()
        # 处理缓存消息
        with self.pending_msg_lock:
            msgs = self.pending_messages.pop(username, [])
        for payload in msgs:
            self._decrypt_and_display(username, payload)
        self._end_verification(username)
        return True

    def distrust_user(self, username):
        with self._trust_lock:
            self.trust_db['users'].pop(username, None)
        self._save_trust_db()

    def get_user_fingerprint(self, username):
        if username not in self.user_pubkeys:
            return None
        return self._fingerprint_from_bytes(
            IdentityKeyManager.serialize_public_key(self.user_pubkeys[username]['ed25519'])
        )

    def _begin_verification(self, username):
        with self.pending_verifications_lock:
            if username in self.pending_verifications:
                return False
            self.pending_verifications.add(username)
            return True

    def _end_verification(self, username):
        with self.pending_verifications_lock:
            self.pending_verifications.discard(username)

    # ------------------------------------------------------------------
    # 服务器信任
    def confirm_server_trust(self, approved):
        endpoint = f"{self.host}:{self.port}"
        fingerprint = self._fingerprint_from_bytes(
            IdentityKeyManager.serialize_public_key(self.server_ed25519_pub)
        )
        if approved:
            self.trust_db['servers'][endpoint] = fingerprint
            self._save_trust_db()
            self.callback('SYS', "已信任服务器公钥")
        else:
            self.server_ed25519_pub = None
            self.server_x25519_pub = None
            self.callback('ERROR', "已拒绝服务器公钥，请重新连接")

    # ------------------------------------------------------------------
    # 登录与注册
    def login(self, username, password):
        self.pending_login_user = username
        self.last_password = password

        # 尝试加载本地私钥
        if not self.id_priv:
            local = self._load_local_private(username, password)
            if local:
                self.id_priv, self.x_priv = local
                self.id_pub = self.id_priv.public_key()
                self.x_pub = self.x_priv.public_key()
                self.local_key_loaded = True
            else:
                self.local_key_loaded = False

        if self.local_key_loaded:
            # 无密码登录（挑战）
            self._send({'cmd': 'login', 'data': {'username': username, 'no_password': True}})
        else:
            # 加密密码并登录
            enc_pw = ServerCrypto.encrypt_for_server(password.encode('utf-8'))
            self._send({'cmd': 'login', 'data': {'username': username, 'password': enc_pw}})

    def _respond_challenge(self, challenge, timestamp):
        if not self.id_priv:
            if self.callback:
                self.callback('ERROR', '缺少本地身份私钥，无法完成挑战应答')
            return
        data_to_sign = f"{challenge}:{timestamp}".encode('utf-8')
        sig = self.id_priv.sign(data_to_sign)
        self._send({
            'cmd': 'challenge_response',
            'data': {
                'username': self.pending_login_user,
                'challenge': challenge,
                'timestamp': timestamp,
                'signature': sig.hex()
            }
        })

    def register(self, username, password, store_private_key=True, invite_code=''):
        # 生成密钥对
        id_priv, id_pub = IdentityKeyManager.generate()
        x_priv, x_pub = ExchangeKeyManager.generate()

        self.id_priv = id_priv
        self.id_pub = id_pub
        self.x_priv = x_priv
        self.x_pub = x_pub

        data = {
            'username': username,
            'store_private_key': store_private_key,
            'ed25519_priv_pem': IdentityKeyManager.serialize_private_key(id_priv),
            'x25519_priv_hex': ExchangeKeyManager.serialize_private_key(x_priv),
            'invite_code': invite_code,
        }

        if store_private_key:
            # 加密私钥包
            keys = {
                'ed25519_priv': IdentityKeyManager.serialize_private_key(id_priv),
                'x25519_priv': ExchangeKeyManager.serialize_private_key(x_priv),
            }
            plain = json.dumps(keys).encode('utf-8')
            salt = os.urandom(16)
            key = PasswordManager.derive_key(password, salt)
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(plain) + encryptor.finalize()
            tag = encryptor.tag
            data['encrypted_private'] = {
                'salt': salt.hex(),
                'nonce': nonce.hex(),
                'ct': ct.hex(),
                'tag': tag.hex()
            }
            enc_pw = ServerCrypto.encrypt_for_server(password.encode('utf-8'))
            data['password'] = enc_pw
        else:
            # 本地存储
            self._save_local_private(username, password)

        self._send({'cmd': 'reg_user', 'data': data})

    def _save_local_private(self, username, password):
        keys = {
            'ed25519_priv': IdentityKeyManager.serialize_private_key(self.id_priv),
            'x25519_priv': ExchangeKeyManager.serialize_private_key(self.x_priv),
        }
        plain = json.dumps(keys).encode('utf-8')
        salt = os.urandom(16)
        key = PasswordManager.derive_key(password, salt)
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(plain) + encryptor.finalize()
        tag = encryptor.tag
        path = f'local_keys/{username}_private.enc'
        with open(path, 'wb') as f:
            f.write(salt + nonce + tag + ct)

    def _load_local_private(self, username, password):
        path = f'local_keys/{username}_private.enc'
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'rb') as f:
                data = f.read()
            salt = data[:16]
            nonce = data[16:28]
            tag = data[28:44]
            ct = data[44:]
            key = PasswordManager.derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plain = decryptor.update(ct) + decryptor.finalize()
            keys = json.loads(plain.decode('utf-8'))
            id_priv = IdentityKeyManager.deserialize_private_key(keys['ed25519_priv'])
            x_priv = ExchangeKeyManager.deserialize_private_key(keys['x25519_priv'])
            return id_priv, x_priv
        except Exception:
            return None

    def clear_password(self):
        self.last_password = None

    # ------------------------------------------------------------------
    # 消息发送
    def send_message(self, receiver, plaintext):
        if not self.id_priv:
            if self.callback:
                self.callback('ERROR', '未加载本地身份私钥，无法发送消息')
            return False
        if not re.match(r'^[A-Za-z0-9]{3,20}$', receiver):
            if self.callback:
                self.callback('ERROR', '用户名格式无效')
            return False
        if receiver not in self.user_pubkeys or 'x25519' not in self.user_pubkeys[receiver]:
            self._queue_pending_outgoing_message(receiver, plaintext)
            self._request_public_key(receiver)
            if self.callback:
                self.callback('SYS', f'正在获取 {receiver} 的公钥，消息将自动发送')
            return True
        return self._send_encrypted_message(receiver, plaintext)

    def _request_public_key(self, username):
        self._send({'cmd': 'get_pubkey', 'token': self.token, 'data': {'username': username}})

    def _request_online_users(self):
        self._send({'cmd': 'list_users', 'token': self.token})

    def logout(self):
        if self.token:
            self._send({'cmd': 'logout', 'token': self.token})
        self._disconnect_cleanup()

    def _disconnect_cleanup(self):
        self.running = False
        self.token = None
        self.username = None
        self.pending_login_user = None
        self.local_key_loaded = False
        self.id_priv = None
        self.id_pub = None
        self.x_priv = None
        self.x_pub = None
        self.server_ed25519_pub = None
        self.server_x25519_pub = None
        self.user_pubkeys.clear()
        with self.pending_msg_lock:
            self.pending_messages.clear()
        with self.pending_outgoing_lock:
            self.pending_outgoing_messages.clear()
        with self.pending_verifications_lock:
            self.pending_verifications.clear()
        self.clear_password()
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
        if self.callback:
            self.callback('UPDATE_BUTTONS',None)


# ----------------------------------------------------------------------
# GUI 工具函数（ctypes 结构体已在文件头部定义）
# ----------------------------------------------------------------------
def flash_taskbar(root, count=3):
    """Windows 任务栏闪烁"""
    try:
        hwnd = root.winfo_id()
        info = FLASHWINFO(
            ctypes.sizeof(FLASHWINFO),
            hwnd,
            FLASHW_TRAY,
            count,
            0
        )
        ctypes.windll.user32.FlashWindowEx(ctypes.byref(info))
    except Exception:
        pass


# ----------------------------------------------------------------------
class ChatGUI:
    """图形界面"""
    USER_LIST_REFRESH_MS = 5000

    def __init__(self):
        self.root = tk.Tk()
        # 设置全局默认字体，确保 ttk 控件和弹窗使用 Verdana
        default_font = ('Verdana', 10)
        self.root.option_add('*Font', default_font)
        self.root.option_add('*Dialog.msg.Font', default_font)
        self.root.title("万花筒聊天软件 V2.2")
        self.root.geometry("850x650")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.bind("<Unmap>", self.on_window_unmap)

        self.message_queue = queue.Queue()
        self.client = ChatClient()
        self.client.callback = self.on_message_received
        self._pending_register = None

        self.is_minimized_to_tray = False
        self.tray_icon = None
        self.is_exiting = False
        self._color_palette = [
            '#1f77b4',
            '#2ca02c',
            '#d62728',
            '#9467bd',
            '#ff7f0e',
            '#17becf',
            '#8c564b',
        ]
        self._name_colors = {}

        self.setup_ui()
        self.root.after(100, self.process_messages)
        self.root.after(self.USER_LIST_REFRESH_MS, self.refresh_online_users)
        self.root.after(300, self.connect_to_server)

    # ------------------------------------------------------------------
    # UI 构建
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)

        # 工具栏
        toolbar = ttk.Frame(main_frame)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        self.status_label = ttk.Label(toolbar, text="未连接", foreground="red")
        self.status_label.pack(side=tk.LEFT, padx=(0, 10))

        self.user_label = ttk.Label(toolbar, text="未登录")
        self.user_label.pack(side=tk.LEFT, padx=(0, 10))

        self.crypto_label = ttk.Label(toolbar, text="🔓 无加密", foreground="red")
        self.crypto_label.pack(side=tk.LEFT, padx=(0, 10))

        self.connect_btn = ttk.Button(toolbar, text="连接", command=self.connect_to_server)
        self.connect_btn.pack(side=tk.LEFT, padx=2)

        self.register_btn = ttk.Button(toolbar, text="注册", command=self.register_user, state=tk.DISABLED)
        self.register_btn.pack(side=tk.LEFT, padx=2)

        self.login_btn = ttk.Button(toolbar, text="登录", command=self.login_user, state=tk.DISABLED)
        self.login_btn.pack(side=tk.LEFT, padx=2)

        self.logout_btn = ttk.Button(toolbar, text="登出", command=self.logout_user, state=tk.DISABLED)
        self.logout_btn.pack(side=tk.LEFT, padx=2)
        self.about_btn = ttk.Button(toolbar, text="关于", command=self.show_about)
        self.about_btn.pack(side=tk.LEFT, padx=2)

        # 聊天区域
        chat_frame = ttk.Frame(main_frame)
        chat_frame.grid(row=1, column=0, sticky="nsew")
        chat_frame.columnconfigure(0, weight=1)
        chat_frame.rowconfigure(0, weight=1)

        self.chat_display = scrolledtext.ScrolledText(
            chat_frame, wrap=tk.WORD, width=50, height=20, state=tk.DISABLED)
        self.chat_display.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        # 在线用户列表（Treeview 加信任列）
        users_frame = ttk.LabelFrame(chat_frame, text="在线用户", padding="5")
        users_frame.grid(row=0, column=1, sticky="ns")
        columns = ('user', 'trust')
        self.users_tree = ttk.Treeview(users_frame, columns=columns, show='headings', height=20)
        self.users_tree.heading('user', text='用户')
        self.users_tree.heading('trust', text='信任')
        self.users_tree.column('user', width=100)
        self.users_tree.column('trust', width=60)
        self.users_tree.pack(fill=tk.BOTH, expand=True)

        # 右键菜单
        self.tree_menu = tk.Menu(self.root, tearoff=0)
        self.tree_menu.add_command(label="验证指纹", command=self.verify_selected_user)
        self.tree_menu.add_command(label="移除信任", command=self.distrust_selected_user)
        self.tree_menu.add_separator()
        self.tree_menu.add_command(label="复制指纹", command=self.copy_fingerprint)
        self.users_tree.bind("<Button-3>", self.on_tree_right_click)
        self.users_tree.bind("<Double-1>", self.on_user_double_click)

        # 发送区域
        send_frame = ttk.Frame(main_frame)
        send_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        send_frame.columnconfigure(0, weight=1)

        receiver_frame = ttk.Frame(send_frame)
        receiver_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        ttk.Label(receiver_frame, text="发送给:").pack(side=tk.LEFT, padx=(0, 5))
        self.receiver_entry = ttk.Entry(receiver_frame, width=15)
        self.receiver_entry.pack(side=tk.LEFT)

        input_frame = ttk.Frame(send_frame)
        input_frame.grid(row=1, column=0, sticky="ew")
        input_frame.columnconfigure(0, weight=1)

        self.message_entry = ttk.Entry(input_frame)
        self.message_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.message_entry.bind('<Return>', lambda e: self.send_message())

        self.send_btn = ttk.Button(input_frame, text="发送", command=self.send_message, state=tk.DISABLED)
        self.send_btn.grid(row=0, column=1)

        self.update_button_states()

    # ------------------------------------------------------------------
    # 按钮状态
    def update_button_states(self):
        if self.client and self.client.sock:
            self.connect_btn.config(state=tk.DISABLED)
            if self.client.server_ed25519_pub:
                self.register_btn.config(state=tk.NORMAL)
                self.login_btn.config(state=tk.NORMAL)
            else:
                self.register_btn.config(state=tk.DISABLED)
                self.login_btn.config(state=tk.DISABLED)

            if self.client.token:
                self.logout_btn.config(state=tk.NORMAL)
                self.send_btn.config(state=tk.NORMAL)
                self.user_label.config(text=f"用户: {self.client.username}")
                self.crypto_label.config(text="🔐 端到端加密", foreground="green")
            else:
                self.logout_btn.config(state=tk.DISABLED)
                self.send_btn.config(state=tk.DISABLED)
                self.user_label.config(text="未登录")
                self.crypto_label.config(text="🔓 未加密", foreground="red")
        else:
            self.connect_btn.config(state=tk.NORMAL)
            self.register_btn.config(state=tk.DISABLED)
            self.login_btn.config(state=tk.DISABLED)
            self.logout_btn.config(state=tk.DISABLED)
            self.send_btn.config(state=tk.DISABLED)
            # 未连接时恢复状态标签为默认未连接样式
            self.status_label.config(text="未连接", foreground="red")
            self.user_label.config(text="未登录")
            self.crypto_label.config(text="🔓 未加密", foreground="red")

    # ------------------------------------------------------------------
    def _dialog_input(self, title, prompt, show=None, initial=''):
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("400x180")
        dlg.resizable(False, False)

        ttk.Label(dlg, text=prompt, wraplength=350).pack(pady=(20, 10), padx=20)
        var = tk.StringVar(value=initial)
        entry = ttk.Entry(dlg, textvariable=var, width=40, show=show)
        entry.pack(pady=(0, 10))
        entry.focus_set()
        result = None

        def on_ok():
            nonlocal result
            result = var.get()
            dlg.destroy()

        def on_cancel():
            dlg.destroy()

        entry.bind('<Return>', lambda e: on_ok())
        entry.bind('<Escape>', lambda e: on_cancel())
        btn_frame = ttk.Frame(dlg)
        btn_frame.pack()
        ttk.Button(btn_frame, text="确定", command=on_ok, width=10).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="取消", command=on_cancel, width=10).pack(side=tk.LEFT, padx=5)

        self.center_dialog(dlg)
        self.root.wait_window(dlg)
        return result
    def _dialog_choice(self, title, message, choices):
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("500x250")
        dlg.resizable(False, False)

        ttk.Label(dlg, text=message, justify=tk.LEFT, wraplength=450).pack(pady=(20, 10), padx=20)
        # 使用单选列表 + 确认按钮，以便显示较长描述文本
        sel_var = tk.IntVar(value=-1)
        list_frame = ttk.Frame(dlg)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20)

        for idx, (text, val) in enumerate(choices):
            row = ttk.Frame(list_frame)
            row.pack(fill=tk.X, pady=4)
            rb = ttk.Radiobutton(row, variable=sel_var, value=idx)
            rb.pack(side=tk.LEFT)
            lbl = ttk.Label(row, text=text, wraplength=420, justify=tk.LEFT)
            lbl.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6,0))

        result = [None]

        def on_ok():
            idx = sel_var.get()
            if idx is None or idx < 0 or idx >= len(choices):
                result[0] = None
            else:
                result[0] = choices[idx][1]
            dlg.destroy()

        def on_cancel():
            result[0] = None
            dlg.destroy()

        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(pady=8)
        ttk.Button(btn_frame, text="确定", command=on_ok, width=12).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="取消", command=on_cancel, width=12).pack(side=tk.LEFT, padx=6)

        dlg.bind('<Escape>', lambda e: on_cancel())
        self.center_dialog(dlg)
        self.root.wait_window(dlg)
        return result[0]

    def _dialog_showinfo(self, title, message):
        messagebox.showinfo(title, message)

    def _dialog_showerror(self, title, message):
        messagebox.showerror(title, message)

    def show_about(self):
        about_text = (
            "KaleidoTalk 聊天软件\n"
            "版本 2.2\n"
            "Copyright (C) 2026 Bangze Han\n\n"
            "This program is free software: you can redistribute it and/or modify\n"
            "it under the terms of the GNU General Public License as published by\n"
            "the Free Software Foundation, either version 3 of the License, or\n"
            "(at your option) any later version.\n\n"
            "This program is distributed in the hope that it will be useful,\n"
            "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
            "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n"
            "You should have received a copy of the GNU General Public License\n"
            "along with this program. If not, see <https://www.gnu.org/licenses/>.\n\n"
            "使用第三方库：\n"
            "- cryptography (Apache 2.0)\n"
            "- pystray (LGPLv3)\n"
            "- PIL (MIT 衍生)\n"
        )
        self._dialog_showinfo("关于 KaleidoTalk", about_text)

    def center_dialog(self, dialog):
        dialog.update_idletasks()
        w = dialog.winfo_width()
        h = dialog.winfo_height()
        x = (dialog.winfo_screenwidth() // 2) - (w // 2)
        y = (dialog.winfo_screenheight() // 2) - (h // 2)
        dialog.geometry(f'{w}x{h}+{x}+{y}')

    # ------------------------------------------------------------------
    # 连接与登录流程
    def connect_to_server(self):
        addr = self._dialog_input("连接服务器", "输入 地址:端口", initial="127.0.0.1:5555")
        if not addr:
            return
        try:
            host, port = addr.split(':')
            port = int(port)
        except:
            host, port = "127.0.0.1", 5555
        self.client.host = host
        self.client.port = port
        self.client.callback = self.on_message_received
        ok = self.client.connect()
        if ok:
            self.status_label.config(text="已连接", foreground="green")
            self.append_chat("系统", "已连接到服务器", "green")
        else:
            self.status_label.config(text="连接失败", foreground="red")
            self._dialog_showerror("错误", "无法连接到服务器")
        self.update_button_states()

    def register_user(self):
        if not self.client.server_ed25519_pub:
            self._dialog_showerror("错误", "服务器公钥未就绪")
            return
        username = self._dialog_input("注册", "用户名 (3-20字母数字):")
        if not username or not re.match(r'^[A-Za-z0-9]{3,20}$', username):
            return
        pw = self._dialog_input("注册", "密码 (至少8位，含字母和数字):", show='*')
        if not pw or len(pw) < 8:
            return

        # 询问私钥存储策略
        choice = self._dialog_choice("私钥存储", "请选择私钥保存方式:",
                                     [("存储到服务器 (可在任何设备登录)", True),
                                      ("仅本地存储 (私钥不离开本机)", False)])
        if choice is None:
            return

        # 记录本次注册请求，若服务端返回 invite_required 可自动补填并重试
        self._pending_register = {
            'username': username,
            'password': pw,
            'store_private_key': choice,
            'invite_code': '',
        }

        invite = ''
        if self._reg_policy_required():
            invite = self._dialog_input("邀请码", "请输入邀请码:")
            if not invite:
                self._pending_register = None
                return
            self._pending_register['invite_code'] = invite

        self.client.register(username, pw, store_private_key=choice, invite_code=invite)

    def _reg_policy_required(self):
        # 连接后客户端会主动查询 get_reg_policy
        return bool(self.client.require_invite_for_register)

    def login_user(self):
        if not self.client.server_ed25519_pub:
            self._dialog_showerror("错误", "服务器公钥未就绪")
            return
        username = self._dialog_input("登录", "用户名:")
        if not username:
            return
        pw = self._dialog_input("登录", "密码:", show='*')
        if not pw:
            return
        self.client.login(username, pw)

    def logout_user(self):
        self.client.logout()
        self.append_chat("系统", "已登出")

    # ------------------------------------------------------------------
    # 消息发送与显示
    def send_message(self):
        receiver = self.receiver_entry.get().strip()
        msg = self.message_entry.get().strip()
        if not receiver or not msg:
            return
        if self.client.send_message(receiver, msg):
            self.append_chat("我", f"-> {receiver}: {msg}")
            self.message_entry.delete(0, tk.END)

    def append_chat(self, source, message, color=None):
        self.chat_display.config(state=tk.NORMAL)
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {source}: {message}\n"
        if color is None or color == 'auto':
            color = self._color_for_name(source)
        tag_name = f"fg_{color.lstrip('#').replace(' ', '_')}"
        self.chat_display.tag_configure(tag_name, foreground=color)
        start_index = self.chat_display.index(tk.END)
        self.chat_display.insert(tk.END, line)
        end_index = self.chat_display.index(tk.END)
        self.chat_display.tag_add(tag_name, start_index, end_index)
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)

    def _color_for_name(self, name):
        if name in self._name_colors:
            return self._name_colors[name]
        color = self._color_palette[len(self._name_colors) % len(self._color_palette)]
        self._name_colors[name] = color
        return color

    # ------------------------------------------------------------------
    # 回调处理
    def on_message_received(self, msg_type, content):
        self.message_queue.put((msg_type, content))

    def process_messages(self):
        try:
            while True:
                msg_type, content = self.message_queue.get_nowait()
                self.handle_message(msg_type, content)
        except queue.Empty:
            pass
        self.root.after(100, self.process_messages)

    def handle_message(self, msg_type, content):
        if msg_type == 'SYS':
            self.append_chat("系统", content)
        elif msg_type == 'ERROR':
            if content == 'invite_required' and self._pending_register is not None:
                invite = self._dialog_input("邀请码", "该服务器要求邀请码，请输入邀请码:")
                if invite:
                    self._pending_register['invite_code'] = invite
                    self.client.register(
                        self._pending_register['username'],
                        self._pending_register['password'],
                        store_private_key=self._pending_register['store_private_key'],
                        invite_code=invite,
                    )
                    return
            self.append_chat("错误", content)
        elif msg_type == 'SUCCESS':
            self.append_chat("成功", content)
            if isinstance(content, str) and ('注册成功' in content):
                self._pending_register = None
            self.update_button_states()
        elif msg_type == 'MESSAGE':
            if isinstance(content, dict):
                sender = content.get('sender', '消息')
                message = content.get('message', '')
                self.append_chat(sender, message)
            else:
                self.append_chat("消息", content)
            if self.is_minimized_to_tray:
                if isinstance(content, dict):
                    self._tray_notify(f"{content.get('sender', '消息')}: {content.get('message', '')}")
                else:
                    self._tray_notify(content)
            else:
                flash_taskbar(self.root)
        elif msg_type == 'USERS':
            self._update_user_list(content)
        elif msg_type == 'WARNING':
            self.append_chat("警告", content)
        elif msg_type == 'SERVER_VERIFY':
            endpoint = content.get('endpoint', '')
            finger = content.get('fingerprint', '')
            approved = self._show_server_fingerprint_dialog(endpoint, finger)
            self.client.confirm_server_trust(approved)
            if approved:
                self.update_button_states()
        elif msg_type == 'USER_VERIFY':
            username = content.get('username', '')
            finger = content.get('fingerprint', '')
            approved = self._show_user_fingerprint_dialog(username, finger)
            if approved:
                self.client.trust_user(username)
            else:
                self.client._end_verification(username)
        elif msg_type == 'UPDATE_BUTTONS':
            self.update_button_states()
        else:
            self.append_chat("原始", str(content), "gray")

    # ------------------------------------------------------------------
    # 用户列表
    def _update_user_list(self, users):
        self.users_tree.delete(*self.users_tree.get_children())
        for u in users:
            if u == self.client.username:
                continue
            trust_status = "✓" if self.client._is_user_trusted(u) else "?"
            self.users_tree.insert("", tk.END, values=(u, trust_status))

    def refresh_online_users(self):
        if self.client and self.client.sock and self.client.token:
            self.client._request_online_users()
        self.root.after(self.USER_LIST_REFRESH_MS, self.refresh_online_users)

    def on_tree_right_click(self, event):
        item = self.users_tree.identify_row(event.y)
        if item:
            self.users_tree.selection_set(item)
            self.tree_menu.post(event.x_root, event.y_root)

    def on_user_double_click(self, event):
        item = self.users_tree.focus()
        if not item:
            return
        username = self.users_tree.item(item, 'values')[0]
        self.receiver_entry.delete(0, tk.END)
        self.receiver_entry.insert(0, username)
        # 请求公钥（如果还没有）
        if username not in self.client.user_pubkeys:
            self.client._request_public_key(username)
        self.message_entry.focus()

    def verify_selected_user(self):
        item = self.users_tree.focus()
        if not item:
            return
        username = self.users_tree.item(item, 'values')[0]
        finger = self.client.get_user_fingerprint(username)
        if finger:
            self._show_user_fingerprint_dialog(username, finger)

    def distrust_selected_user(self):
        item = self.users_tree.focus()
        if not item:
            return
        username = self.users_tree.item(item, 'values')[0]
        self.client.distrust_user(username)
        self._update_user_list([self.users_tree.item(i, 'values')[0] for i in self.users_tree.get_children()])

    def copy_fingerprint(self):
        item = self.users_tree.focus()
        if not item:
            return
        username = self.users_tree.item(item, 'values')[0]
        finger = self.client.get_user_fingerprint(username)
        if finger:
            self.root.clipboard_clear()
            self.root.clipboard_append(finger)
            self.append_chat("系统", f"已复制 {username} 的指纹到剪贴板")

    # ------------------------------------------------------------------
    # 指纹对话框
    def _show_server_fingerprint_dialog(self, endpoint, fingerprint):
        dlg = tk.Toplevel(self.root)
        dlg.title("服务器公钥验证")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("600x300")
        dlg.resizable(False, False)

        ttk.Label(dlg, text=f"首次连接 {endpoint}，请核对服务器指纹:", wraplength=550).pack(pady=10)
        ttk.Label(dlg, text=fingerprint, font=("Courier", 10), background="#f0f0f0").pack(pady=10)

        result = [False]

        def approve():
            result[0] = True
            dlg.destroy()

        def reject():
            dlg.destroy()

        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="信任", command=approve, width=10).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="拒绝", command=reject, width=10).pack(side=tk.LEFT, padx=5)
        dlg.bind('<Escape>', lambda e: reject())
        self.center_dialog(dlg)
        self.root.wait_window(dlg)
        return result[0]

    def _show_user_fingerprint_dialog(self, username, fingerprint):
        dlg = tk.Toplevel(self.root)
        dlg.title("用户公钥验证")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("600x300")
        dlg.resizable(False, False)

        ttk.Label(dlg, text=f"请与 {username} 核对以下指纹以确认身份:", wraplength=550).pack(pady=10)
        ttk.Label(dlg, text=fingerprint, font=("Courier", 10), background="#f0f0f0").pack(pady=10)
        result = [False]

        def verify():
            result[0] = True
            dlg.destroy()

        def cancel():
            dlg.destroy()

        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="验证通过", command=verify, width=12).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="取消", command=cancel, width=12).pack(side=tk.LEFT, padx=5)
        dlg.bind('<Escape>', lambda e: cancel())
        self.center_dialog(dlg)
        self.root.wait_window(dlg)
        return result[0]

    # ------------------------------------------------------------------
    # 托盘与退出
    def on_closing(self):
        self.minimize_to_tray()

    def on_window_unmap(self, event):
        if not self.is_exiting and not self.is_minimized_to_tray and self.root.state() == 'iconic':
            self.root.after(0, self.minimize_to_tray)

    def minimize_to_tray(self):
        if pystray is None:
            self._quit_application()
            return
        self.root.withdraw()
        self.is_minimized_to_tray = True
        image = Image.new('RGB', (64, 64), color=(30, 136, 229))
        draw = ImageDraw.Draw(image)
        draw.ellipse((10, 10, 54, 54), fill=(255, 255, 255))
        draw.ellipse((20, 20, 44, 44), fill=(30, 136, 229))
        menu = pystray.Menu(
            pystray.MenuItem('打开', lambda: self.root.after(0, self.restore_from_tray)),
            pystray.MenuItem('退出', lambda: self.root.after(0, self._quit_application))
        )
        self.tray_icon = pystray.Icon('kaleido', image, '万花筒聊天', menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def restore_from_tray(self):
        self.is_minimized_to_tray = False
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None

    def _tray_notify(self, msg):
        if self.tray_icon:
            self.tray_icon.notify(msg[:100], "新消息")

    def _quit_application(self):
        self.is_exiting = True
        if self.tray_icon:
            self.tray_icon.stop()
        self.client.logout()
        # 在销毁窗口前更新按钮状态，确保 UI 状态已清理
        try:
            self.update_button_states()
        except Exception:
            pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ----------------------------------------------------------------------
def main():
    app = ChatGUI()
    app.run()


if __name__ == '__main__':
    print("KaleidoTalk Copyright (C) 2026 Bangze Han")
    print("This program comes with ABSOLUTELY NO WARRANTY.")
    print("This is free software, and you are welcome to redistribute it")
    print("under the terms of the GNU General Public License version 3 or later.")
    main()
