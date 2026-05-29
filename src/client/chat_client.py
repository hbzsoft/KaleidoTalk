# chat_client.py
# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


# chat_client.py
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
import ssl
import ctypes
from datetime import datetime
from src.common.network import set_socket_time_offset, get_socket_time_offset
from src.common.padding import (
    PaddedSender,
    PaddedReceiver,
    build_padding_packet,
    next_interval,
    PACKET_SIZE,
)
from src.common.crypto_utils import (
    IdentityKeyManager,
    ExchangeKeyManager,
    PasswordManager,
    MessageEncryptorV2,
    ServerCrypto,
    FingerprintWords,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519

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
        self.cert_verify_callback = None      # 用于弹出 TLS 证书确认窗口
        self.session_id = None
        self.session_key = None
        self.token = None
        self._auth_sequence = 0

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
        self.pending_manual_verifications = set()
        self.pending_manual_verifications_lock = threading.Lock()

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

        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread = None
        self._send_lock = threading.Lock()  # 保护 socket 并发写
        self._last_timestamp = 0  # 上次认证请求的时间戳，确保单调递增

    # ------------------------------------------------------------------
    # 掩护流量：心跳线程
    def _heartbeat_loop(self):
        """客户端心跳线程：定期发送填充包维持流量掩护"""
        try:
            while not self._heartbeat_stop.is_set():
                self._heartbeat_stop.wait(next_interval())
                if self._heartbeat_stop.is_set():
                    break
                try:
                    if self.sock:
                        with self._send_lock:
                            self.sock.sendall(build_padding_packet())
                except Exception:
                    break
        except Exception:
            pass

    def _start_heartbeat(self):
        """启动心跳线程"""
        self._heartbeat_stop.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True
        )
        self._heartbeat_thread.start()

    def _stop_heartbeat(self):
        """停止心跳线程"""
        self._heartbeat_stop.set()

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
            db = json.loads(data)
            # 将旧的 servers 字符串迁移为对象格式
            for endpoint, val in db.get('servers', {}).items():
                if isinstance(val, str):
                    db['servers'][endpoint] = {'ed25519': val}
            return db
        except Exception as e:
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
        )
        return hashlib.sha256(raw).hexdigest()

    def _fingerprint_from_bytes(self, pem_str):
        return hashlib.sha256(pem_str.encode('utf-8')).hexdigest()

    def _canonical_json(self, data):
        return json.dumps(data or {}, ensure_ascii=False, sort_keys=True, separators=(',', ':'))

    def _build_authenticated_payload(self, cmd, data=None):
        if not self.session_id or not self.session_key:
            raise ValueError('会话未建立')
        payload_data = data or {}
        self._auth_sequence += 1
        seq = self._auth_sequence
        timestamp = int(time.time() * 1000) + get_socket_time_offset(self.sock)
        # 确保时间戳单调递增，避免快速连续请求时时间戳相同被误判为重放
        if timestamp <= self._last_timestamp:
            timestamp = self._last_timestamp + 1
        self._last_timestamp = timestamp
        message = f'{self.session_id}{seq}{timestamp}{self._canonical_json(payload_data)}'.encode('utf-8')
        signature = hmac.new(self.session_key, message, hashlib.sha256).hexdigest()
        return {
            'cmd': cmd,
            'session_id': self.session_id,
            'seq': seq,
            'timestamp': timestamp,
            'hmac': signature,
            'data': payload_data,
        }

    def _decrypt_session_key(self, encrypted_session_key):
        eph_pub_bytes = base64.b64decode(encrypted_session_key['eph_pub'])
        ct = base64.b64decode(encrypted_session_key['ct'])
        tag = base64.b64decode(encrypted_session_key['tag'])
        nonce_b64 = encrypted_session_key.get('nonce')
        eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
        shared_secret = self.x_priv.exchange(eph_pub)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'kaleidotalk-session-key',
            backend=default_backend(),
        )
        aes_key = hkdf.derive(shared_secret)
        if nonce_b64:
            nonce = base64.b64decode(nonce_b64)
        else:
            hkdf_legacy = HKDF(
                algorithm=hashes.SHA256(),
                length=32 + 12,
                salt=None,
                info=b'kaleidotalk-session-key',
                backend=default_backend(),
            )
            legacy_km = hkdf_legacy.derive(shared_secret)
            nonce = legacy_km[32:44]
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    # ------------------------------------------------------------------
    # 连接与协议通信
    def connect(self):
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(5)
            raw_sock.connect((self.host, self.port))

            # 建立 TLS 连接
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # 手动验证指纹
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            tls_sock = context.wrap_socket(raw_sock, server_hostname=self.host)
            self.sock = tls_sock
            self.sock.settimeout(30.0)

            # 获取证书指纹并验证
            der_cert = self.sock.getpeercert(binary_form=True)
            tls_fingerprint = hashlib.sha256(der_cert).hexdigest()
            endpoint = f"{self.host}:{self.port}"

            # 检查信任库
            server_trust = self.trust_db['servers'].get(endpoint)
            if server_trust is None:
                # 首次连接，弹窗确认
                if self.cert_verify_callback:
                    ok = self.cert_verify_callback(endpoint, tls_fingerprint)
                    if not ok:
                        self.sock.close()
                        self.sock = None
                        if self.callback:
                            self.callback('ERROR', '已拒绝 TLS 证书')
                        return False
                    # 信任
                    self.trust_db['servers'][endpoint] = {'tls': tls_fingerprint}
                    self._save_trust_db()
                else:
                    # 无回调时直接信任（避免阻塞）
                    self.trust_db['servers'][endpoint] = {'tls': tls_fingerprint}
                    self._save_trust_db()
            else:
                stored_tls = server_trust.get('tls')
                if stored_tls and stored_tls != tls_fingerprint:
                    self.sock.close()
                    self.sock = None
                    if self.callback:
                        self.callback('ERROR', '服务器 TLS 证书指纹不匹配！可能遭受中间人攻击')
                    return False
                elif not stored_tls:
                    # 只有旧版 ed25519 指纹，补上 tls
                    server_trust['tls'] = tls_fingerprint
                    self._save_trust_db()

            self.running = True

            # 使用定长包接收欢迎信息
            receiver = PaddedReceiver()
            try:
                welcome_bytes = receiver.recv(self.sock)
                welcome = json.loads(welcome_bytes.decode('utf-8'))
            except Exception as e:
                if self.callback:
                    self.callback('ERROR', f'接收欢迎信息失败: {e}')
                self.sock.close()
                self.sock = None
                return False

            if welcome.get('type') == 'welcome':
                server_time_text = welcome.get('data', {}).get('server_time')
                try:
                    server_time = datetime.fromisoformat(server_time_text.replace('Z', '+00:00'))
                    local_time = datetime.now(server_time.tzinfo) if server_time.tzinfo else datetime.now()
                    offset_ms = int((server_time.timestamp() - local_time.timestamp()) * 1000)
                    set_socket_time_offset(self.sock, offset_ms)
                except Exception:
                    pass
                if self.callback:
                    self.callback('SYS', welcome['data']['message'])

            # 启动接收线程（使用定长包）
            threading.Thread(target=self._recv_loop, daemon=True).start()

            # 启动心跳线程（掩护流量）
            self._start_heartbeat()

            # 请求服务器公钥
            self._send({'cmd': 'get_server_pubkey'})
            # 查询注册策略
            self._send({'cmd': 'get_reg_policy'})
            return True

        except ssl.SSLError as e:
            if self.callback:
                self.callback('ERROR', f'TLS 错误: {e}')
            return False
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
            # 使用定长包发送（掩护流量）
            data = json.dumps(obj, ensure_ascii=False).encode('utf-8')
            with self._send_lock:
                PaddedSender.send(self.sock, data)
            return True
        except Exception as e:
            if self.callback:
                self.callback('ERROR', f'发送失败: {e}')
            return False

    def _recv_loop(self):
        receiver = PaddedReceiver()
        while self.running and self.sock:
            try:
                # 使用定长包接收（掩护流量）
                raw = receiver.recv(self.sock)
                if not raw:
                    break
                try:
                    msg = json.loads(raw.decode('utf-8'))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if msg.get('type') == 'ping':
                    continue
                self._handle_msg(msg)
            except ConnectionError:
                break
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
                sender = msg['sender']
                payload = msg['payload']
                self._process_incoming_message(sender, payload)
            elif msg['type'] == 'force_logout':
                self._disconnect_cleanup()
                if self.callback:
                    self.callback('SYS', '您的账号在其他设备登录，被迫下线')
            return

        status = msg.get('status')
        cmd = msg.get('cmd')
        data = msg.get('data', {})

        if status == 'error':
            if cmd == 'pubkey':
                target = data.get('username')
                if target:
                    self._clear_pending_outgoing_messages(target)
                    with self.pending_manual_verifications_lock:
                        self.pending_manual_verifications.discard(target)
                    self._end_verification(target)
            if self.callback:
                self.callback('ERROR', msg.get('error') or data.get('error', '未知错误'))
            return

        if cmd == 'server_pubkey':
            self.server_ed25519_pub = IdentityKeyManager.deserialize_public_key(data['ed25519'])
            self.server_x25519_pub = ExchangeKeyManager.deserialize_public_key(data['x25519'])
            ServerCrypto._ed25519_pub = self.server_ed25519_pub
            ServerCrypto._x25519_pub = self.server_x25519_pub
            endpoint = f"{self.host}:{self.port}"
            ed_fingerprint = self._fingerprint_from_bytes(data['ed25519'])

            # 更新信任库中的 Ed25519 指纹（TLS 已通过）
            server_entry = self.trust_db['servers'].get(endpoint, {})
            server_entry['ed25519'] = ed_fingerprint
            self.trust_db['servers'][endpoint] = server_entry
            self._save_trust_db()

            if self.callback:
                self.callback('SYS', "服务器公钥已通过 TLS 证书信任")
            if self.callback:
                self.callback('UPDATE_BUTTONS', None)

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

            self.session_id = data['session_id']
            self.token = None
            self.username = self.pending_login_user
            self.pending_login_user = None

            if 'encrypted_private' in data and data['encrypted_private']:
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
                try:
                    self.id_pub = IdentityKeyManager.deserialize_public_key(data['ed25519_pub'])
                    self.x_pub = ExchangeKeyManager.deserialize_public_key(data['x25519_pub'])
                except Exception as e:
                    if self.callback:
                        self.callback('ERROR', f"加载公钥失败: {e}")
                    self._disconnect_cleanup()
                    return

            try:
                self.session_key = self._decrypt_session_key(data['encrypted_session_key'])
            except Exception as e:
                if self.callback:
                    self.callback('ERROR', f'会话密钥解密失败: {e}')
                self._disconnect_cleanup()
                return

            self.user_pubkeys[self.username] = {
                'ed25519': self.id_pub,
                'x25519': self.x_pub,
            }

            self.clear_password()
            if self.callback:
                self.callback('SUCCESS', f"登录成功 ({self.username})")
            self._request_online_users()
            self.callback('UPDATE_BUTTONS', None)

        elif cmd == 'challenge_response' or status == 'challenge':
            challenge = data['challenge']
            timestamp = data['timestamp']
            self._respond_challenge(challenge, timestamp)

        elif cmd == 'pubkey':
            username = data['username']
            ed_pub = IdentityKeyManager.deserialize_public_key(data['ed25519_pub'])
            x_pub = ExchangeKeyManager.deserialize_public_key(data['x25519_pub'])
            self.user_pubkeys[username] = {'ed25519': ed_pub, 'x25519': x_pub}
            self._check_manual_verification(username)
            self._check_pending_outgoing_verification(username)
            self._check_pending_verification(username)

        elif cmd == 'users':
            users = data.get('users', [])
            if self.callback:
                self.callback('USERS', users)

        elif cmd == 'logout':
            self._clear_session_state()
            if self.callback:
                self.callback('UPDATE_BUTTONS', None)

    # ------------------------------------------------------------------
    # 消息加解密与缓存
    def _process_incoming_message(self, sender, encrypted_payload):
        if sender not in self.user_pubkeys:
            with self.pending_msg_lock:
                self.pending_messages.setdefault(sender, []).append(encrypted_payload)
            self._request_public_key(sender)
            return

        if not self._is_user_trusted(sender):
            with self.pending_msg_lock:
                self.pending_messages.setdefault(sender, []).append(encrypted_payload)
            if self._begin_verification(sender):
                finger = self._fingerprint_from_bytes(
                    IdentityKeyManager.serialize_public_key(self.user_pubkeys[sender]['ed25519'])
                )
                self.callback('USER_VERIFY', {'username': sender, 'fingerprint': finger})
            return

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
        return self._send(self._build_authenticated_payload('message', {
            'receiver': receiver,
            'payload': enc,
        }))

    def _check_pending_verification(self, username):
        with self.pending_manual_verifications_lock:
            if username in self.pending_manual_verifications:
                return
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

    def _check_pending_outgoing_verification(self, username):
        with self.pending_manual_verifications_lock:
            if username in self.pending_manual_verifications:
                return
        with self.pending_outgoing_lock:
            has_pending = username in self.pending_outgoing_messages and bool(self.pending_outgoing_messages[username])

        if not has_pending:
            return

        if self._is_user_trusted(username):
            self._flush_pending_outgoing_messages(username)
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
        with self.pending_msg_lock:
            msgs = self.pending_messages.pop(username, [])
        for payload in msgs:
            self._decrypt_and_display(username, payload)
        self._flush_pending_outgoing_messages(username)
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

    def get_fingerprint_words(self, username, word_count=6):
        fingerprint_hex = self.get_user_fingerprint(username)
        if not fingerprint_hex:
            return None
        try:
            from src.common.crypto_utils import FingerprintWords
            return FingerprintWords.fingerprint_to_words(fingerprint_hex, word_count)
        except Exception as e:
            if self.callback:
                self.callback('ERROR', f"生成指纹单词失败: {e}")
            return None

    def get_own_fingerprint_words(self, word_count=6):
        if not self.id_pub:
            return None
        try:
            from src.common.crypto_utils import FingerprintWords
            fingerprint_hex = self._fingerprint_from_bytes(
                IdentityKeyManager.serialize_public_key(self.id_pub)
            )
            return FingerprintWords.fingerprint_to_words(fingerprint_hex, word_count)
        except Exception as e:
            if self.callback:
                self.callback('ERROR', f"生成自己的指纹单词失败: {e}")
            return None

    def _begin_verification(self, username):
        with self.pending_verifications_lock:
            if username in self.pending_verifications:
                return False
            self.pending_verifications.add(username)
            return True

    def _end_verification(self, username):
        with self.pending_verifications_lock:
            self.pending_verifications.discard(username)

    def _check_manual_verification(self, username):
        with self.pending_manual_verifications_lock:
            if username not in self.pending_manual_verifications:
                return
            self.pending_manual_verifications.discard(username)

        if username not in self.user_pubkeys:
            return

        finger = self._fingerprint_from_bytes(
            IdentityKeyManager.serialize_public_key(self.user_pubkeys[username]['ed25519'])
        )
        if self.callback:
            self.callback('USER_VERIFY', {'username': username, 'fingerprint': finger})

    # ------------------------------------------------------------------
    # 服务器信任（TLS 证书确认由 cert_verify_callback 处理）
    def confirm_server_trust(self, approved):
        pass

    # ------------------------------------------------------------------
    # 登录与注册
    def login(self, username, password):
        self.pending_login_user = username
        self.last_password = password

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
            self._send({'cmd': 'login', 'data': {'username': username, 'no_password': True}})
        else:
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
        if self.token:
            self.logout()

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
        if not self.session_id or not self.session_key:
            if self.callback:
                self.callback('ERROR', '会话未建立，无法发送消息')
            return False
        if not re.match(r'^[A-Za-z0-9]{3,20}$', receiver):
            if self.callback:
                self.callback('ERROR', '用户名格式无效')
            return False
        if receiver not in self.user_pubkeys or 'x25519' not in self.user_pubkeys[receiver]:
            self._queue_pending_outgoing_message(receiver, plaintext)
            self._request_public_key(receiver)
            return True
        if not self._is_user_trusted(receiver):
            self._queue_pending_outgoing_message(receiver, plaintext)
            if self._begin_verification(receiver):
                finger = self._fingerprint_from_bytes(
                    IdentityKeyManager.serialize_public_key(self.user_pubkeys[receiver]['ed25519'])
                )
                self.callback('USER_VERIFY', {'username': receiver, 'fingerprint': finger})
            return True
        return self._send_encrypted_message(receiver, plaintext)

    def _request_public_key(self, username):
        self._send(self._build_authenticated_payload('get_pubkey', {'username': username}))

    def _request_online_users(self):
        self._send(self._build_authenticated_payload('list_users'))

    def logout(self):
        # 先停心跳，避免它继续占用发送锁；再发送合法的认证 logout 请求。
        # 这样服务器会立即从在线列表中移除该用户，其他客户端下一次轮询即可看到变化。
        if self.session_id and self.session_key and self.sock:
            self._stop_heartbeat()
            try:
                payload = self._build_authenticated_payload('logout')
                with self._send_lock:
                    PaddedSender.send(self.sock, json.dumps(payload, ensure_ascii=False).encode('utf-8'))
            except Exception:
                pass
        else:
            self._stop_heartbeat()

        self._clear_session_state()
        self._auth_sequence = 0
        self._last_timestamp = 0
        # 关闭连接
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        if self.callback:
            self.callback('UPDATE_BUTTONS', None)

    def _clear_session_state(self):
        self.session_id = None
        self.session_key = None
        self._auth_sequence = 0
        self._last_timestamp = 0
        self.token = None
        self.username = None
        self.pending_login_user = None
        self.local_key_loaded = False
        self.id_priv = None
        self.id_pub = None
        self.x_priv = None
        self.x_pub = None
        self.user_pubkeys.clear()
        with self.pending_msg_lock:
            self.pending_messages.clear()
        with self.pending_outgoing_lock:
            self.pending_outgoing_messages.clear()
        with self.pending_verifications_lock:
            self.pending_verifications.clear()
        with self.pending_manual_verifications_lock:
            self.pending_manual_verifications.clear()
        self.clear_password()

    def _disconnect_cleanup(self):
        self.running = False
        self._stop_heartbeat()
        self._clear_session_state()
        self.server_ed25519_pub = None
        self.server_x25519_pub = None
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
        if self.callback:
            self.callback('UPDATE_BUTTONS', None)


# ----------------------------------------------------------------------
# GUI 工具函数（ctypes 结构体已在文件头部定义）
# ----------------------------------------------------------------------
def flash_taskbar(root, count=3):
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
