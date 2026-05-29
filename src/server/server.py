# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


# server.py — 服务器主入口（集成掩护流量）
import socket
import threading
import json
import os
import struct
import hashlib
import time
import logging
import ssl
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from src.common.padding import (
    PaddedSender,
    PaddedReceiver,
    build_padding_packet,
    next_interval,
    PACKET_SIZE,
)
from src.common.crypto_utils import ServerCrypto
from src.server.server_storage import (
    locks as storage_locks,
    USERS_FILE,
    KEYS_FILE,
    INVITES_FILE,
    BANS_FILE,
    load_users,
    save_users,
    load_user_keys,
    save_user_keys,
    load_invites,
    save_invites,
    load_bans_file,
    save_bans_file,
    require_invite_code,
)
from src.server.server_session import (
    locks,
    clients,
    logged_in_users,
    ip_ban_list,
    user_ban_list,
    ip_attempts,
    register_socket,
    unregister_socket,
)
from src.server.server_commands import handle_message

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
# TLS 上下文（全局）
TLS_CONTEXT = None
TLS_CERT_FILE = 'server_keys/server.crt'
TLS_KEY_FILE = 'server_keys/server.key'


def generate_self_signed_cert(cert_file=TLS_CERT_FILE, key_file=TLS_KEY_FILE):
    """生成自签名证书和 RSA 密钥并保存到文件"""
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return

    os.makedirs(os.path.dirname(cert_file), exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KaleidoTalk"),
        x509.NameAttribute(NameOID.COMMON_NAME, "KaleidoTalk Server"),
    ])

    not_before = datetime.now(timezone.utc)
    not_after = not_before + timedelta(days=365 * 10)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    logger.info(f"已生成 TLS 证书和密钥: {cert_file}, {key_file}")


def create_tls_context():
    """创建并返回服务器端 TLS 上下文"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)
    context.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, 'TLSVersion'):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    return context


# ----------------------------------------------------------------------
# 掩护流量：服务端心跳线程
def _heartbeat_sender(sock, stop_event, send_lock):
    """服务端心跳发送线程：定期发送填充包维持流量掩护"""
    try:
        while not stop_event.is_set():
            stop_event.wait(next_interval())
            if stop_event.is_set():
                break
            try:
                with send_lock:
                    sock.sendall(build_padding_packet())
            except Exception:
                break
    except Exception:
        pass


# ----------------------------------------------------------------------
# PaddedSocket 包装器（模块级定义，确保对象唯一性）
class PaddedSocket:
    """包装 socket，拦截 send_msg 的输出并转换为定长包发送原始响应

    关键：每个客户端连接只创建一个 PaddedSocket 实例，
    因为 server_session 中的 clients / logged_in_users 字典以该对象为 key。
    如果每次消息都新建实例，unregister_socket 将无法通过 key 找到对应条目，
    导致用户退出后仍残留在在线列表中。
    """
    def __init__(self, inner_sock, lock):
        self._inner = inner_sock
        self._lock = lock
        self._send_buffer = b''

    def sendall(self, data):
        # send_msg 发送的格式: [4字节长度][JSON帧数据]
        # 我们需要解析帧数据，提取其中的 data 字段，然后用定长包发送
        self._send_buffer += data

        # 尝试解析帧
        while len(self._send_buffer) >= 4:
            length = struct.unpack('>I', self._send_buffer[:4])[0]
            if length > 10 * 1024 * 1024:
                # 异常，清空缓冲区
                self._send_buffer = b''
                break
            if len(self._send_buffer) < 4 + length:
                # 数据不完整，等待更多数据
                break

            # 提取帧数据
            frame_data = self._send_buffer[4:4+length]
            self._send_buffer = self._send_buffer[4+length:]

            try:
                frame = json.loads(frame_data.decode('utf-8'))
                # 提取原始响应数据
                response = frame.get('data', frame)
                # 用定长包发送原始响应
                response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
                with self._lock:
                    PaddedSender.send(self._inner, response_bytes)
            except Exception:
                # 解析失败，直接发送原始数据
                with self._lock:
                    PaddedSender.send(self._inner, frame_data)

    def recv(self, bufsize):
        return self._inner.recv(bufsize)

    def settimeout(self, timeout):
        self._inner.settimeout(timeout)

    def getpeername(self):
        return self._inner.getpeername()

    def close(self):
        self._inner.close()

    def fileno(self):
        return self._inner.fileno()


def handle_message_padded(padded_sock, addr, payload):
    """处理命令并使用定长包发送响应"""
    handle_message(padded_sock, addr, payload)


# ----------------------------------------------------------------------
# 客户端处理线程（集成掩护流量）
def handle_client(raw_sock, addr):
    """处理单个客户端连接

    通信流程：
    1. TLS 握手
    2. 发送欢迎消息（使用定长包）
    3. 启动心跳线程（发送填充包）
    4. 主循环：接收定长包 → 拆封 → 处理命令 → 封装响应
    """
    global TLS_CONTEXT
    sock = None
    stop_event = threading.Event()
    send_lock = threading.Lock()  # 保护 socket 并发写

    try:
        sock = TLS_CONTEXT.wrap_socket(raw_sock, server_side=True)
    except Exception as e:
        logger.error(f"TLS 握手失败 ({addr}): {e}")
        raw_sock.close()
        return

    logger.info(f"新 TLS 连接 (掩护流量): {addr}")
    sock.settimeout(30.0)

    # 创建定长包接收器
    receiver = PaddedReceiver()

    # 发送欢迎消息（使用定长包封装）
    try:
        welcome = {
            'type': 'welcome',
            'data': {
                'message': '欢迎使用KaleidoTalk V2.3',
                'server_time': datetime.now(timezone.utc).isoformat()
            }
        }
        welcome_bytes = json.dumps(welcome, ensure_ascii=False).encode('utf-8')
        with send_lock:
            PaddedSender.send(sock, welcome_bytes)
    except Exception:
        sock.close()
        return

    # 启动心跳线程（掩护流量）
    heartbeat = threading.Thread(
        target=_heartbeat_sender,
        args=(sock, stop_event, send_lock),
        daemon=True
    )
    heartbeat.start()

    # 创建 PaddedSocket 包装器（整个连接生命周期复用同一个实例）
    # 这是关键：server_session 的 clients / logged_in_users 以该对象为 key，
    # 如果每次消息都新建实例，logout 和连接断开时 unregister_socket 将无法匹配。
    padded_sock = PaddedSocket(sock, send_lock)

    # 主消息循环
    while True:
        try:
            # 接收定长包，自动重组为完整消息
            raw = receiver.recv(sock)
            if not raw:
                break

            # 解析 JSON 消息
            try:
                payload = json.loads(raw.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue

            # 处理命令（复用同一个 padded_sock）
            handle_message_padded(padded_sock, addr, payload)

        except ConnectionError:
            break
        except socket.timeout:
            # 超时不做特殊处理，心跳线程负责维持流量
            continue
        except Exception as e:
            logger.error(f"处理消息异常 ({addr}): {e}")
            break

    # 清理（使用同一个 padded_sock 以确保能正确 unregister）
    stop_event.set()
    unregister_socket(padded_sock)
    try:
        sock.close()
    except Exception:
        pass
    logger.info(f"连接关闭: {addr}")


# ----------------------------------------------------------------------
# 主函数
def start_server(host='0.0.0.0', port=5555):
    global TLS_CONTEXT

    # 初始化服务器密钥
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

    # 生成/加载 TLS 证书
    generate_self_signed_cert()
    TLS_CONTEXT = create_tls_context()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)

    logger.info(f"服务器已启动 (TLS + 掩护流量) {host}:{port}")
    logger.info(f"定长包大小: {PACKET_SIZE} 字节")
    logger.info(f"服务器 ed25519 指纹: {hashlib.sha256(ServerCrypto.get_ed25519_pub_pem().encode()).hexdigest()}")
    logger.info(f"邀请码注册状态: {require_invite_code()}")

    # 初始化数据文件
    if not os.path.exists(USERS_FILE):
        save_users({})
    if not os.path.exists(KEYS_FILE):
        save_user_keys({})
    if not os.path.exists(INVITES_FILE):
        save_invites({'require_invite': False, 'codes': {}})

    # 加载封禁列表
    try:
        bans = load_bans_file()
        now_t = time.time()
        for ip, until in bans.get('ip_bans', {}).items():
            try:
                if not until or float(until) > now_t:
                    ip_ban_list[ip] = float(until)
            except Exception:
                continue
        user_ban_list.clear()
        for u in bans.get('user_bans', {}):
            user_ban_list[u] = True
        logger.info('已加载封禁列表')
    except Exception:
        logger.warning('加载封禁列表失败或文件不存在')

    try:
        while True:
            raw_sock, addr = server.accept()
            threading.Thread(target=handle_client, args=(raw_sock, addr), daemon=True).start()
    except KeyboardInterrupt:
        logger.info("服务器关闭中...")
    finally:
        server.close()


if __name__ == '__main__':
    print("KaleidoTalk Copyright (C) 2026 Bangze Han")
    print("This program comes with ABSOLUTELY NO WARRANTY.")
    print("This is free software, and you are welcome to redistribute it")
    print("under the terms of the GNU General Public License version 3 or later.")
    print()
    print("版本 2.3")
    start_server('0.0.0.0', 5555)
