# Copyright (C) 2026 Bangze Han

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


# crypto_utils.py
import os
import base64
import hashlib
import hmac as hmac_mod
import json
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

class IdentityKeyManager:
    """Ed25519 身份密钥管理"""
    @staticmethod
    def generate():
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_private_key(private_key, password=None):
        encryption_alg = serialization.NoEncryption()
        if password:
            encryption_alg = serialization.BestAvailableEncryption(password.encode('utf-8'))
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_alg
        ).decode('utf-8')

    @staticmethod
    def deserialize_private_key(pem_str, password=None):
        password_bytes = password.encode('utf-8') if password else None
        return serialization.load_pem_private_key(
            pem_str.encode('utf-8'),
            password=password_bytes,
            backend=default_backend()
        )

    @staticmethod
    def serialize_public_key(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    @staticmethod
    def deserialize_public_key(pem_str):
        return serialization.load_pem_public_key(
            pem_str.encode('utf-8'),
            backend=default_backend()
        )

    @staticmethod
    def sign(private_key, data: bytes) -> bytes:
        return private_key.sign(data)

    @staticmethod
    def verify(public_key, signature: bytes, data: bytes) -> bool:
        try:
            public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

class ExchangeKeyManager:
    """X25519 密钥交换密钥管理"""
    @staticmethod
    def generate():
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_private_key(private_key):
        return private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ).hex()

    @staticmethod
    def deserialize_private_key(hex_str):
        return x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(hex_str))

    @staticmethod
    def serialize_public_key(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()

    @staticmethod
    def deserialize_public_key(hex_str):
        return x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))

    @staticmethod
    def ecdh(private_key, peer_public_key) -> bytes:
        return private_key.exchange(peer_public_key)

class PasswordManager:
    """密码哈希与验证"""
    SALT_LENGTH = 16
    KEY_LENGTH = 32
    ITERATIONS = 600_000

    @staticmethod
    def generate_salt():
        return os.urandom(PasswordManager.SALT_LENGTH)

    @staticmethod
    def derive_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=PasswordManager.KEY_LENGTH,
            salt=salt,
            iterations=PasswordManager.ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    @staticmethod
    def hash_password(password):
        salt = PasswordManager.generate_salt()
        derived = PasswordManager.derive_key(password, salt)
        # 存储格式：PBKDF2$<hex(salt)>$<hex(derived)>
        return f"PBKDF2${salt.hex()}${derived.hex()}"

    @staticmethod
    def verify_password(stored_hash, password):
        try:
            parts = stored_hash.split('$')
            if len(parts) != 3 or parts[0] != 'PBKDF2':
                return False
            salt = bytes.fromhex(parts[1])
            expected = bytes.fromhex(parts[2])
            candidate = PasswordManager.derive_key(password, salt)
            return hmac_mod.compare_digest(candidate, expected)
        except Exception:
            return False

class MessageEncryptorV2:
    """带签名的 X25519 ECDH + AES-256-GCM 加密"""
    @staticmethod
    def encrypt(plaintext: str, recipient_x25519_pub, sender_identity_priv):
        """
        返回 JSON 字符串 (base64 encoded fields)
        """
        # 生成临时 X25519 密钥对
        eph_priv = x25519.X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key()
        # ECDH
        shared_secret = eph_priv.exchange(recipient_x25519_pub)
        # HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32 + 12,  # key(32) + nonce(12)
            salt=None,
            info=b'kaleido-msg',
            backend=default_backend()
        )
        key_material = hkdf.derive(shared_secret)
        aes_key = key_material[:32]
        nonce = key_material[32:44]
        # GCM 加密
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        tag = encryptor.tag
        # 签名 (eph_pub || ciphertext || tag)
        signed_data = eph_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) + ciphertext + tag
        signature = sender_identity_priv.sign(signed_data)
        # 组装
        packet = {
            'eph_pub': base64.b64encode(eph_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode(),
            'ct': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode(),
            'sig': base64.b64encode(signature).decode(),
        }
        return json.dumps(packet)

    @staticmethod
    def decrypt(encrypted_json_str, recipient_x25519_priv, sender_identity_pub):
        """
        返回 (plaintext_or_None, error_string)
        """
        try:
            p = json.loads(encrypted_json_str)
            eph_pub_bytes = base64.b64decode(p['eph_pub'])
            eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
            ct = base64.b64decode(p['ct'])
            tag = base64.b64decode(p['tag'])
            sig = base64.b64decode(p['sig'])
            # 验证签名
            signed_data = eph_pub_bytes + ct + tag
            sender_identity_pub.verify(sig, signed_data)  # 若无效会抛出异常
            # ECDH
            shared_secret = recipient_x25519_priv.exchange(eph_pub)
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32 + 12,
                salt=None,
                info=b'kaleido-msg',
                backend=default_backend()
            )
            key_material = hkdf.derive(shared_secret)
            aes_key = key_material[:32]
            nonce = key_material[32:44]
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plain = decryptor.update(ct) + decryptor.finalize()
            return plain.decode('utf-8'), None
        except InvalidSignature:
            return None, "签名验证失败"
        except Exception as e:
            return None, f"解密失败: {str(e)}"

class ServerCrypto:
    """服务器密钥管理与客户端-服务器密码传输加密"""
    _ed25519_priv = None
    _ed25519_pub = None
    _x25519_priv = None
    _x25519_pub = None
    _key_dir = 'server_keys'
    _encrypted_file = _key_dir + '/server_master.enc'

    @classmethod
    def initialize(cls, admin_password):
        """加载或生成服务器密钥。若密码错误将抛异常。"""
        if not os.path.exists(cls._key_dir):
            os.makedirs(cls._key_dir)
        if os.path.exists(cls._encrypted_file):
            # 解密
            with open(cls._encrypted_file, 'rb') as f:
                data = f.read()
            salt = data[:16]
            iv = data[16:28]
            ciphertext = data[28:]
            key = PasswordManager.derive_key(admin_password, salt)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, ciphertext[-16:]), backend=default_backend())
            decryptor = cipher.decryptor()
            try:
                plain = decryptor.update(ciphertext[:-16]) + decryptor.finalize()
            except Exception:
                raise ValueError("管理密码错误或密钥文件损坏")
            keys = json.loads(plain.decode('utf-8'))
            cls._ed25519_priv = IdentityKeyManager.deserialize_private_key(keys['ed25519_priv'])
            cls._ed25519_pub = cls._ed25519_priv.public_key()
            cls._x25519_priv = ExchangeKeyManager.deserialize_private_key(keys['x25519_priv'])
            cls._x25519_pub = cls._x25519_priv.public_key()
        else:
            # 生成新密钥并加密保存
            cls._ed25519_priv, cls._ed25519_pub = IdentityKeyManager.generate()
            cls._x25519_priv, cls._x25519_pub = ExchangeKeyManager.generate()
            keys = {
                'ed25519_priv': IdentityKeyManager.serialize_private_key(cls._ed25519_priv),
                'x25519_priv': ExchangeKeyManager.serialize_private_key(cls._x25519_priv),
            }
            plaintext = json.dumps(keys).encode('utf-8')
            salt = os.urandom(16)
            key = PasswordManager.derive_key(admin_password, salt)
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(plaintext) + encryptor.finalize()
            tag = encryptor.tag
            with open(cls._encrypted_file, 'wb') as f:
                f.write(salt + nonce + ct + tag)
            print("[ServerCrypto] 已生成新服务器密钥并加密保存。")

    @classmethod
    def get_ed25519_pub_pem(cls):
        return IdentityKeyManager.serialize_public_key(cls._ed25519_pub)

    @classmethod
    def get_x25519_pub_hex(cls):
        return ExchangeKeyManager.serialize_public_key(cls._x25519_pub)

    @classmethod
    def encrypt_for_server(cls, data: bytes) -> dict:
        """客户端调用：使用服务器 X25519 公钥加密数据，返回 JSON 可序列化的字典"""
        eph_priv = x25519.X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key()
        shared = eph_priv.exchange(cls._x25519_pub)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32 + 12,
            salt=None,
            info=b'server-enc',
            backend=default_backend()
        )
        km = hkdf.derive(shared)
        aes_key = km[:32]
        nonce = km[32:44]
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        return {
            'eph_pub': base64.b64encode(eph_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode(),
            'ct': base64.b64encode(ct).decode(),
            'tag': base64.b64encode(tag).decode(),
        }

    @classmethod
    def decrypt_from_client(cls, encrypted_dict: dict) -> bytes:
        """服务器调用：解密密文，返回明文 bytes"""
        eph_pub_bytes = base64.b64decode(encrypted_dict['eph_pub'])
        eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
        ct = base64.b64decode(encrypted_dict['ct'])
        tag = base64.b64decode(encrypted_dict['tag'])
        shared = cls._x25519_priv.exchange(eph_pub)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32 + 12,
            salt=None,
            info=b'server-enc',
            backend=default_backend()
        )
        km = hkdf.derive(shared)
        aes_key = km[:32]
        nonce = km[32:44]
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plain = decryptor.update(ct) + decryptor.finalize()
        return plain