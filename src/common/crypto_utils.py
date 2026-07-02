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
import gzip
import json
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

EMBEDDED_BIP39_WORDLIST_B64_GZ = """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
28E8MwAA"""

class IdentityKeyManager:
    """Ed25519 identity key management"""
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
    """X25519 key exchange management"""
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
    """Password hashing and verification"""
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
        # Storage format: PBKDF2$<hex(salt)>$<hex(derived)>
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
    """Signed X25519 ECDH + AES-256-GCM encryption"""
    @staticmethod
    def encrypt(plaintext: str, recipient_x25519_pub, sender_identity_priv, key_id=None):
        """
        Return JSON string (base64 encoded fields).
        If key_id is provided, it is included in the packet for key rotation support.
        """
        # Generate ephemeral X25519 key pair
        eph_priv = x25519.X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key()
        # ECDH
        shared_secret = eph_priv.exchange(recipient_x25519_pub)
        # HKDF
        salt = os.urandom(16)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'kaleido-msg',
            backend=default_backend()
        )
        aes_key = hkdf.derive(shared_secret)
        nonce = os.urandom(12)
        # GCM encryption
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        tag = encryptor.tag
        # Sign (eph_pub || ciphertext || tag)
        signed_data = eph_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) + ciphertext + tag
        signature = sender_identity_priv.sign(signed_data)
        # Assemble
        packet = {
            'eph_pub': base64.b64encode(eph_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode(),
            'ct': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'sig': base64.b64encode(signature).decode(),
            'salt': base64.b64encode(salt).decode(),
        }
        if key_id:
            packet['key_id'] = key_id
        return json.dumps(packet)

    @staticmethod
    def decrypt(encrypted_json_str, recipient_x25519_priv, sender_identity_pub):
        """
        Return (plaintext_or_None, error_string)
        """
        try:
            p = json.loads(encrypted_json_str)
            eph_pub_bytes = base64.b64decode(p['eph_pub'])
            eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
            ct = base64.b64decode(p['ct'])
            tag = base64.b64decode(p['tag'])
            nonce_b64 = p.get('nonce')
            sig = base64.b64decode(p['sig'])
            salt_b64 = p.get('salt')
            # Verify signature
            signed_data = eph_pub_bytes + ct + tag
            sender_identity_pub.verify(sig, signed_data)  # Raises exception if invalid
            # ECDH
            shared_secret = recipient_x25519_priv.exchange(eph_pub)
            salt = base64.b64decode(salt_b64) if salt_b64 else None
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b'kaleido-msg',
                backend=default_backend()
            )
            aes_key = hkdf.derive(shared_secret)
            nonce = base64.b64decode(nonce_b64)
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plain = decryptor.update(ct) + decryptor.finalize()
            return plain.decode('utf-8'), None
        except InvalidSignature:
            return None, "Signature verification failed"
        except Exception as e:
            return None, f"Decryption failed: {str(e)}"

class ServerCrypto:
    """Server key management and client-server password transport encryption"""
    _ed25519_priv = None
    _ed25519_pub = None
    _x25519_priv = None
    _x25519_pub = None
    _key_dir = 'server_keys'
    _encrypted_file = _key_dir + '/server_master.enc'

    @classmethod
    def initialize(cls, admin_password):
        """Load or generate server keys. Raises exception if password is wrong."""
        if not os.path.exists(cls._key_dir):
            os.makedirs(cls._key_dir)
        if os.path.exists(cls._encrypted_file):
            # Decrypt
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
                raise ValueError("Admin password incorrect or key file corrupted")
            keys = json.loads(plain.decode('utf-8'))
            cls._ed25519_priv = IdentityKeyManager.deserialize_private_key(keys['ed25519_priv'])
            cls._ed25519_pub = cls._ed25519_priv.public_key()
            cls._x25519_priv = ExchangeKeyManager.deserialize_private_key(keys['x25519_priv'])
            cls._x25519_pub = cls._x25519_priv.public_key()
        else:
            # Generate new keys and save encrypted
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
            print("[ServerCrypto] Generated new server keys and saved encrypted.")

    @classmethod
    def initialize_noninteractive(cls):
        """Non-interactive initialization: load unencrypted PEM or generate new keys.

        Behavior:
        - If server_keys/server_ed25519.pem exists (unencrypted PEM): load it.
        - If server_master.enc exists (encrypted): raise error (cannot decrypt without password).
        - If neither exists: generate new keys and save as unencrypted PEM files.
        """
        if not os.path.exists(cls._key_dir):
            os.makedirs(cls._key_dir)

        ed_pem_path = os.path.join(cls._key_dir, 'server_ed25519.pem')
        x_pem_path = os.path.join(cls._key_dir, 'server_x25519.pem')

        if os.path.exists(cls._encrypted_file):
            raise ValueError(
                "Encrypted key file server_master.enc found. "
                "Cannot decrypt in non-interactive mode. "
                "Use --interactive mode or remove the encrypted file."
            )

        if os.path.exists(ed_pem_path) and os.path.exists(x_pem_path):
            # Load existing unencrypted PEM files
            with open(ed_pem_path, 'r', encoding='utf-8') as f:
                cls._ed25519_priv = IdentityKeyManager.deserialize_private_key(f.read())
            cls._ed25519_pub = cls._ed25519_priv.public_key()
            with open(x_pem_path, 'r', encoding='utf-8') as f:
                cls._x25519_priv = ExchangeKeyManager.deserialize_private_key(f.read())
            cls._x25519_pub = cls._x25519_priv.public_key()
            print("[ServerCrypto] Loaded existing unencrypted PEM keys.")
        else:
            # Generate new keys and save as unencrypted PEM
            cls._ed25519_priv, cls._ed25519_pub = IdentityKeyManager.generate()
            cls._x25519_priv, cls._x25519_pub = ExchangeKeyManager.generate()
            with open(ed_pem_path, 'w', encoding='utf-8') as f:
                f.write(IdentityKeyManager.serialize_private_key(cls._ed25519_priv))
            with open(x_pem_path, 'w', encoding='utf-8') as f:
                f.write(ExchangeKeyManager.serialize_private_key(cls._x25519_priv))
            print("[ServerCrypto] Generated new unencrypted PEM keys.")

    @classmethod
    def get_ed25519_pub_pem(cls):
        return IdentityKeyManager.serialize_public_key(cls._ed25519_pub)

    @classmethod
    def get_x25519_pub_hex(cls):
        return ExchangeKeyManager.serialize_public_key(cls._x25519_pub)

    @classmethod
    def encrypt_for_server(cls, data: bytes) -> dict:
        """Client call: encrypt data with server X25519 public key and return JSON-serializable dict"""
        eph_priv = x25519.X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key()
        shared = eph_priv.exchange(cls._x25519_pub)
        salt = os.urandom(16)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'server-enc',
            backend=default_backend()
        )
        aes_key = hkdf.derive(shared)
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        return {
            'eph_pub': base64.b64encode(eph_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode(),
            'ct': base64.b64encode(ct).decode(),
            'tag': base64.b64encode(tag).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'salt': base64.b64encode(salt).decode(),
        }

    @classmethod
    def decrypt_from_client(cls, encrypted_dict: dict) -> bytes:
        """Server call: decrypt ciphertext and return plaintext bytes"""
        eph_pub_bytes = base64.b64decode(encrypted_dict['eph_pub'])
        eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
        ct = base64.b64decode(encrypted_dict['ct'])
        tag = base64.b64decode(encrypted_dict['tag'])
        nonce_b64 = encrypted_dict.get('nonce')
        salt_b64 = encrypted_dict.get('salt')
        shared = cls._x25519_priv.exchange(eph_pub)
        salt = base64.b64decode(salt_b64) if salt_b64 else None
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'server-enc',
            backend=default_backend()
        )
        aes_key = hkdf.derive(shared)
        nonce = base64.b64decode(nonce_b64)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plain = decryptor.update(ct) + decryptor.finalize()
        return plain


class FingerprintWords:
    """
    Convert SHA-256 fingerprint to readable English word list (similar to Signal safety code)
    Using BIP39 standard English word list (2048 words)
    """
    
    # Load BIP39 word list from english.txt
    _wordlist = None
    
    @classmethod
    def _load_wordlist(cls):
        """Load embedded word list; file version is compatibility fallback only"""
        if cls._wordlist is None:
            try:
                decoded = gzip.decompress(base64.b64decode(EMBEDDED_BIP39_WORDLIST_B64_GZ))
                cls._wordlist = [word.strip() for word in decoded.decode('utf-8').splitlines() if word.strip()]
                if len(cls._wordlist) != 2048:
                    raise ValueError(f"Embedded word list should contain 2048 words, but got {len(cls._wordlist)}")
            except Exception as e:
                try:
                    wordlist_path = os.path.join(os.path.dirname(__file__), 'english.txt')
                    with open(wordlist_path, 'r', encoding='utf-8') as f:
                        cls._wordlist = [word.strip() for word in f.readlines() if word.strip()]
                    if len(cls._wordlist) != 2048:
                        raise ValueError(f"Word list should contain 2048 words, but got {len(cls._wordlist)}")
                except Exception as fallback_error:
                    raise RuntimeError(f"Failed to load BIP39 word list: {e}; fallback: {fallback_error}")
        return cls._wordlist
    
    @staticmethod
    def fingerprint_to_words(fingerprint_hex: str, word_count: int = 6) -> list:
        """
        Convert SHA-256 hexadecimal fingerprint to word list
        
        Args:
            fingerprint_hex: 64-character hexadecimal string (32-byte SHA-256 hash)
            word_count: number of words to generate (default 6, equals 66 bits)
        
        Returns:
            English word list
        
        Raises:
            ValueError: invalid input
        """
        if not isinstance(fingerprint_hex, str) or len(fingerprint_hex) != 64:
            raise ValueError(f"Fingerprint must be a 64-character hexadecimal string, got: {fingerprint_hex}")
        
        if word_count < 1 or word_count > 24:
            raise ValueError(f"Word count must be between 1 and 24, got: {word_count}")
        
        try:
            fingerprint_bytes = bytes.fromhex(fingerprint_hex)
        except ValueError as e:
            raise ValueError(f"Invalid hexadecimal fingerprint: {e}")
        
        wordlist = FingerprintWords._load_wordlist()
        
        # Compute required bits: word_count * 11
        total_bits = word_count * 11
        
        # Convert bytes to bit string
        bit_string = ''.join(format(byte, '08b') for byte in fingerprint_bytes)
        
        # Take first total_bits bits
        bit_string = bit_string[:total_bits]
        
        # Map each 11 bits to one word index
        words = []
        for i in range(word_count):
            start = i * 11
            end = start + 11
            index_bits = bit_string[start:end]
            index = int(index_bits, 2)
            if index >= len(wordlist):
                raise RuntimeError(f"Index out of range: {index} >= {len(wordlist)}")
            words.append(wordlist[index])
        
        return words
    
    @staticmethod
    def words_to_fingerprint(words: list) -> str:
        """
        Convert word list back to hexadecimal fingerprint (for verification)
        
        Args:
            words: English word list
        
        Returns:
            Hexadecimal fingerprint string
        
        Raises:
            ValueError: invalid words or conversion failure
        """
        if not isinstance(words, list) or len(words) == 0:
            raise ValueError("Word list cannot be empty")
        
        wordlist = FingerprintWords._load_wordlist()
        word_count = len(words)
        
        # Build word-to-index mapping
        word_to_index = {word: idx for idx, word in enumerate(wordlist)}
        
        # Convert each word to an 11-bit index
        bit_string = ''
        for word in words:
            if word not in word_to_index:
                raise ValueError(f"Invalid word: {word}")
            index = word_to_index[word]
            bit_string += format(index, '011b')
        
        # Compute required byte count (round up)
        byte_count = (len(bit_string) + 7) // 8
        
        # Pad bit string to byte boundary
        bit_string = bit_string.ljust(byte_count * 8, '0')
        
        # Convert bits back to bytes
        fingerprint_bytes = bytes(int(bit_string[i:i+8], 2) for i in range(0, len(bit_string), 8))
        
        return fingerprint_bytes.hex()

