# KaleidoTalk

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/hbzsoft/KaleidoTalk/actions/workflows/ci.yml/badge.svg)](https://github.com/hbzsoft/KaleidoTalk/actions/workflows/ci.yml)

**Secure end-to-end encrypted chat software**

🔗 **Project Website**: [https://kaleidotalk.hanbangze.tech](https://kaleidotalk.hanbangze.tech)  
📜 **Read the Manifesto**: [MANIFESTO.md](MANIFESTO.md) — *Privacy is a human right.*

KaleidoTalk is an end-to-end encrypted chat application that uses Ed25519 identity keys and X25519 key exchange to ensure that only message participants can read message content.

**New in v3.0**: X25519 key rotation, irreversible account freeze, modern bubble UI, server configuration file, and client config persistence.

## 📜 Legal Compliance Notice

Before using or deploying this software, please read the full **[Compliance Statement](COMPLIANCE.md)** and **[Disclaimer](DISCLAIMER.md)**.

**Quick reminder**: KaleidoTalk is an open-source learning project. If you deploy it on the public internet, you are responsible for complying with local law.

## ✨ Features

### Core Cryptography
- **End-to-end encryption**: Ed25519 + X25519 + AES-256-GCM, only sender and receiver can decrypt
- **Forward secrecy**: each message uses an ephemeral X25519 key pair, so long-term key compromise does not expose historical messages
- **Key rotation (v3.0)**: X25519 keys are automatically rotated every 24 hours, limiting the impact of private key leakage to a narrow time window
- **Irreversible account freeze (v3.0)**: generate a recovery certificate during registration; if your account is compromised, you can permanently freeze it — no one, not even the server admin, can unfreeze it
- **Dual private-key storage modes**: encrypted server-side key storage (multi-device login) or local-only key storage
- **User trust verification**: identity fingerprint validation via SHA-256 public key hash, with **BIP39 word display** (6 English words) for human verification

### Transport and Metadata Protection
- **TLS 1.2+ transport encryption**: self-signed certificates + TOFU trust model, first-connection certificate fingerprint verification via BIP39 words
- **Cover traffic**:
  - All packets are fixed to **2048 bytes**, with random padding
  - Heartbeat packets are sent at **random intervals (3.3–6.7 seconds)**
  - Helps resist traffic analysis based on packet length and timing

### Server Management
- **Offline message queue**: users receive offline messages automatically after login
- **IP/User bans**: admins can ban malicious IPs or users, with temporary/permanent options
- **DoS protection**: registration/login rate limiting with automatic IP banning
- **Invite-code registration**: optional invite mechanism to restrict open registration
- **Server configuration file**: `config.json` for easy setup of host, port, security parameters, and more

### Graphical Interface (v3.0)
- **Modern bubble chat UI**: left contact list with avatars, unread badges, trust indicators; right chat area with message bubbles (own messages in blue, others with avatars)
- **Responsive design**: adapts to screen resolution
- **System tray & message flashing**: stays unobtrusive while keeping you notified
- **Dark theme** by default

## 🔐 Cryptography Stack

| Component | Algorithm | Purpose |
|------|------|------|
| Identity key | Ed25519 | Digital signatures and sender authenticity |
| Key exchange | X25519 | ECDH shared-secret negotiation |
| Symmetric encryption | AES-256-GCM | Message encryption with authentication |
| Key derivation | HKDF-SHA256 | Derive AES key and nonce from ECDH secret |
| Password storage | PBKDF2-SHA256 (600k iterations) | Server-side password hash storage |
| Transport encryption | TLS 1.2+ (RSA 2048) | Protect client-server communication (self-signed cert) |

**Message encryption flow**:
1. Sender generates an ephemeral X25519 key pair
2. ECDH with recipient's public key (using the latest X25519 key from the recipient's key list) to derive a shared secret
3. HKDF derives AES key and nonce
4. Encrypt message with AES-256-GCM, including the `key_id` of the sender's key used (for rotation compatibility)
5. Sender signs (ephemeral public key + ciphertext + tag) with Ed25519
6. Recipient verifies signature, extracts `key_id`, finds the corresponding private key, and decrypts

## 📦 Installation and Run

### Requirements
- Python 3.8+
- Dependencies: `cryptography`, `pystray`, `Pillow`, `customtkinter`

### Install dependencies
Using a virtual environment is recommended:
```bash
pip install -r requirements.txt
```
Or install directly:
```bash
pip install cryptography pystray Pillow customtkinter
```

### Start the server
```bash
python run_server.py
```
On first start, you must set an **admin password** to protect server private keys.
After startup, TLS certificate and key files are generated under `server_keys/`.
You can customize server behavior by editing `config.json` (created automatically).

### Start the client
```bash
python run_client.py
```
Client configuration (server address, window size, theme, auto-connect) is persisted in `local_keys/client_config.json`.

## 🚀 Quick Start

1. **Connect to server**: Click "Connect" and enter server address (default `127.0.0.1:5555`)
   - On first connection, the client shows **6 BIP39 words** for the server TLS certificate fingerprint. Verify through a secure channel (phone/in person), then trust.
2. **Register account**: Click "Register" and set username (3-20 alphanumeric) and password (at least 8 chars including letters and digits)
   - Choose private-key storage mode: server-hosted (cross-device) or local-only.
   - **Important**: A recovery key is generated and saved locally (`local_keys/<username>_recovery.priv`). Keep it safe — it allows you to permanently freeze your account if compromised.
3. **Login**: Sign in with the registered username and password.
4. **Send messages**: Double-click an online user, type a message, and send.

### Trust verification (recommended)
When chatting with a new contact for the first time, verify the peer fingerprint (also shown as 6 BIP39 words) through a secure channel. After successful verification, decryption is automatic in future chats.

## 🛠️ Admin Commands

`admin.py` provides local server administration (direct file edits; server runtime not required):

```bash
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
```

### Emergency Account Freeze (standalone tool)

If you lose access to your account (e.g., forgotten password or stolen credentials), you can permanently freeze it using the recovery key:

```bash
python freeze_account.py --server 127.0.0.1:5555 --username alice --recovery-key local_keys/alice_recovery.priv
```

This action is **irreversible**. The account will be permanently locked and cannot be logged in again.

## 📁 File Structure

```
KaleidoTalk/
├── run_client.py              # Client entrypoint
├── run_server.py              # Server entrypoint
├── admin.py                   # Admin CLI script (root)
├── freeze_account.py          # Standalone account freeze tool
├── reset.bat                  # Windows reset script (wipes runtime data)
├── src/
│   ├── client/                # Client logic and GUI
│   │   ├── chat_client.py
│   │   └── chat_gui.py
│   ├── server/                # Server core
│   │   ├── config.py          # Server configuration loader
│   │   ├── server.py
│   │   ├── server_commands.py
│   │   ├── server_session.py
│   │   └── server_storage.py
│   └── common/                # Shared modules
│       ├── crypto_utils.py
│       ├── network.py
│       └── padding.py
├── test/                      # Smoke and integration tests
│   ├── test_key_rotation_smoke.py
│   ├── test_e2e_rotation.py
│   ├── test_freeze_smoke.py
│   └── test_freeze_e2e.py
├── docs/                      # Website HTML
├── licenses/                  # Third-party license texts
├── .github/workflows/         # CI configuration
├── requirements.txt
├── README.md
├── LICENSE
├── COMPLIANCE.md
├── DISCLAIMER.md
├── MANIFESTO.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
└── .gitignore
```

Runtime-generated data files (default server working directory):

| File/Directory | Description |
|-----------|------|
| `users.json` | User password hashes (hosted-key mode) |
| `user_keys.json` | User public keys, encrypted private keys, and rotation data |
| `invite_codes.json` | Invite-code configuration |
| `bans.json` | IP/User ban records |
| `server.log` | Server logs |
| `config.json` | Server configuration (host, port, security params, etc.) |
| `local_keys/` | Client local key storage (trust store, private keys, recovery keys, config) |
| `server_keys/` | Server key storage (TLS cert, Ed25519/X25519 private keys) |

## 🔧 Technical Architecture

- **Protocol**: custom fixed-size packet protocol (2048 bytes), supports fragmentation reassembly, random padding, and heartbeat cover traffic
- **Transport encryption**: TLS 1.2+ (self-signed certificates, TOFU trust)
- **Session management**: HMAC auth + sequence/timestamp anti-replay, supports single-session login
- **Concurrency model**: multi-threaded server, one thread per client
- **Storage**: JSON-based storage (extendable to database)
- **Key rotation**: automatic 24‑hour cycle; server stores multiple key versions for smooth transitions

## 🤝 Contributing and Feedback

Issues and Pull Requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) first.

## ⚠️ Disclaimer

This software is for educational and lawful use only. Users must comply with local law. The author is not responsible for unlawful use. See [DISCLAIMER.md](DISCLAIMER.md) for full terms.

## 📄 License

KaleidoTalk is free software licensed under the **GNU General Public License v3.0**.
See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgements

Third-party libraries used:

- [cryptography](https://cryptography.io/) – Cryptographic primitives (Apache 2.0)
- [pystray](https://github.com/moses-palmer/pystray) – System tray support (LGPLv3)
- [Pillow](https://python-pillow.org/) – Image processing (MIT derivative)
- [CustomTkinter](https://customtkinter.tomschimansky.com/) – GUI framework (MIT)

## 📧 Contact

- Submit an [Issue](https://github.com/hbzsoft/KaleidoTalk/issues)
- Website: [https://kaleidotalk.hanbangze.tech](https://kaleidotalk.hanbangze.tech)

---

**Built with love by [Bangze Han](https://github.com/hbzsoft)**