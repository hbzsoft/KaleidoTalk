
# KaleidoTalk

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

**Secure end-to-end encrypted chat software**

KaleidoTalk 是一款端到端加密聊天软件，采用 Ed25519 身份密钥和 X25519 密钥交换协议，确保通信内容仅限通信双方读取。

## ✨ 功能特性

- **端到端加密**：基于 Ed25519 + X25519 + AES-256-GCM，消息仅收发双方可解密
- **双模式私钥存储**：可选择将私钥加密存储于服务器（跨设备登录）或仅保留在本地
- **用户信任验证**：通过指纹（公钥哈希）验证好友身份，防止中间人攻击
- **离线消息队列**：用户上线后自动接收离线期间的消息
- **IP/用户封禁**：管理员可封禁恶意 IP 或用户，支持临时/永久封禁
- **DoS 防护**：注册/登录频率限制，自动封禁异常 IP
- **图形界面**：基于 tkinter 的跨平台 GUI，支持系统托盘

## 🔐 加密协议

| 组件 | 算法 | 用途 |
|------|------|------|
| 身份密钥 | Ed25519 | 数字签名，验证消息发送者身份 |
| 密钥交换 | X25519 | ECDH 协商共享密钥 |
| 对称加密 | AES-256-GCM | 消息加密，同时提供认证 |
| 密钥派生 | HKDF-SHA256 | 从 ECDH 共享密钥派生 AES key 和 nonce |
| 密码存储 | PBKDF2-SHA256 (600k 迭代) | 服务端存储密码哈希 |

**消息加密流程**：
1. 发送方生成临时 X25519 密钥对
2. ECDH 与接收方公钥协商共享密钥
3. HKDF 派生 AES key 和 nonce
4. AES-256-GCM 加密消息
5. 发送方 Ed25519 签名 (临时公钥 + 密文 + tag)
6. 接收方验证签名后解密

## 📦 安装与运行

### 环境要求

- Python 3.8+
- 依赖库：`cryptography`, `pystray`, `Pillow`

### 安装依赖

```bash
pip install cryptography pystray Pillow
```

### 启动服务器

```bash
python server.py
```

首次启动需要设置管理员密码，用于保护服务器密钥。

### 启动客户端

```bash
python client.py
```

## 🚀 快速开始

1. **连接服务器**：点击「连接」，输入服务器地址（默认 `127.0.0.1:5555`）
2. **注册账号**：点击「注册」，设置用户名（3-20位字母数字）、密码（至少8位含字母数字）
3. **登录账号**：使用注册的用户名和密码登录
4. **发送消息**：双击在线用户，输入消息后发送

### 信任验证（可选但推荐）

首次与好友聊天时，系统会要求验证对方指纹。请通过安全渠道（如当面、电话）核对指纹，确认一致后「通过验证」。

## 🛠️ 管理员命令

`admin.py` 提供服务器管理功能（仅在服务器本机运行）：

```bash
# 邀请码管理
python admin.py invites add --count 5 --uses 1 --length 8
python admin.py invites delete CODE123
python admin.py invites set-require true

# 封禁管理
python admin.py ban ip 1.2.3.4 --duration 3600
python admin.py unban ip 1.2.3.4
python admin.py ban user alice
python admin.py list-bans
```

## 📁 文件结构

```
KaleidoTalk/
├── client.py          # 客户端 GUI
├── server.py          # 服务端
├── crypto_utils.py    # 加密模块
├── network.py         # 网络通信协议
├── admin.py           # 管理员脚本
├── COPYING            # GPL v3 许可证
└── README.md          # 本文件
```

运行时生成的数据文件：

| 文件 | 说明 |
|------|------|
| `users.json` | 用户密码哈希 |
| `user_keys.json` | 用户公钥及加密私钥 |
| `invite_codes.json` | 邀请码配置 |
| `bans.json` | IP/用户封禁记录 |
| `server.log` | 服务器日志 |
| `local_keys/` | 客户端本地密钥存储 |
| `server_keys/` | 服务器密钥存储 |

## 🔧 技术架构

- **通信协议**：自定义 JSON 格式，4 字节长度头 + JSON 消息体
- **会话管理**：Token 认证，支持单点登录（新登录踢旧连接）
- **并发模型**：服务端多线程，每客户端独立线程
- **存储**：JSON 文件存储（可扩展为数据库）

## ⚠️ 免责声明

本软件仅供学习交流使用。用户需遵守当地法律法规，作者不对任何违法使用行为承担责任。

## 📄 许可证

KaleidoTalk 是自由软件，采用 **GNU General Public License v3.0** 授权。

```
KaleidoTalk Copyright (C) 2026 Bangze Han

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

## 🙏 致谢

使用的第三方库：

- [cryptography](https://cryptography.io/) - 加密算法实现 (Apache 2.0)
- [pystray](https://github.com/moses-palmer/pystray) - 系统托盘 (LGPLv3)
- [Pillow](https://python-pillow.org/) - 图像处理 (MIT 衍生)
- [CustomTkinter](https://customtkinter.tomschimansky.com/) - GUI 页面 (MIT)

## 📧 联系方式

如有问题或建议，欢迎提交 [Issue](https://github.com/hbzsoft/KaleidoTalk/issues)。

---

**Built with ❤️ by [Bangze Han](https://github.com/hbzsoft)**

