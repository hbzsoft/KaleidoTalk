# KaleidoTalk

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/hbzsoft/KaleidoTalk/actions/workflows/ci.yml/badge.svg)](https://github.com/hbzsoft/KaleidoTalk/actions/workflows/ci.yml)

**Secure end-to-end encrypted chat software**

🔗 **项目官网**: [https://kaleidotalk.hanbangze.tech](https://kaleidotalk.hanbangze.tech)  
📜 **阅读宣言**: [MANIFESTO.md](MANIFESTO.md) — *Privacy is a human right.*

KaleidoTalk 是一款端到端加密聊天软件，采用 Ed25519 身份密钥和 X25519 密钥交换协议，确保通信内容仅限通信双方读取。  
**v2.3 新特性**：TLS 传输加密 + 掩护流量（Cover Traffic）进一步保护通信元数据。

## 📜 法律合规性提示

请在使用或部署本软件前，阅读完整的 **[合规声明](COMPLIANCE.md)** 和 **[免责声明](DISCLAIMER.md)**。

**简要提醒**：KaleidoTalk 是一个开源学习项目。如果您计划在公网部署，请自行确保符合当地法律。

## ✨ 功能特性

### 核心加密
- **端到端加密**：Ed25519 + X25519 + AES-256-GCM，消息仅收发双方可解密
- **前向安全**：每条消息使用临时 X25519 密钥对，长期私钥泄露不影响历史消息
- **双模式私钥存储**：可选择将私钥加密存储于服务器（跨设备登录）或仅保留在本地
- **用户信任验证**：通过指纹（SHA-256 公钥哈希）验证好友身份，支持 **BIP39 单词** 显示（6 个英文单词），便于人工核对

### 传输与元数据保护（v2.3 新增）
- **TLS 1.2+ 传输加密**：自签名证书 + TOFU 信任模型，首次连接时通过 BIP39 单词核对证书指纹
- **掩护流量（Cover Traffic）**：
  - 所有数据包固定为 **2048 字节**，真实数据填充随机字节
  - 心跳包以 **随机间隔（3.3~6.7 秒）** 持续发送，混淆通信模式
  - 有效防御基于包长度和时间间隔的流量分析

### 服务端管理
- **离线消息队列**：用户上线后自动接收离线期间的消息
- **IP/用户封禁**：管理员可封禁恶意 IP 或用户，支持临时/永久封禁
- **DoS 防护**：注册/登录频率限制，自动封禁异常 IP
- **邀请码注册**：可开启邀请码机制，限制公开注册

### 图形界面
- 基于 **CustomTkinter** 的跨平台 GUI，支持暗色主题、系统托盘、消息提醒闪烁

## 🔐 加密协议

| 组件 | 算法 | 用途 |
|------|------|------|
| 身份密钥 | Ed25519 | 数字签名，验证消息发送者身份 |
| 密钥交换 | X25519 | ECDH 协商共享密钥 |
| 对称加密 | AES-256-GCM | 消息加密，同时提供认证 |
| 密钥派生 | HKDF-SHA256 | 从 ECDH 共享密钥派生 AES key 和 nonce |
| 密码存储 | PBKDF2-SHA256 (600k 迭代) | 服务端存储密码哈希 |
| 传输加密 | TLS 1.2+ (RSA 2048) | 保护客户端‑服务器通信（证书自签名） |

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
- 依赖库：`cryptography`, `pystray`, `Pillow`, `customtkinter`

### 安装依赖
推荐使用虚拟环境：
```bash
pip install -r requirements.txt
```
或直接安装：
```bash
pip install cryptography pystray Pillow customtkinter
```

### 启动服务器
```bash
python run_server.py
```
首次启动需要设置**管理员密码**，用于保护服务器私钥。  
服务器启动后会在 `server_keys/` 目录下生成 TLS 证书和密钥（自签名）。

### 启动客户端
```bash
python run_client.py
```

## 🚀 快速开始

1. **连接服务器**：点击「连接」，输入服务器地址（默认 `127.0.0.1:5555`）
   - 首次连接时，客户端会显示服务器 TLS 证书的 **6 个 BIP39 单词**，请通过安全渠道（电话、当面）核对后「信任」。
2. **注册账号**：点击「注册」，设置用户名（3-20位字母数字）、密码（至少8位含字母数字）
   - 选择私钥存储方式：服务器托管（可跨设备）或仅本地存储。
3. **登录账号**：使用注册的用户名和密码登录。
4. **发送消息**：双击在线用户，输入消息后发送。

### 信任验证（推荐）
首次与好友聊天时，系统会要求验证对方身份指纹（同样是 6 个 BIP39 单词）。请通过安全渠道核对后「验证通过」，此后消息自动解密。

## 🛠️ 管理员命令

`admin.py` 提供服务器本地管理功能（直接编辑配置文件，无需运行服务器）：

```bash
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
```

## 📁 文件结构

```
KaleidoTalk/
├── run_client.py          # 客户端启动入口
├── run_server.py          # 服务端启动入口
├── src/
│   ├── client/            # 客户端逻辑与 GUI
│   ├── server/            # 服务端核心（命令、会话、存储）
│   ├── common/            # 共享模块（加密、网络、定长包协议）
│   └── admin.py           # 管理员脚本
├── tests/                 # 单元测试（逐步完善）
├── docs/                  # 用户/管理员文档
├── .github/workflows/     # CI 配置
├── requirements.txt       # Python 依赖
├── README.md
├── LICENSE                # GPL v3 许可证（原 COPYING）
├── COMPLIANCE.md          # 合规声明
├── DISCLAIMER.md          # 免责声明
├── MANIFESTO.md           # 项目宣言
├── CONTRIBUTING.md        # 贡献指南
└── .gitignore
```

运行时生成的数据文件（默认在服务器工作目录）：

| 文件/目录 | 说明 |
|-----------|------|
| `users.json` | 用户密码哈希（托管模式） |
| `user_keys.json` | 用户公钥及加密私钥 |
| `invite_codes.json` | 邀请码配置 |
| `bans.json` | IP/用户封禁记录 |
| `server.log` | 服务器日志 |
| `local_keys/` | 客户端本地密钥存储（信任库、私钥） |
| `server_keys/` | 服务器密钥存储（TLS 证书、Ed25519/X25519 私钥） |

## 🔧 技术架构

- **通信协议**：自定义定长包协议（2048 字节），支持分片重组、随机填充、心跳掩护
- **传输加密**：TLS 1.2+（自签名证书，TOFU 信任）
- **会话管理**：HMAC 认证 + 序号/时间戳防重放，支持单点登录
- **并发模型**：服务端多线程，每客户端独立线程
- **存储**：JSON 文件存储（可扩展为数据库）

## 🤝 贡献与反馈

欢迎提交 Issue 和 Pull Request。请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 和 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。

## ⚠️ 免责声明

本软件仅供学习交流使用。用户需遵守当地法律法规，作者不对任何违法使用行为承担责任。详细免责条款见 [DISCLAIMER.md](DISCLAIMER.md)。

## 📄 许可证

KaleidoTalk 是自由软件，采用 **GNU General Public License v3.0** 授权。  
详见 [LICENSE](LICENSE) 文件。

## 🙏 致谢

使用的第三方库：

- [cryptography](https://cryptography.io/) – 加密算法实现 (Apache 2.0)
- [pystray](https://github.com/moses-palmer/pystray) – 系统托盘 (LGPLv3)
- [Pillow](https://python-pillow.org/) – 图像处理 (MIT 衍生)
- [CustomTkinter](https://customtkinter.tomschimansky.com/) – GUI 页面 (MIT)

## 📧 联系方式

- 提交 [Issue](https://github.com/hbzsoft/KaleidoTalk/issues)
- 官网：[https://kaleidotalk.hanbangze.tech](https://kaleidotalk.hanbangze.tech)

---

**Built with ❤️ by [Bangze Han](https://github.com/hbzsoft)**