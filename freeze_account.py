# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.

"""freeze_account.py — standalone CLI tool to permanently freeze a KaleidoTalk account.

Usage:
    python freeze_account.py --server 127.0.0.1:5555 --username alice --recovery-key recovery.priv

Requirements: recovery private key (PEM file) generated during registration.
The freeze is **irreversible** — no server or admin can undo it.
"""

import argparse
import os
import sys
import json
import time
import socket
import ssl

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from src.common.padding import PaddedSender, PaddedReceiver


def send_msg(sock, obj):
    """Send a JSON dict through the padded protocol."""
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    PaddedSender.send(sock, data)


def load_recovery_key(path):
    """Load Ed25519 recovery private key from PEM file."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Recovery key file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(
        pem_data.encode("utf-8"), password=None, backend=default_backend()
    )


def freeze_account(server_host, server_port, username, recovery_key_path):
    """Connect to server, sign and send freeze_account command."""
    # Load recovery key
    recovery_priv = load_recovery_key(recovery_key_path)

    # Connect
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(10)
    raw_sock.connect((server_host, server_port))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls_sock = ctx.wrap_socket(raw_sock, server_hostname=server_host)
    tls_sock.settimeout(10)

    receiver = PaddedReceiver()
    # Drain welcome message
    welcome_raw = receiver.recv(tls_sock)
    if welcome_raw:
        welcome = json.loads(welcome_raw.decode("utf-8"))
        if welcome.get("type") == "welcome":
            print(f"Connected: {welcome['data']['message']}")

    # Build freeze request
    freeze_ts = int(time.time())
    nonce = os.urandom(16).hex()
    data_to_sign = f"{username}{freeze_ts}{nonce}".encode("utf-8")
    signature = recovery_priv.sign(data_to_sign).hex()

    cmd = {
        "cmd": "freeze_account",
        "data": {
            "username": username,
            "timestamp": freeze_ts,
            "nonce": nonce,
            "signature": signature,
        },
    }
    send_msg(tls_sock, cmd)
    response_raw = receiver.recv(tls_sock)
    if not response_raw:
        print("ERROR: No response from server")
        sys.exit(1)

    resp = json.loads(response_raw.decode("utf-8"))
    if resp.get("status") == "ok":
        print(f"SUCCESS: {resp.get('data', {}).get('message', 'Account permanently frozen')}")
        tls_sock.close()
        sys.exit(0)
    else:
        print(f"FAILED: {resp.get('error', 'Unknown error')}")
        tls_sock.close()
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Permanently freeze a KaleidoTalk account")
    parser.add_argument("--server", default="127.0.0.1:5555", help="Server address (host:port)")
    parser.add_argument("--username", required=True, help="Username to freeze")
    parser.add_argument("--recovery-key", required=True, help="Path to recovery private key PEM file")
    args = parser.parse_args()

    parts = args.server.split(":")
    host = parts[0]
    port = int(parts[1]) if len(parts) > 1 else 5555

    print(f"WARNING: This action is IRREVERSIBLE!")
    print(f"  Account: {args.username}")
    print(f"  Server:  {host}:{port}")
    print(f"  Key:     {args.recovery_key}")
    answer = input("Type 'FREEZE' to confirm: ")
    if answer != "FREEZE":
        print("Canceled.")
        sys.exit(0)

    try:
        freeze_account(host, port, args.username, args.recovery_key)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    except ConnectionRefusedError:
        print("ERROR: Connection refused — server not running?")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
