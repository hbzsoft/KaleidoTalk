# Copyright (C) 2026 Bangze Han

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


# network.py
import json
import struct

def send_msg(sock, obj):
    """发送 JSON 消息，格式: [4字节长度][JSON字节]"""
    data = json.dumps(obj).encode('utf-8')
    length = len(data)
    sock.sendall(struct.pack('>I', length) + data)

def recv_msg(sock):
    """接收一条 JSON 消息，返回字典或 None(连接关闭)"""
    # 先读取4字节长度
    raw = b''
    while len(raw) < 4:
        chunk = sock.recv(4 - len(raw))
        if not chunk:
            return None
        raw += chunk
    length = struct.unpack('>I', raw)[0]
    if length > 10 * 1024 * 1024:  # 10 MB 限制
        raise ValueError('消息过长')
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return json.loads(data.decode('utf-8'))