# Copyright (C) 2026 Bangze Han

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


# network.py
import json
import threading
import struct
import time
import weakref

_STATE_LOCK = threading.Lock()
_SOCKET_STATE = weakref.WeakKeyDictionary()
_MAX_CLOCK_SKEW_MS = 5 * 60 * 1000


def _get_socket_state(sock):
    with _STATE_LOCK:
        state = _SOCKET_STATE.get(sock)
        if state is None:
            state = {'send_seq': 0, 'recv_seq': 0, 'time_offset_ms': 0}
            _SOCKET_STATE[sock] = state
        return state


def set_socket_time_offset(sock, offset_ms):
    state = _get_socket_state(sock)
    with _STATE_LOCK:
        state['time_offset_ms'] = int(offset_ms)


def get_socket_time_offset(sock):
    state = _get_socket_state(sock)
    with _STATE_LOCK:
        return int(state.get('time_offset_ms', 0))

def send_msg(sock, obj):
    """发送 JSON 消息，格式: [4字节长度][JSON字节]"""
    state = _get_socket_state(sock)
    with _STATE_LOCK:
        state['send_seq'] += 1
        seq = state['send_seq']
        offset_ms = state.get('time_offset_ms', 0)
    packet = {
        'seq': seq,
        'timestamp': int(time.time() * 1000) + offset_ms,
        'data': obj,
    }
    data = json.dumps(packet, ensure_ascii=False).encode('utf-8')
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
    packet = json.loads(data.decode('utf-8'))
    if not isinstance(packet, dict):
        raise ValueError('消息格式无效')
    try:
        seq = int(packet['seq'])
        timestamp = int(packet['timestamp'])
    except Exception as e:
        raise ValueError('消息序号或时间戳无效') from e
    payload = packet.get('data')
    state = _get_socket_state(sock)
    with _STATE_LOCK:
        if state['recv_seq'] == 0:
            state['recv_seq'] = seq
            return payload
        now_ms = int(time.time() * 1000) + int(state.get('time_offset_ms', 0))
        if abs(now_ms - timestamp) > _MAX_CLOCK_SKEW_MS:
            raise ValueError('消息时间戳超出允许范围')
        if seq <= state['recv_seq']:
            raise ValueError('检测到重放消息')
        state['recv_seq'] = seq
    return payload