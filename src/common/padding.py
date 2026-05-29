# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


# padding.py
"""掩护流量（Cover Traffic）模块

提供定长数据包封装/拆封、随机抖动间隔、分片/重组功能，
用于混淆通信元数据（包大小、发送频率），对抗流量分析。

协议格式（定长 PACKET_SIZE 字节）:
  [0:1]   type     - 1 字节: 0x01=真实数据, 0x02=分片首片, 0x03=分片续片, 0x04=分片末片, 0x00=填充
  [1:3]   length   - 2 字节大端: 真实数据长度（不含填充）
  [3:5]   seq      - 2 字节大端: 分片序号（仅分片类型有效）
  [5:7]   total    - 2 字节大端: 总分片数（仅分片类型有效）
  [7:N]   payload  - 真实数据
  [N:END] padding  - 随机填充字节（使总长度 = PACKET_SIZE）
"""

import os
import struct
import time
import random
import threading

# ----------------------------------------------------------------------
# 协议常量
PACKET_SIZE = 2048          # 定长包字节数
HEADER_SIZE = 7             # 头部字节数 (type + length + seq + total)
MAX_PAYLOAD = PACKET_SIZE - HEADER_SIZE  # 单包最大有效载荷

# 包类型
TYPE_PADDING = 0x00         # 纯填充包
TYPE_DATA = 0x01            # 完整数据包（不分片）
TYPE_FRAGMENT_FIRST = 0x02   # 分片：首片
TYPE_FRAGMENT_MID = 0x03    # 分片：中间片
TYPE_FRAGMENT_LAST = 0x04   # 分片：末片

# 心跳参数
BASE_INTERVAL = 5.0         # 基础心跳间隔（秒）
JITTER_RATIO = 1.0 / 3.0   # 抖动范围 = ±BASE_INTERVAL * JITTER_RATIO


def next_interval():
    """计算下一次心跳间隔（含随机抖动）

    Returns:
        float: 等待秒数
    """
    jitter = BASE_INTERVAL * JITTER_RATIO
    return BASE_INTERVAL + random.uniform(-jitter, jitter)


def build_packet(data: bytes, packet_type: int = TYPE_DATA,
                 frag_seq: int = 0, frag_total: int = 0) -> bytes:
    """构造一个定长数据包

    Args:
        data: 真实载荷（不超过 MAX_PAYLOAD 字节）
        packet_type: 包类型
        frag_seq: 分片序号（仅分片时有效）
        frag_total: 总分片数（仅分片时有效）

    Returns:
        bytes: 长度恰好为 PACKET_SIZE 的数据包

    Raises:
        ValueError: 数据超过 MAX_PAYLOAD
    """
    if len(data) > MAX_PAYLOAD:
        raise ValueError(f"数据 {len(data)} 字节超过单包上限 {MAX_PAYLOAD}")

    header = struct.pack('>BHHH', packet_type, len(data), frag_seq, frag_total)
    payload = header + data

    # 用随机字节填充到定长
    padding_len = PACKET_SIZE - len(payload)
    padding = os.urandom(padding_len) if padding_len > 0 else b''

    return payload + padding


def parse_packet(raw: bytes):
    """解析一个定长数据包

    Args:
        raw: 原始数据包（长度应为 PACKET_SIZE）

    Returns:
        tuple: (packet_type, data, frag_seq, frag_total)
            - packet_type: 包类型（int）
            - data: 真实载荷（bytes）
            - frag_seq: 分片序号（int）
            - frag_total: 总分片数（int）

    Raises:
        ValueError: 包长度无效或头部解析失败
    """
    if len(raw) != PACKET_SIZE:
        raise ValueError(f"包长度 {len(raw)} 不等于期望的 {PACKET_SIZE}")

    packet_type, length, frag_seq, frag_total = struct.unpack('>BHHH', raw[:HEADER_SIZE])

    if packet_type == TYPE_PADDING:
        return packet_type, b'', frag_seq, frag_total

    if length > MAX_PAYLOAD or length + HEADER_SIZE > PACKET_SIZE:
        raise ValueError(f"载荷长度 {length} 无效")

    data = raw[HEADER_SIZE:HEADER_SIZE + length]
    return packet_type, data, frag_seq, frag_total


def fragment_data(data: bytes) -> list:
    """将大数据分片为多个定长包

    Args:
        data: 待分片的原始数据

    Returns:
        list[bytes]: 定长包列表
    """
    if len(data) <= MAX_PAYLOAD:
        return [build_packet(data, TYPE_DATA)]

    total = (len(data) + MAX_PAYLOAD - 1) // MAX_PAYLOAD
    fragments = []

    for i in range(total):
        start = i * MAX_PAYLOAD
        end = min(start + MAX_PAYLOAD, len(data))
        chunk = data[start:end]

        if i == 0:
            ptype = TYPE_FRAGMENT_FIRST
        elif i == total - 1:
            ptype = TYPE_FRAGMENT_LAST
        else:
            ptype = TYPE_FRAGMENT_MID

        fragments.append(build_packet(chunk, ptype, frag_seq=i, frag_total=total))

    return fragments


class FragmentReassembler:
    """分片重组器

    用于在接收端将多个分片重组为完整数据。
    线程安全。
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._buffers = {}  # key -> {'total': int, 'chunks': dict, 'timer': float}

    def feed(self, packet_type: int, data: bytes, frag_seq: int, frag_total: int):
        """喂入一个包，尝试重组

        Args:
            packet_type: 包类型
            data: 载荷
            frag_seq: 分片序号
            frag_total: 总分片数

        Returns:
            bytes or None: 重组完成的完整数据，或 None（尚未完成）
        """
        # 非分片包直接返回
        if packet_type == TYPE_DATA:
            return data
        if packet_type == TYPE_PADDING:
            return None

        if frag_total <= 0 or frag_total > 1000:
            return None  # 防御异常值

        with self._lock:
            # 使用 (frag_total, frag_seq 范围) 作为 key
            # 简化：用第一个包的 frag_total 作为标识
            # 更精确的做法需要流 ID，但当前协议每个连接同时只有一个重组操作
            key = frag_total  # 简化 key

            if key not in self._buffers:
                self._buffers[key] = {
                    'total': frag_total,
                    'chunks': {},
                    'timer': time.time(),
                }

            buf = self._buffers[key]
            buf['chunks'][frag_seq] = data

            # 超时清理（30秒）
            if time.time() - buf['timer'] > 30:
                del self._buffers[key]
                return None

            # 检查是否所有分片已到齐
            if len(buf['chunks']) == buf['total']:
                result = b''
                for i in range(buf['total']):
                    result += buf['chunks'][i]
                del self._buffers[key]
                return result

            return None

    def reset(self):
        """清空所有缓冲区"""
        with self._lock:
            self._buffers.clear()


def build_padding_packet() -> bytes:
    """构造一个纯填充包（掩护流量）"""
    return build_packet(b'', TYPE_PADDING)


class PaddedSender:
    """定长包发送器

    在底层 socket 上发送定长数据包。
    """

    @staticmethod
    def send(sock, data: bytes):
        """发送一个定长包

        Args:
            sock: 已连接的 socket
            data: 要发送的原始数据（会自动分片）
        """
        packets = fragment_data(data)
        for pkt in packets:
            sock.sendall(pkt)

    @staticmethod
    def send_padding(sock):
        """发送一个纯填充包"""
        sock.sendall(build_padding_packet())


class PaddedReceiver:
    """定长包接收器

    从底层 socket 上接收定长数据包并重组。
    """

    def __init__(self):
        self._reassembler = FragmentReassembler()
        self._recv_buf = b''

    def recv(self, sock) -> bytes:
        """接收一个完整的逻辑消息（可能跨多个定长包）

        Args:
            sock: 已连接的 socket

        Returns:
            bytes: 完整的消息数据

        Raises:
            ValueError: 数据格式错误
            ConnectionError: 连接关闭
        """
        while True:
            # 尝试从缓冲区中取出一个完整包
            while len(self._recv_buf) >= PACKET_SIZE:
                raw = self._recv_buf[:PACKET_SIZE]
                self._recv_buf = self._recv_buf[PACKET_SIZE:]

                ptype, data, frag_seq, frag_total = parse_packet(raw)

                if ptype == TYPE_PADDING:
                    continue  # 填充包，跳过

                result = self._reassembler.feed(ptype, data, frag_seq, frag_total)
                if result is not None:
                    return result

            # 需要更多数据
            try:
                chunk = sock.recv(PACKET_SIZE * 4)  # 一次读取多个包
                if not chunk:
                    raise ConnectionError("连接已关闭")
                self._recv_buf += chunk
            except (ConnectionError, OSError):
                raise

    def reset(self):
        """重置接收状态"""
        self._reassembler.reset()
        self._recv_buf = b''
