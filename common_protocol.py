import os
import socket
import struct

# 极简协议：
# Header = MAGIC(4) + MSG_TYPE(1) + NAME_LEN(2) + DATA_LEN(8)
# 然后是 name(可选) + data
# - MSG_TYPE: 1=text, 2=file, 3=ack
# - NAME: 文件名(utf-8)，text/ack 可以为空

MAGIC = b"INW1"

MSG_TEXT = 1
MSG_FILE = 2
MSG_ACK = 3

HEADER_FMT = "!4sBHQ"  # 4s + uint8 + uint16 + uint64
HEADER_SIZE = struct.calcsize(HEADER_FMT)


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def send_message(sock, msg_type, name_bytes, data_bytes):
    if name_bytes is None:
        name_bytes = b""
    if data_bytes is None:
        data_bytes = b""

    header = struct.pack(HEADER_FMT, MAGIC, msg_type, len(name_bytes), len(data_bytes))
    sock.sendall(header)
    if name_bytes:
        sock.sendall(name_bytes)
    if data_bytes:
        sock.sendall(data_bytes)


def recv_message(sock):
    header = recv_exact(sock, HEADER_SIZE)
    if header is None:
        return None

    magic, msg_type, name_len, data_len = struct.unpack(HEADER_FMT, header)
    if magic != MAGIC:
        raise ValueError("协议错误：MAGIC不匹配")

    name_bytes = b""
    if name_len > 0:
        name_bytes = recv_exact(sock, name_len)
        if name_bytes is None:
            return None

    data_bytes = b""
    if data_len > 0:
        data_bytes = recv_exact(sock, data_len)
        if data_bytes is None:
            return None

    return msg_type, name_bytes, data_bytes


def safe_filename(name):
    # 防止客户端传入路径穿越，只取 basename
    name = os.path.basename(name)
    if not name:
        name = "noname.bin"
    return name


def set_tcp_keepalive(sock):
    # 工业场景常见：连接保持/检测
    # Windows 上部分参数不一定可用，这里尽量不报错。
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        pass
