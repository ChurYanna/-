import os
import socket

from common_protocol import (
    MSG_FILE,
    MSG_TEXT,
    recv_message,
    send_message,
    set_tcp_keepalive,
)


def send_text(sock):
    text = input("请输入要发送的文本: ")
    data = text.encode("utf-8")
    send_message(sock, MSG_TEXT, b"", data)

    resp = recv_message(sock)
    if resp:
        _t, _n, d = resp
        print("[服务端响应]", d.decode("utf-8", errors="ignore"))


def send_file(sock):
    path = input("请输入文件路径(图片/音频/任意文件): ").strip('"')
    if not os.path.exists(path):
        print("文件不存在:", path)
        return

    name = os.path.basename(path)
    with open(path, "rb") as f:
        data = f.read()

    send_message(sock, MSG_FILE, name.encode("utf-8"), data)
    print("已发送文件:", name, "大小:", len(data), "字节")

    resp = recv_message(sock)
    if resp:
        _t, _n, d = resp
        print("[服务端响应]", d.decode("utf-8", errors="ignore"))


def main():
    host = input("服务端IP(回车默认127.0.0.1): ").strip()
    if host == "":
        host = "127.0.0.1"

    port_str = input("端口(回车默认9000): ").strip()
    if port_str == "":
        port = 9000
    else:
        port = int(port_str)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    set_tcp_keepalive(sock)
    sock.connect((host, port))

    print("=== 工业网络 Socket 客户端 ===")

    try:
        while True:
            print("\n请选择操作:")
            print("1) 发送文本")
            print("2) 发送文件(图片/音频/任意)")
            print("0) 退出")
            choice = input("> ").strip()

            if choice == "1":
                send_text(sock)
            elif choice == "2":
                send_file(sock)
            elif choice == "0":
                break
            else:
                print("无效选择")

    finally:
        try:
            sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
