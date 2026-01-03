import os
import socket
import threading
import time

from common_protocol import (
    MSG_ACK,
    MSG_FILE,
    MSG_TEXT,
    recv_message,
    safe_filename,
    send_message,
    set_tcp_keepalive,
)


def handle_client(conn, addr, save_dir):
    set_tcp_keepalive(conn)
    print("[+] 客户端已连接:", addr)

    try:
        while True:
            msg = recv_message(conn)
            if msg is None:
                print("[-] 客户端断开:", addr)
                break

            msg_type, name_bytes, data_bytes = msg

            if msg_type == MSG_TEXT:
                text = data_bytes.decode("utf-8", errors="ignore")
                print("[TEXT] 来自", addr, ":", text)
                # 回一个 ACK
                send_message(conn, MSG_ACK, b"", ("已收到TEXT: " + str(len(data_bytes)) + "字节").encode("utf-8"))

            elif msg_type == MSG_FILE:
                filename = "file.bin"
                try:
                    filename = name_bytes.decode("utf-8", errors="ignore")
                except Exception:
                    filename = "file.bin"

                filename = safe_filename(filename)

                # 给文件名加时间戳，避免覆盖
                ts = time.strftime("%Y%m%d_%H%M%S")
                out_name = ts + "_" + filename
                out_path = os.path.join(save_dir, out_name)

                with open(out_path, "wb") as f:
                    f.write(data_bytes)

                print("[FILE] 保存:", out_path, "大小:", len(data_bytes), "字节")
                send_message(conn, MSG_ACK, b"", ("已收到FILE: " + out_name).encode("utf-8"))

            else:
                print("[?] 未知消息类型:", msg_type, "来自", addr)
                send_message(conn, MSG_ACK, b"", "已收到未知类型".encode("utf-8"))

    except Exception as e:
        print("[!] 连接异常:", addr, "错误:", e)

    try:
        conn.close()
    except Exception:
        pass


def main():
    host = "0.0.0.0"
    port = 9000

    save_dir = os.path.join(os.path.dirname(__file__), "recv_files")
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(5)

    print("=== 工业网络 Socket 服务端 ===")
    print("监听:", host, port)
    print("文件保存目录:", save_dir)

    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr, save_dir))
        t.daemon = True
        t.start()


if __name__ == "__main__":
    main()
